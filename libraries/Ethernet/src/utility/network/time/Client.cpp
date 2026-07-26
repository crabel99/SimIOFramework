#include "Client.h"

#include <string.h>
#include <utility/network/TimeService.h>

namespace {
constexpr uint64_t NtpUnixEpochOffset = 2208988800ULL;
constexpr uint8_t NtpClientRequest = 0x23; // LI=0, version=4, mode=3.
constexpr uint8_t NtpLeapIndicatorMask = 0xC0;
constexpr uint8_t NtpLeapIndicatorAlarm = 0xC0;
constexpr uint8_t NtpVersionMask = 0x38;
constexpr uint8_t NtpVersion4 = 0x20;
constexpr uint8_t NtpModeMask = 0x07;
constexpr uint8_t NtpModeServer = 4;
constexpr uint8_t NtpModeBroadcast = 5;
constexpr uint8_t NtpOriginateTimestampOffset = 24;
constexpr uint8_t NtpTransmitTimestampOffset = 40;
uint32_t requestSequence = 0;

uint32_t readBigEndian32(const uint8_t *buffer) {
  return (static_cast<uint32_t>(buffer[0]) << 24) |
         (static_cast<uint32_t>(buffer[1]) << 16) |
         (static_cast<uint32_t>(buffer[2]) << 8) |
         static_cast<uint32_t>(buffer[3]);
}

void writeBigEndian32(uint8_t *buffer, uint32_t value) {
  buffer[0] = static_cast<uint8_t>(value >> 24);
  buffer[1] = static_cast<uint8_t>(value >> 16);
  buffer[2] = static_cast<uint8_t>(value >> 8);
  buffer[3] = static_cast<uint8_t>(value);
}
} // namespace

NetworkTimeClient::NetworkTimeClient(TransportProvider &provider,
                                     NetworkTimeService &timeService)
    : _udp(provider) {
  attach(provider, timeService);
}

void NetworkTimeClient::attach(TransportProvider &provider,
                               NetworkTimeService &timeService) {
  _udp.setProvider(provider);
  _timeService = &timeService;
}

bool NetworkTimeClient::beginRequest(IPAddress server, uint16_t serverPort,
                                     uint16_t localPort) {
  return startRequest(server, serverPort, NetworkTimeLevel::Provisional,
                      localPort, {});
}

bool NetworkTimeClient::beginAuthenticatedRequest(
    IPAddress server, const NetworkTimeAuthenticationPolicy &policy,
    uint16_t serverPort, uint16_t localPort) {
  if (!policy.valid()) {
    _lastError = NetworkTimeClientError::InvalidArgument;
    return false;
  }

  return startRequest(server, serverPort, NetworkTimeLevel::Trusted, localPort,
                      policy);
}

bool NetworkTimeClient::startRequest(
    IPAddress server, uint16_t serverPort, NetworkTimeLevel level,
    uint16_t localPort, const NetworkTimeAuthenticationPolicy &policy) {
  if (_timeService == nullptr) {
    _lastError = NetworkTimeClientError::InvalidArgument;
    return false;
  }
  if (active()) {
    _lastError = NetworkTimeClientError::Busy;
    return false;
  }
  if (server == IPAddress() || serverPort == 0 ||
      level == NetworkTimeLevel::Unset) {
    _lastError = NetworkTimeClientError::InvalidArgument;
    return false;
  }

  uint8_t request[PacketSize] = {};
  request[0] = NtpClientRequest;
  const uint32_t sequence = ++requestSequence;
  writeBigEndian32(request + NtpTransmitTimestampOffset,
                   static_cast<uint32_t>(NtpUnixEpochOffset + sequence));
  writeBigEndian32(request + NtpTransmitTimestampOffset + 4, ~sequence);

  if (_udp.begin(localPort) == 0) {
    _lastError = NetworkTimeClientError::BindFailed;
    return false;
  }
  if (_udp.beginPacket(server, serverPort) != 1) {
    _udp.stop();
    _lastError = NetworkTimeClientError::BeginPacketFailed;
    return false;
  }
  if (_udp.write(request, sizeof(request)) != sizeof(request)) {
    _udp.stop();
    _lastError = NetworkTimeClientError::WriteFailed;
    return false;
  }
  if (_udp.endPacket() != 1) {
    _udp.stop();
    _lastError = NetworkTimeClientError::EndPacketFailed;
    return false;
  }

  _server = server;
  _serverPort = serverPort;
  _level = level;
  _authenticationPolicy = policy;
  _status = NetworkTimeClientStatus::Pending;
  _lastError = NetworkTimeClientError::None;
  _receivedUnixTime = 0;
  _pollCount = 0;
  memcpy(_requestTransmitTimestamp, request + NtpTransmitTimestampOffset,
         sizeof(_requestTransmitTimestamp));
  return true;
}

bool NetworkTimeClient::setPollLimit(uint16_t pollLimit) {
  if (active() || pollLimit == 0)
    return false;

  _pollLimit = pollLimit;
  return true;
}

NetworkTimeClientStatus NetworkTimeClient::poll() {
  if (!active())
    return _status;
  if (!consumePollBudget())
    return fail(NetworkTimeClientError::OperationDeadlineExceeded);

  const int packetLength = _udp.parsePacket();
  if (packetLength == 0)
    return NetworkTimeClientStatus::Pending;
  if (packetLength < PacketSize)
    return fail(NetworkTimeClientError::ShortPacket);
  if (!(_udp.remoteIP() == _server) || _udp.remotePort() != _serverPort)
    return fail(NetworkTimeClientError::UnexpectedRemote);

  uint8_t response[PacketSize] = {};
  if (_udp.read(response, sizeof(response)) != sizeof(response))
    return fail(NetworkTimeClientError::ReadFailed);

  uint64_t unixTime = 0;
  if (!parseResponse(response, _requestTransmitTimestamp, unixTime))
    return fail(NetworkTimeClientError::InvalidResponse);
  if (_level == NetworkTimeLevel::Trusted &&
      (!_authenticationPolicy.valid() ||
       !_authenticationPolicy.authenticate(response, sizeof(response), unixTime,
                                           _authenticationPolicy.context)))
    return fail(NetworkTimeClientError::AuthenticationFailed);
  if (_timeService == nullptr || !_timeService->applyTime(unixTime, _level))
    return fail(NetworkTimeClientError::TimeRejected);

  _receivedUnixTime = unixTime;
  _status = NetworkTimeClientStatus::Updated;
  _lastError = NetworkTimeClientError::None;
  _udp.stop();
  return _status;
}

void NetworkTimeClient::stop() {
  if (active())
    _udp.stop();
  _status = NetworkTimeClientStatus::Idle;
  _lastError = NetworkTimeClientError::None;
  _receivedUnixTime = 0;
  _pollCount = 0;
  memset(_requestTransmitTimestamp, 0, sizeof(_requestTransmitTimestamp));
}

bool NetworkTimeClient::parseResponse(
    const uint8_t *packet, const uint8_t expectedOriginateTimestamp[8],
    uint64_t &unixTimeOut) {
  if (packet == nullptr || expectedOriginateTimestamp == nullptr)
    return false;

  if ((packet[0] & NtpLeapIndicatorMask) == NtpLeapIndicatorAlarm)
    return false;
  if ((packet[0] & NtpVersionMask) != NtpVersion4)
    return false;
  const uint8_t mode = packet[0] & NtpModeMask;
  if (mode != NtpModeServer && mode != NtpModeBroadcast)
    return false;
  if (packet[1] == 0)
    return false;
  if (memcmp(packet + NtpOriginateTimestampOffset, expectedOriginateTimestamp,
             8) != 0)
    return false;

  const uint32_t ntpSeconds =
      readBigEndian32(packet + NtpTransmitTimestampOffset);
  if (ntpSeconds <= NtpUnixEpochOffset)
    return false;

  unixTimeOut = static_cast<uint64_t>(ntpSeconds) - NtpUnixEpochOffset;
  return true;
}

NetworkTimeClientStatus NetworkTimeClient::fail(NetworkTimeClientError error) {
  _status = NetworkTimeClientStatus::Failed;
  _lastError = error;
  _udp.stop();
  return _status;
}

bool NetworkTimeClient::consumePollBudget() {
  if (_pollLimit == 0)
    return false;
  if (_pollCount >= _pollLimit)
    return false;

  ++_pollCount;
  return true;
}
