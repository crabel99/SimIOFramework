#include "NetworkTimeClient.h"

#include <string.h>

namespace {
constexpr uint64_t NtpUnixEpochOffset = 2208988800ULL;
constexpr uint8_t NtpClientRequest = 0x23; // LI=0, version=4, mode=3.
constexpr uint8_t NtpModeMask = 0x07;
constexpr uint8_t NtpModeServer = 4;
constexpr uint8_t NtpModeBroadcast = 5;
constexpr uint8_t NtpTransmitTimestampOffset = 40;

uint32_t readBigEndian32(const uint8_t *buffer) {
  return (static_cast<uint32_t>(buffer[0]) << 24) |
         (static_cast<uint32_t>(buffer[1]) << 16) |
         (static_cast<uint32_t>(buffer[2]) << 8) |
         static_cast<uint32_t>(buffer[3]);
}
} // namespace

NetworkTimeClient::NetworkTimeClient(TransportProvider &provider,
                                     NetworkClock &clock)
    : _udp(provider), _clock(clock) {}

bool NetworkTimeClient::beginRequest(IPAddress server, uint16_t serverPort,
                                     NetworkTimeState state,
                                     uint16_t localPort,
                                     NetworkTimeAuthentication authentication) {
  if (active()) {
    _lastError = NetworkTimeClientError::Busy;
    return false;
  }
  if (server == IPAddress() || serverPort == 0 ||
      state == NetworkTimeState::Unset) {
    _lastError = NetworkTimeClientError::InvalidArgument;
    return false;
  }
  if (state == NetworkTimeState::Trusted &&
      authentication != NetworkTimeAuthentication::AuthenticatedSource) {
    _lastError = NetworkTimeClientError::InvalidArgument;
    return false;
  }

  uint8_t request[PacketSize] = {};
  request[0] = NtpClientRequest;

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
  _state = state;
  _status = NetworkTimeClientStatus::Pending;
  _lastError = NetworkTimeClientError::None;
  _receivedUnixTime = 0;
  return true;
}

NetworkTimeClientStatus NetworkTimeClient::poll() {
  if (!active())
    return _status;

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
  if (!parseResponse(response, unixTime))
    return fail(NetworkTimeClientError::InvalidResponse);
  if (!_clock.setUnixTime(unixTime, _state))
    return fail(NetworkTimeClientError::ClockRejected);

  _receivedUnixTime = unixTime;
  _status = NetworkTimeClientStatus::Updated;
  _lastError = NetworkTimeClientError::None;
  _udp.stop();
  return _status;
}

void NetworkTimeClient::stop() {
  _udp.stop();
  _status = NetworkTimeClientStatus::Idle;
  _lastError = NetworkTimeClientError::None;
  _receivedUnixTime = 0;
}

bool NetworkTimeClient::parseResponse(const uint8_t *packet,
                                      uint64_t &unixTimeOut) {
  if (packet == nullptr)
    return false;

  const uint8_t mode = packet[0] & NtpModeMask;
  if (mode != NtpModeServer && mode != NtpModeBroadcast)
    return false;
  if (packet[1] == 0)
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
