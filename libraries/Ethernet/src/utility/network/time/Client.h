#pragma once

#include <EthernetUdp.h>
#include <IPAddress.h>
#include <stddef.h>
#include <stdint.h>
#include <utility/network/time/Config.h>
#include <utility/transport/TransportProvider.h>

class NetworkTimeService;

enum class NetworkTimeClientStatus : uint8_t {
  Idle = 0,
  Pending = 1,
  Updated = 2,
  Failed = 3,
};

enum class NetworkTimeClientError : uint8_t {
  None = 0,
  Busy = 1,
  InvalidArgument = 2,
  BindFailed = 3,
  BeginPacketFailed = 4,
  WriteFailed = 5,
  EndPacketFailed = 6,
  ShortPacket = 7,
  UnexpectedRemote = 8,
  ReadFailed = 9,
  InvalidResponse = 10,
  TimeRejected = 11,
  AuthenticationFailed = 12,
  OperationDeadlineExceeded = 13,
};

using NetworkTimeAuthenticator = bool (*)(const uint8_t *packet,
                                          size_t packetLength,
                                          uint64_t unixTime, void *context);

struct NetworkTimeAuthenticationPolicy {
  constexpr NetworkTimeAuthenticationPolicy() = default;
  constexpr NetworkTimeAuthenticationPolicy(NetworkTimeAuthenticator callback,
                                            void *callbackContext = nullptr)
      : authenticate(callback), context(callbackContext) {}

  NetworkTimeAuthenticator authenticate = nullptr;
  void *context = nullptr;

  bool valid() const { return authenticate != nullptr; }
};

class NetworkTimeClient {
public:
  static constexpr uint16_t DefaultServerPort =
      NetworkTimeProvisionalSource::DefaultServerPort;
  static constexpr uint16_t DefaultLocalPort =
      NetworkTimeProvisionalSource::DefaultLocalPort;
  static constexpr uint8_t PacketSize = 48;
  static constexpr uint16_t DefaultPollLimit = 2000;

  NetworkTimeClient() = default;
  NetworkTimeClient(TransportProvider &provider, NetworkTimeService &service);

  void attach(TransportProvider &provider, NetworkTimeService &service);

  bool beginRequest(IPAddress server, uint16_t serverPort = DefaultServerPort,
                    uint16_t localPort = DefaultLocalPort);
  bool beginAuthenticatedRequest(IPAddress server,
                                 const NetworkTimeAuthenticationPolicy &policy,
                                 uint16_t serverPort = DefaultServerPort,
                                 uint16_t localPort = DefaultLocalPort);
  bool setPollLimit(uint16_t pollLimit);
  NetworkTimeClientStatus poll();
  void stop();

  bool active() const { return _status == NetworkTimeClientStatus::Pending; }
  NetworkTimeClientStatus status() const { return _status; }
  NetworkTimeClientError lastError() const { return _lastError; }
  uint64_t receivedUnixTime() const { return _receivedUnixTime; }
  uint16_t pollLimit() const { return _pollLimit; }

private:
  static bool parseResponse(const uint8_t *packet,
                            const uint8_t expectedOriginateTimestamp[8],
                            uint64_t &unixTimeOut);
  bool startRequest(IPAddress server, uint16_t serverPort,
                    NetworkTimeLevel level, uint16_t localPort,
                    const NetworkTimeAuthenticationPolicy &policy);
  NetworkTimeClientStatus fail(NetworkTimeClientError error);
  bool consumePollBudget();

  EthernetUDP _udp;
  NetworkTimeService *_timeService = nullptr;
  IPAddress _server;
  NetworkTimeAuthenticationPolicy _authenticationPolicy = {};
  uint16_t _serverPort = DefaultServerPort;
  NetworkTimeLevel _level = NetworkTimeLevel::Provisional;
  NetworkTimeClientStatus _status = NetworkTimeClientStatus::Idle;
  NetworkTimeClientError _lastError = NetworkTimeClientError::None;
  uint64_t _receivedUnixTime = 0;
  uint16_t _pollLimit = DefaultPollLimit;
  uint16_t _pollCount = 0;
  uint8_t _requestTransmitTimestamp[8] = {};
};
