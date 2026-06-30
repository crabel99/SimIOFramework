#pragma once

#include <EthernetUdp.h>
#include <IPAddress.h>
#include <stdint.h>
#include <utility/network/NetworkClock.h>
#include <utility/transport/TransportProvider.h>

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
  ClockRejected = 11,
};

/**
 * @brief Bounded SNTP client that applies received time through NetworkClock.
 *
 * The client sends one UDP SNTP request and returns immediately. Call `poll()`
 * from the network service loop until it returns `Updated` or `Failed`.
 * The caller selects whether an accepted response is manual/provisional or
 * trusted; `NetworkClock` enforces that manual time cannot overwrite trusted
 * time after promotion.
 */
class NetworkTimeClient {
public:
  static constexpr uint16_t DefaultServerPort = 123;
  static constexpr uint16_t DefaultLocalPort = 0;
  static constexpr uint8_t PacketSize = 48;

  NetworkTimeClient(TransportProvider &provider, NetworkClock &clock);

  bool beginRequest(IPAddress server, uint16_t serverPort = DefaultServerPort,
                    NetworkTimeState state = NetworkTimeState::Manual,
                    uint16_t localPort = DefaultLocalPort);
  NetworkTimeClientStatus poll();
  void stop();

  bool active() const { return _status == NetworkTimeClientStatus::Pending; }
  NetworkTimeClientStatus status() const { return _status; }
  NetworkTimeClientError lastError() const { return _lastError; }
  uint64_t receivedUnixTime() const { return _receivedUnixTime; }

private:
  static bool parseResponse(const uint8_t *packet, uint64_t &unixTimeOut);
  NetworkTimeClientStatus fail(NetworkTimeClientError error);

  EthernetUDP _udp;
  NetworkClock &_clock;
  IPAddress _server;
  uint16_t _serverPort = DefaultServerPort;
  NetworkTimeState _state = NetworkTimeState::Manual;
  NetworkTimeClientStatus _status = NetworkTimeClientStatus::Idle;
  NetworkTimeClientError _lastError = NetworkTimeClientError::None;
  uint64_t _receivedUnixTime = 0;
};
