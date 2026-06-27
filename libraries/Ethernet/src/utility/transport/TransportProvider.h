/**
 * @file TransportProvider.h
 * @brief Internal socket and transport contract for Ethernet public APIs.
 *
 * `TransportProvider` is the single boundary consumed by `EthernetClient`,
 * `EthernetServer`, `EthernetUDP`, and `SecureClient`. It owns the eventual
 * lwIP TCP/UDP/TLS backing objects and exposes only Arduino-facing transport
 * operations to public classes.
 *
 * Public API classes own Arduino semantics and provider socket lifetime. The
 * provider owns protocol-control blocks, listener state, UDP packet state, DNS
 * resolution, and TLS-capable socket creation. Neither side may reach down into
 * GMAC descriptors, PHY state, MIIM operations, or hardware registers.
 *
 * All operations must be bounded and fail closed. Provider-acquired TCP/TLS
 * sockets remain provider-owned and are released by the public facade through
 * `releaseSocket()`. Server listeners are independent from accepted clients:
 * stopping a listener must not invalidate an accepted client socket that has
 * already been handed to `EthernetClient`.
 */
#pragma once

#include <IPAddress.h>

#include <stddef.h>
#include <stdint.h>

class EthernetSocket {
public:
  virtual ~EthernetSocket() = default;

  /**
   * @brief Return cached carrier state for fail-fast connect decisions.
   */
  virtual bool carrierUp() const = 0;

  /**
   * @brief Start a TCP/TLS-capable socket connection.
   */
  virtual int connect(IPAddress ip, uint16_t port) = 0;
  virtual int connect(const char *host, uint16_t port) = 0;

  /**
   * @brief Delegate Arduino stream operations to the provider-owned socket.
   *
   * Stream calls must return a fail-closed value when disconnected or invalid
   * rather than blocking for carrier, connection progress, or receive data.
   */
  virtual size_t write(uint8_t value) = 0;
  virtual size_t write(const uint8_t *buffer, size_t size) = 0;
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int read(uint8_t *buffer, size_t size) = 0;
  virtual int peek() = 0;
  virtual void flush() = 0;
  virtual void stop() = 0;
  virtual uint8_t connected() = 0;
};

class TransportProvider {
public:
  virtual ~TransportProvider() = default;

  /**
   * @brief Acquire provider-owned sockets for public client objects.
   *
   * The caller owns the acquired handle until it calls `releaseSocket()`. If a
   * connect attempt fails after acquisition, the public client must release the
   * handle before returning failure.
   */
  virtual EthernetSocket *acquireClientSocket() = 0;
  virtual EthernetSocket *acquireSecureClientSocket() = 0;
  virtual void releaseSocket(EthernetSocket *socket) = 0;
  virtual bool tlsAvailable() const = 0;

  /**
   * @brief Server/listener operations keyed by Arduino server port.
   *
   * Accepted sockets are returned to public `EthernetClient` objects, which own
   * release responsibility after acceptance.
   */
  virtual bool beginServer(uint16_t port) = 0;
  virtual void stopServer(uint16_t port) = 0;
  virtual EthernetSocket *acceptClientSocket(uint16_t port) = 0;
  virtual size_t writeServer(uint16_t port, uint8_t value) = 0;
  virtual size_t writeServer(uint16_t port, const uint8_t *buffer,
                             size_t size) = 0;

  /**
   * @brief UDP endpoint and packet operations.
   *
   * The provider owns UDP endpoint binding, multicast membership, outbound
   * packet buffering, receive buffering, and remote endpoint state. Packet
   * writes must be bounded by the backend buffer and report the accepted byte
   * count without overrunning.
   */
  virtual uint8_t beginUdp(uint16_t port) = 0;
  virtual uint8_t beginUdpMulticast(IPAddress ip, uint16_t port) = 0;
  virtual void stopUdp() = 0;
  virtual int beginUdpPacket(IPAddress ip, uint16_t port) = 0;
  virtual int beginUdpPacket(const char *host, uint16_t port) = 0;
  virtual int endUdpPacket() = 0;
  virtual size_t writeUdp(uint8_t value) = 0;
  virtual size_t writeUdp(const uint8_t *buffer, size_t size) = 0;
  virtual int parseUdpPacket() = 0;
  virtual int availableUdp() = 0;
  virtual int readUdp() = 0;
  virtual int readUdp(uint8_t *buffer, size_t size) = 0;
  virtual int peekUdp() = 0;
  virtual void flushUdp() = 0;
  virtual IPAddress remoteUdpIP() = 0;
  virtual uint16_t remoteUdpPort() = 0;
};
