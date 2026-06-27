/**
 * @file LwipTransportBackend.h
 * @brief Concrete transport backend for lwIP-backed builds.
 *
 * `LwipTransportBackend` implements the internal TCP and UDP backend contracts at
 * the lwIP boundary. TCP client/server use lwIP's no-OS raw TCP PCB callback
 * API and UDP uses lwIP's no-OS `udp_pcb` callback API when the vendored lwIP
 * core is present. TLS currently remains fail-closed until a secure transport
 * provider is added above the TCP backend. Public API classes must not own
 * lwIP internals directly. Hostname operations are non-blocking: numeric or
 * cached DNS answers proceed immediately, while unresolved names return
 * fail-pending instead of waiting for DNS completion.
 */
#pragma once

#include <utility/lwip/LwipPort.h>

class LwipTransportBackend : public LwipTcpSocketBackend,
                             public LwipUdpBackend {
public:
  struct TcpHandle;
  struct UdpState;

  LwipTransportBackend();
  ~LwipTransportBackend() override;

  /**
   * @brief Allocate one provider-owned TCP client handle.
   *
   * Only one plain client and one secure client slot are exposed by this
   * backend. Public clients must release acquired handles through
   * `releaseSocket()`.
   */
  void *acquireClientSocket() override;
  void *acquireSecureClientSocket() override;
  void releaseSocket(void *handle) override;
  bool tlsAvailable() const override;

  /**
   * @brief Manage a single raw TCP server listener and accepted client slot.
   */
  bool beginServer(uint16_t port) override;
  void stopServer(uint16_t port) override;
  void *acceptClientSocket(uint16_t port) override;
  size_t writeServer(uint16_t port, uint8_t value) override;
  size_t writeServer(uint16_t port, const uint8_t *buffer,
                     size_t size) override;

  bool carrierUp(void *handle) const override;

  /**
   * @brief Start a bounded TCP connect attempt.
   *
   * Numeric IPs and cached DNS names may proceed immediately. Unresolved DNS
   * names fail pending rather than blocking for resolver completion.
   */
  int connect(void *handle, IPAddress ip, uint16_t port) override;
  int connect(void *handle, const char *host, uint16_t port) override;

  /**
   * @brief Stream operations against the provider-owned raw TCP handle.
   */
  size_t write(void *handle, uint8_t value) override;
  size_t write(void *handle, const uint8_t *buffer, size_t size) override;
  int available(void *handle) override;
  int read(void *handle) override;
  int read(void *handle, uint8_t *buffer, size_t size) override;
  int peek(void *handle) override;
  void flush(void *handle) override;
  void stop(void *handle) override;
  uint8_t connected(void *handle) override;

  /**
   * @brief UDP raw PCB endpoint and packet lifecycle.
   */
  uint8_t begin(uint16_t port) override;
  uint8_t beginMulticast(IPAddress ip, uint16_t port) override;
  void stop() override;
  int beginPacket(IPAddress ip, uint16_t port) override;
  int beginPacket(const char *host, uint16_t port) override;
  int endPacket() override;
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int parsePacket() override;
  int available() override;
  int read() override;
  int read(uint8_t *buffer, size_t size) override;
  int peek() override;
  void flush() override;
  IPAddress remoteIP() override;
  uint16_t remotePort() override;

private:
  TcpHandle *_client;
  TcpHandle *_secure;
  TcpHandle *_accepted;
  UdpState *_udp;
  void *_serverPcb;
  uint16_t _serverPort;

  TcpHandle *asTcpHandle(void *handle) const;
  void closeTcpHandle(TcpHandle *handle);
  size_t writeServerToAccepted(const uint8_t *buffer, size_t size);
};
