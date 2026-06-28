/**
 * @file LwipTransportBackend.h
 * @brief Concrete transport backend for lwIP-backed builds.
 *
 * `LwipTransportBackend` implements the internal TCP and UDP backend contracts at
 * the lwIP boundary. TCP client/server use lwIP's no-OS raw TCP PCB callback
 * API and UDP uses lwIP's no-OS `udp_pcb` callback API when the vendored lwIP
 * core is present. The secure-client slot is a second raw TCP handle that
 * `SecureClient` wraps with the Crypto/Mbed TLS session; this backend does not
 * own TLS state or call Mbed TLS directly. Public API classes must not own lwIP
 * internals directly. Capacity is intentionally fixed and Arduino-sized: one
 * plain client TCP slot, one secure-client TCP slot, one accepted server-client
 * slot, one listener, and one UDP endpoint. TCP hostname connects are
 * non-blocking: numeric or cached DNS answers proceed immediately, while
 * unresolved names leave the handle in a pending-connect state until lwIP's DNS
 * callback resolves or fails.
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
   * Only one plain client and one secure-client TCP slot are exposed by this
   * backend. The secure slot is TLS-capable only by contract; TLS protocol
   * state belongs to `SecureClient` and `libraries/Crypto`. Public clients
   * must release acquired handles through `releaseSocket()` before the same
   * slot can be acquired again.
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
   * names return success with the handle in pending-connect state; callers
   * observe progress through `connected()` without blocking.
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
   *
   * Multicast begin joins one IGMP group when enabled. `stop()` and rebegin
   * leave the previous group before releasing endpoint state, so multicast
   * membership cannot leak across endpoint lifetimes.
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
