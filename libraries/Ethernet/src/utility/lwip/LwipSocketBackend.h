/**
 * @file LwipSocketBackend.h
 * @brief Concrete TCP/UDP backend for lwIP socket builds.
 *
 * `LwipSocketBackend` implements the internal TCP and UDP backend contracts
 * using lwIP's socket API when lwIP is present. If lwIP headers are not
 * available at compile time, the same class compiles as a fail-closed backend
 * so native tests and partial framework builds do not accidentally pull in
 * platform networking dependencies.
 */
#pragma once

#include <utility/lwip/LwipPort.h>

class LwipSocketBackend : public LwipTcpSocketBackend,
                          public LwipUdpBackend {
public:
  LwipSocketBackend();
  ~LwipSocketBackend() override;

  bool socketsAvailable() const;

  void *acquireClientSocket() override;
  void *acquireSecureClientSocket() override;
  void releaseSocket(void *handle) override;
  bool tlsAvailable() const override;

  bool beginServer(uint16_t port) override;
  void stopServer(uint16_t port) override;
  void *acceptClientSocket(uint16_t port) override;
  size_t writeServer(uint16_t port, uint8_t value) override;
  size_t writeServer(uint16_t port, const uint8_t *buffer,
                     size_t size) override;

  bool carrierUp(void *handle) const override;
  int connect(void *handle, IPAddress ip, uint16_t port) override;
  int connect(void *handle, const char *host, uint16_t port) override;
  size_t write(void *handle, uint8_t value) override;
  size_t write(void *handle, const uint8_t *buffer, size_t size) override;
  int available(void *handle) override;
  int read(void *handle) override;
  int read(void *handle, uint8_t *buffer, size_t size) override;
  int peek(void *handle) override;
  void flush(void *handle) override;
  void stop(void *handle) override;
  uint8_t connected(void *handle) override;

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
  struct TcpHandle;
  struct UdpState;

  TcpHandle *_client;
  TcpHandle *_secure;
  TcpHandle *_accepted;
  UdpState *_udp;
  int _serverFd;
  uint16_t _serverPort;

  TcpHandle *asTcpHandle(void *handle) const;
  void closeTcpHandle(TcpHandle *handle);
  size_t writeServerToAccepted(const uint8_t *buffer, size_t size);
};
