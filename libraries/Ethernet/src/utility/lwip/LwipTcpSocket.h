/**
 * @file LwipTcpSocket.h
 * @brief Internal TCP/TLS socket wrapper for the lwIP port boundary.
 *
 * `LwipTcpSocket` adapts an opaque lwIP-side socket handle to the
 * `EthernetSocket` contract consumed by public Arduino client classes. The
 * backend owns the real protocol-control block or TLS session object; this
 * wrapper owns only delegation and fail-closed API behavior.
 */
#pragma once

#include <utility/transport/TransportProvider.h>

class LwipTcpSocketBackend {
public:
  virtual ~LwipTcpSocketBackend() = default;

  virtual void *acquireClientSocket() = 0;
  virtual void *acquireSecureClientSocket() = 0;
  virtual void releaseSocket(void *handle) = 0;
  virtual bool tlsAvailable() const = 0;

  virtual bool beginServer(uint16_t port) = 0;
  virtual void stopServer(uint16_t port) = 0;
  virtual void *acceptClientSocket(uint16_t port) = 0;
  virtual size_t writeServer(uint16_t port, uint8_t value) = 0;
  virtual size_t writeServer(uint16_t port, const uint8_t *buffer,
                             size_t size) = 0;

  virtual bool carrierUp(void *handle) const = 0;
  virtual int connect(void *handle, IPAddress ip, uint16_t port) = 0;
  virtual int connect(void *handle, const char *host, uint16_t port) = 0;
  virtual size_t write(void *handle, uint8_t value) = 0;
  virtual size_t write(void *handle, const uint8_t *buffer, size_t size) = 0;
  virtual int available(void *handle) = 0;
  virtual int read(void *handle) = 0;
  virtual int read(void *handle, uint8_t *buffer, size_t size) = 0;
  virtual int peek(void *handle) = 0;
  virtual void flush(void *handle) = 0;
  virtual void stop(void *handle) = 0;
  virtual uint8_t connected(void *handle) = 0;
};

class LwipTcpSocket : public EthernetSocket {
public:
  bool attached() const { return _backend != nullptr && _handle != nullptr; }
  void attach(LwipTcpSocketBackend &backend, void *handle);
  void detach();
  void *handle() const { return _handle; }

  bool carrierUp() const override;
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t *buffer, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;

private:
  LwipTcpSocketBackend *_backend = nullptr;
  void *_handle = nullptr;
};
