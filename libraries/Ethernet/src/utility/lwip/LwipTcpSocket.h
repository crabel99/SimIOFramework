/**
 * @file LwipTcpSocket.h
 * @brief Internal TCP/TLS socket wrapper for the lwIP port boundary.
 *
 * `LwipTcpSocket` is the narrow adapter between provider-owned transport
 * handles and the public `EthernetSocket` contract consumed by Arduino client
 * classes. It is not a second socket implementation and it is not a fallback
 * stack: the attached backend owns the real TCP PCB, accepted-client PCB, or
 * secure-client transport handle.
 *
 * The wrapper owns only delegation and fail-closed API behavior. Public client
 * objects may hold this adapter, but they must not see lwIP PCB types, DNS
 * callbacks, server listener state, or TLS transport internals.
 */
#pragma once

#include <utility/transport/TransportProvider.h>

class LwipTcpSocketBackend {
public:
  virtual ~LwipTcpSocketBackend() = default;

  /**
   * @brief Acquire and release bounded provider-owned TCP/TLS handles.
   *
   * Backends own the concrete lwIP resources. Each acquired handle must remain
   * valid until `releaseSocket()` or until the backend explicitly fails the
   * operation closed through the handle APIs.
   */
  virtual void *acquireClientSocket() = 0;
  virtual void *acquireSecureClientSocket() = 0;
  virtual void releaseSocket(void *handle) = 0;
  virtual bool tlsAvailable() const = 0;

  /**
   * @brief Listener and accepted-client operations.
   *
   * Listener lifetime is independent from accepted-client handle lifetime.
   * Stopping a listener must not invalidate a handle already returned by
   * `acceptClientSocket()`.
   */
  virtual bool beginServer(uint16_t port) = 0;
  virtual void stopServer(uint16_t port) = 0;
  virtual void *acceptClientSocket(uint16_t port) = 0;
  virtual size_t writeServer(uint16_t port, uint8_t value) = 0;
  virtual size_t writeServer(uint16_t port, const uint8_t *buffer,
                             size_t size) = 0;

  /**
   * @brief Per-handle stream operations.
   *
   * Calls must be bounded and fail closed for null, released, disconnected, or
   * carrier-down handles. Hostname connect may represent pending DNS inside the
   * backend without exposing DNS state through this adapter.
   */
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
