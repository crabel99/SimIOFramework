#include "LwipSocketBackend.h"

#include <string.h>

#if defined(__has_include)
#if __has_include(<lwip/sockets.h>)
#define SIMIO_ETHERNET_HAS_LWIP_SOCKETS 1
#endif
#endif

#ifndef SIMIO_ETHERNET_HAS_LWIP_SOCKETS
#define SIMIO_ETHERNET_HAS_LWIP_SOCKETS 0
#endif

#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
#include <errno.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#endif

namespace {

constexpr int kInvalidSocket = -1;
constexpr size_t kUdpBufferSize = 1536;

struct SockAddrParts {
  uint32_t address;
  uint16_t port;
};

uint32_t ipToHostOrderAddress(IPAddress ip) {
  return (static_cast<uint32_t>(ip[0]) << 24) |
         (static_cast<uint32_t>(ip[1]) << 16) |
         (static_cast<uint32_t>(ip[2]) << 8) | static_cast<uint32_t>(ip[3]);
}

IPAddress hostOrderAddressToIp(uint32_t address) {
  return IPAddress(static_cast<uint8_t>((address >> 24) & 0xff),
                   static_cast<uint8_t>((address >> 16) & 0xff),
                   static_cast<uint8_t>((address >> 8) & 0xff),
                   static_cast<uint8_t>(address & 0xff));
}

#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
bool isWouldBlockError() {
  return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS;
}

bool setNonBlocking(int fd) {
#if defined(FIONBIO)
  int nonBlocking = 1;
  return lwip_ioctl(fd, FIONBIO, &nonBlocking) == 0;
#else
  (void)fd;
  return false;
#endif
}

sockaddr_in makeSocketAddress(IPAddress ip, uint16_t port) {
  sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = lwip_htons(port);
  address.sin_addr.s_addr = lwip_htonl(ipToHostOrderAddress(ip));
  return address;
}

IPAddress socketAddressToIp(const sockaddr_in &address) {
  return hostOrderAddressToIp(lwip_ntohl(address.sin_addr.s_addr));
}

uint16_t socketAddressToPort(const sockaddr_in &address) {
  return lwip_ntohs(address.sin_port);
}

bool resolveHost(const char *host, uint16_t port, sockaddr_in &address) {
  if (host == nullptr || host[0] == '\0')
    return false;

  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char service[6];
  snprintf(service, sizeof(service), "%u", static_cast<unsigned>(port));

  addrinfo *result = nullptr;
  if (lwip_getaddrinfo(host, service, &hints, &result) != 0 || result == nullptr)
    return false;

  bool resolved = false;
  if (result->ai_addr != nullptr &&
      result->ai_addrlen >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
    memcpy(&address, result->ai_addr, sizeof(sockaddr_in));
    resolved = true;
  }

  lwip_freeaddrinfo(result);
  return resolved;
}
#endif

} // namespace

struct LwipSocketBackend::TcpHandle {
  int fd = kInvalidSocket;
  bool acquired = false;
  bool connected = false;
};

struct LwipSocketBackend::UdpState {
  int fd = kInvalidSocket;
  bool started = false;
  bool packetOpen = false;
  uint8_t tx[kUdpBufferSize];
  size_t txLength = 0;
  uint8_t rx[kUdpBufferSize];
  size_t rxLength = 0;
  size_t rxIndex = 0;
  SockAddrParts txRemote = {0, 0};
  SockAddrParts rxRemote = {0, 0};
};

LwipSocketBackend::LwipSocketBackend()
    : _client(new TcpHandle), _secure(new TcpHandle),
      _accepted(new TcpHandle), _udp(new UdpState), _serverFd(kInvalidSocket),
      _serverPort(0) {}

LwipSocketBackend::~LwipSocketBackend() {
  stopServer(_serverPort);
  stop();
  closeTcpHandle(_client);
  closeTcpHandle(_secure);
  closeTcpHandle(_accepted);
  delete _client;
  delete _secure;
  delete _accepted;
  delete _udp;
}

bool LwipSocketBackend::socketsAvailable() const {
  return SIMIO_ETHERNET_HAS_LWIP_SOCKETS != 0;
}

void *LwipSocketBackend::acquireClientSocket() {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_client == nullptr || _client->acquired)
    return nullptr;

  closeTcpHandle(_client);
  _client->fd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (_client->fd < 0 || !setNonBlocking(_client->fd)) {
    closeTcpHandle(_client);
    return nullptr;
  }

  _client->acquired = true;
  return _client;
#else
  return nullptr;
#endif
}

void *LwipSocketBackend::acquireSecureClientSocket() { return nullptr; }

void LwipSocketBackend::releaseSocket(void *handle) {
  closeTcpHandle(asTcpHandle(handle));
}

bool LwipSocketBackend::tlsAvailable() const { return false; }

bool LwipSocketBackend::beginServer(uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  stopServer(_serverPort);

  _serverFd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (_serverFd < 0 || !setNonBlocking(_serverFd)) {
    stopServer(port);
    return false;
  }

  int reuse = 1;
  lwip_setsockopt(_serverFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in address = makeSocketAddress(IPAddress(0, 0, 0, 0), port);
  if (lwip_bind(_serverFd, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0 ||
      lwip_listen(_serverFd, 1) != 0) {
    stopServer(port);
    return false;
  }

  _serverPort = port;
  return true;
#else
  (void)port;
  return false;
#endif
}

void LwipSocketBackend::stopServer(uint16_t port) {
  (void)port;
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_serverFd >= 0)
    lwip_close(_serverFd);
#endif
  _serverFd = kInvalidSocket;
  _serverPort = 0;
  closeTcpHandle(_accepted);
}

void *LwipSocketBackend::acceptClientSocket(uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_accepted == nullptr || _accepted->acquired || _serverFd < 0 ||
      port != _serverPort)
    return nullptr;

  sockaddr_in address;
  socklen_t addressLength = sizeof(address);
  int fd = lwip_accept(_serverFd, reinterpret_cast<sockaddr *>(&address),
                       &addressLength);
  if (fd < 0)
    return nullptr;

  if (!setNonBlocking(fd)) {
    lwip_close(fd);
    return nullptr;
  }

  _accepted->fd = fd;
  _accepted->acquired = true;
  _accepted->connected = true;
  return _accepted;
#else
  (void)port;
  return nullptr;
#endif
}

size_t LwipSocketBackend::writeServer(uint16_t port, uint8_t value) {
  return writeServer(port, &value, 1);
}

size_t LwipSocketBackend::writeServer(uint16_t port, const uint8_t *buffer,
                                      size_t size) {
  if (port != _serverPort)
    return 0;

  return writeServerToAccepted(buffer, size);
}

bool LwipSocketBackend::carrierUp(void *handle) const {
  return asTcpHandle(handle) != nullptr;
}

int LwipSocketBackend::connect(void *handle, IPAddress ip, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0)
    return 0;

  sockaddr_in address = makeSocketAddress(ip, port);
  if (lwip_connect(tcp->fd, reinterpret_cast<sockaddr *>(&address),
                   sizeof(address)) == 0 ||
      isWouldBlockError()) {
    tcp->connected = true;
    return 1;
  }

  closeTcpHandle(tcp);
  return 0;
#else
  (void)handle;
  (void)ip;
  (void)port;
  return 0;
#endif
}

int LwipSocketBackend::connect(void *handle, const char *host, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  sockaddr_in address;
  if (!resolveHost(host, port, address))
    return 0;

  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0)
    return 0;

  if (lwip_connect(tcp->fd, reinterpret_cast<sockaddr *>(&address),
                   sizeof(address)) == 0 ||
      isWouldBlockError()) {
    tcp->connected = true;
    return 1;
  }

  closeTcpHandle(tcp);
  return 0;
#else
  (void)handle;
  (void)host;
  (void)port;
  return 0;
#endif
}

size_t LwipSocketBackend::write(void *handle, uint8_t value) {
  return write(handle, &value, 1);
}

size_t LwipSocketBackend::write(void *handle, const uint8_t *buffer,
                                size_t size) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0 || buffer == nullptr || size == 0)
    return 0;

  int written = lwip_send(tcp->fd, buffer, size, 0);
  if (written <= 0)
    return 0;

  return static_cast<size_t>(written);
#else
  (void)handle;
  (void)buffer;
  (void)size;
  return 0;
#endif
}

int LwipSocketBackend::available(void *handle) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0)
    return 0;

#if defined(FIONREAD)
  int count = 0;
  if (lwip_ioctl(tcp->fd, FIONREAD, &count) == 0)
    return count;
#endif
  uint8_t value = 0;
  int result = lwip_recv(tcp->fd, &value, 1, MSG_PEEK);
  return result > 0 ? result : 0;
#else
  (void)handle;
  return 0;
#endif
}

int LwipSocketBackend::read(void *handle) {
  uint8_t value = 0;
  int result = read(handle, &value, 1);
  return result == 1 ? value : -1;
}

int LwipSocketBackend::read(void *handle, uint8_t *buffer, size_t size) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0 || buffer == nullptr || size == 0)
    return 0;

  int result = lwip_recv(tcp->fd, buffer, size, 0);
  if (result == 0)
    tcp->connected = false;
  return result > 0 ? result : 0;
#else
  (void)handle;
  (void)buffer;
  (void)size;
  return 0;
#endif
}

int LwipSocketBackend::peek(void *handle) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0)
    return -1;

  uint8_t value = 0;
  int result = lwip_recv(tcp->fd, &value, 1, MSG_PEEK);
  return result == 1 ? value : -1;
#else
  (void)handle;
  return -1;
#endif
}

void LwipSocketBackend::flush(void *handle) { (void)handle; }

void LwipSocketBackend::stop(void *handle) {
  closeTcpHandle(asTcpHandle(handle));
}

uint8_t LwipSocketBackend::connected(void *handle) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->fd < 0 || !tcp->connected)
    return 0;

  int error = 0;
  socklen_t errorLength = sizeof(error);
  if (lwip_getsockopt(tcp->fd, SOL_SOCKET, SO_ERROR, &error, &errorLength) != 0)
    return 0;

  if (error != 0) {
    tcp->connected = false;
    return 0;
  }

  return 1;
#else
  (void)handle;
  return 0;
#endif
}

uint8_t LwipSocketBackend::begin(uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_udp == nullptr)
    return 0;

  stop();
  _udp->fd = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (_udp->fd < 0 || !setNonBlocking(_udp->fd)) {
    stop();
    return 0;
  }

  sockaddr_in address = makeSocketAddress(IPAddress(0, 0, 0, 0), port);
  if (lwip_bind(_udp->fd, reinterpret_cast<sockaddr *>(&address),
                sizeof(address)) != 0) {
    stop();
    return 0;
  }

  _udp->started = true;
  return 1;
#else
  (void)port;
  return 0;
#endif
}

uint8_t LwipSocketBackend::beginMulticast(IPAddress ip, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  uint8_t started = begin(port);
  if (!started)
    return 0;

#if defined(IP_ADD_MEMBERSHIP)
  ip_mreq request;
  request.imr_multiaddr.s_addr = lwip_htonl(ipToHostOrderAddress(ip));
  request.imr_interface.s_addr = lwip_htonl(INADDR_ANY);
  if (lwip_setsockopt(_udp->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request,
                      sizeof(request)) != 0) {
    stop();
    return 0;
  }
#else
  (void)ip;
#endif
  return 1;
#else
  (void)ip;
  (void)port;
  return 0;
#endif
}

void LwipSocketBackend::stop() {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_udp != nullptr && _udp->fd >= 0)
    lwip_close(_udp->fd);
#endif
  if (_udp == nullptr)
    return;

  _udp->fd = kInvalidSocket;
  _udp->started = false;
  _udp->packetOpen = false;
  _udp->txLength = 0;
  _udp->rxLength = 0;
  _udp->rxIndex = 0;
  _udp->txRemote = {0, 0};
  _udp->rxRemote = {0, 0};
}

int LwipSocketBackend::beginPacket(IPAddress ip, uint16_t port) {
  if (_udp == nullptr || !_udp->started)
    return 0;

  _udp->txRemote = {ipToHostOrderAddress(ip), port};
  _udp->txLength = 0;
  _udp->packetOpen = true;
  return 1;
}

int LwipSocketBackend::beginPacket(const char *host, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  sockaddr_in address;
  if (!resolveHost(host, port, address))
    return 0;

  return beginPacket(socketAddressToIp(address), socketAddressToPort(address));
#else
  (void)host;
  (void)port;
  return 0;
#endif
}

int LwipSocketBackend::endPacket() {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_udp == nullptr || !_udp->started || !_udp->packetOpen)
    return 0;

  sockaddr_in address =
      makeSocketAddress(hostOrderAddressToIp(_udp->txRemote.address),
                        _udp->txRemote.port);
  int sent = lwip_sendto(_udp->fd, _udp->tx, _udp->txLength, 0,
                         reinterpret_cast<sockaddr *>(&address),
                         sizeof(address));
  _udp->packetOpen = false;
  _udp->txLength = 0;
  return sent >= 0 ? 1 : 0;
#else
  return 0;
#endif
}

size_t LwipSocketBackend::write(uint8_t value) { return write(&value, 1); }

size_t LwipSocketBackend::write(const uint8_t *buffer, size_t size) {
  if (_udp == nullptr || !_udp->started || !_udp->packetOpen ||
      buffer == nullptr || size == 0)
    return 0;

  size_t availableSpace = kUdpBufferSize - _udp->txLength;
  if (size > availableSpace)
    size = availableSpace;

  memcpy(&_udp->tx[_udp->txLength], buffer, size);
  _udp->txLength += size;
  return size;
}

int LwipSocketBackend::parsePacket() {
#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_udp == nullptr || !_udp->started)
    return 0;

  sockaddr_in address;
  socklen_t addressLength = sizeof(address);
  int received = lwip_recvfrom(_udp->fd, _udp->rx, kUdpBufferSize, 0,
                               reinterpret_cast<sockaddr *>(&address),
                               &addressLength);
  if (received <= 0)
    return 0;

  _udp->rxLength = static_cast<size_t>(received);
  _udp->rxIndex = 0;
  _udp->rxRemote = {ipToHostOrderAddress(socketAddressToIp(address)),
                    socketAddressToPort(address)};
  return received;
#else
  return 0;
#endif
}

int LwipSocketBackend::available() {
  if (_udp == nullptr || !_udp->started || _udp->rxIndex >= _udp->rxLength)
    return 0;

  return static_cast<int>(_udp->rxLength - _udp->rxIndex);
}

int LwipSocketBackend::read() {
  if (available() <= 0)
    return -1;

  return _udp->rx[_udp->rxIndex++];
}

int LwipSocketBackend::read(uint8_t *buffer, size_t size) {
  if (buffer == nullptr || size == 0 || available() <= 0)
    return 0;

  size_t bytesToRead = static_cast<size_t>(available());
  if (bytesToRead > size)
    bytesToRead = size;

  memcpy(buffer, &_udp->rx[_udp->rxIndex], bytesToRead);
  _udp->rxIndex += bytesToRead;
  return static_cast<int>(bytesToRead);
}

int LwipSocketBackend::peek() {
  if (available() <= 0)
    return -1;

  return _udp->rx[_udp->rxIndex];
}

void LwipSocketBackend::flush() {
  if (_udp == nullptr)
    return;

  _udp->rxIndex = _udp->rxLength;
}

IPAddress LwipSocketBackend::remoteIP() {
  if (_udp == nullptr)
    return IPAddress();

  return hostOrderAddressToIp(_udp->rxRemote.address);
}

uint16_t LwipSocketBackend::remotePort() {
  return _udp == nullptr ? 0 : _udp->rxRemote.port;
}

LwipSocketBackend::TcpHandle *LwipSocketBackend::asTcpHandle(void *handle) const {
  if (handle == _client)
    return _client;
  if (handle == _secure)
    return _secure;
  if (handle == _accepted)
    return _accepted;

  return nullptr;
}

void LwipSocketBackend::closeTcpHandle(TcpHandle *handle) {
  if (handle == nullptr)
    return;

#if SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (handle->fd >= 0)
    lwip_close(handle->fd);
#endif
  handle->fd = kInvalidSocket;
  handle->acquired = false;
  handle->connected = false;
}

size_t LwipSocketBackend::writeServerToAccepted(const uint8_t *buffer,
                                                size_t size) {
  return write(_accepted, buffer, size);
}
