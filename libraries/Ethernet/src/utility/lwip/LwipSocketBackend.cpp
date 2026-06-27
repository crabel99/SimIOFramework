#include "LwipSocketBackend.h"

#include <string.h>

#if defined(SIMIO_ETHERNET_ENABLE_LWIP_SOCKETS) &&                                \
    SIMIO_ETHERNET_ENABLE_LWIP_SOCKETS && defined(__has_include)
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

#if SIMIO_ETHERNET_HAS_LWIP_CORE
#include <lwip/dns.h>
#include <lwip/igmp.h>
#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#endif

namespace {

constexpr int kInvalidSocket = -1;
constexpr size_t kTcpBufferSize = 1536;
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

#if SIMIO_ETHERNET_HAS_LWIP_CORE
ip_addr_t makeRawIpAddress(IPAddress ip) {
  ip_addr_t address;
  IP_ADDR4(&address, ip[0], ip[1], ip[2], ip[3]);
  return address;
}

IPAddress rawIpAddressToIp(const ip_addr_t *address) {
  if (address == nullptr)
    return IPAddress();

  return hostOrderAddressToIp(lwip_ntohl(ip_addr_get_ip4_u32(address)));
}

uint32_t rawIpAddressToHostOrder(const ip_addr_t *address) {
  return address == nullptr ? 0 : lwip_ntohl(ip_addr_get_ip4_u32(address));
}

void ignoreDnsResult(const char *name, const ip_addr_t *address,
                     void *context) {
  (void)name;
  (void)address;
  (void)context;
}

bool resolveRawHostImmediate(const char *host, ip_addr_t &address) {
  if (host == nullptr || host[0] == '\0')
    return false;

  return dns_gethostbyname(host, &address, ignoreDnsResult, nullptr) == ERR_OK;
}
#endif

} // namespace

struct LwipSocketBackend::TcpHandle {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  tcp_pcb *pcb = nullptr;
#endif
  int fd = kInvalidSocket;
  bool acquired = false;
  bool connected = false;
  bool connecting = false;
  uint8_t rx[kTcpBufferSize];
  size_t rxLength = 0;
  size_t rxIndex = 0;
};

struct LwipSocketBackend::UdpState {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  udp_pcb *pcb = nullptr;
#endif
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

namespace {
void resetTcpReceiveBuffer(LwipSocketBackend::TcpHandle *state) {
  if (state == nullptr)
    return;

  state->rxLength = 0;
  state->rxIndex = 0;
}
} // namespace

#if SIMIO_ETHERNET_HAS_LWIP_CORE
namespace {
void detachTcpCallbacks(tcp_pcb *pcb) {
  if (pcb == nullptr)
    return;

  tcp_arg(pcb, nullptr);
  tcp_recv(pcb, nullptr);
  tcp_sent(pcb, nullptr);
  tcp_err(pcb, nullptr);
}

err_t receiveTcpData(void *arg, tcp_pcb *pcb, pbuf *packet, err_t err) {
  auto *state = static_cast<LwipSocketBackend::TcpHandle *>(arg);
  if (state == nullptr || pcb == nullptr)
    return ERR_ARG;

  if (packet == nullptr) {
    state->connected = false;
    state->connecting = false;
    state->pcb = nullptr;
    return ERR_OK;
  }

  if (err != ERR_OK) {
    pbuf_free(packet);
    return err;
  }

  const size_t receivedLength = packet->tot_len;
  size_t availableSpace = kTcpBufferSize - state->rxLength;
  size_t bytesToCopy = receivedLength;
  if (bytesToCopy > availableSpace)
    bytesToCopy = availableSpace;

  if (bytesToCopy > 0) {
    pbuf_copy_partial(packet, &state->rx[state->rxLength], bytesToCopy, 0);
    state->rxLength += bytesToCopy;
    tcp_recved(pcb, static_cast<u16_t>(bytesToCopy));
  }

  pbuf_free(packet);
  return bytesToCopy == receivedLength ? ERR_OK : ERR_MEM;
}

void handleTcpError(void *arg, err_t err) {
  (void)err;
  auto *state = static_cast<LwipSocketBackend::TcpHandle *>(arg);
  if (state == nullptr)
    return;

  state->pcb = nullptr;
  state->fd = kInvalidSocket;
  state->acquired = false;
  state->connected = false;
  state->connecting = false;
  resetTcpReceiveBuffer(state);
}

err_t tcpConnected(void *arg, tcp_pcb *pcb, err_t err) {
  auto *state = static_cast<LwipSocketBackend::TcpHandle *>(arg);
  if (state == nullptr || pcb == nullptr)
    return ERR_ARG;

  state->connecting = false;
  state->connected = err == ERR_OK;
  return err == ERR_OK ? ERR_OK : err;
}

void armTcpCallbacks(LwipSocketBackend::TcpHandle *state, tcp_pcb *pcb) {
  if (state == nullptr || pcb == nullptr)
    return;

  tcp_arg(pcb, state);
  tcp_recv(pcb, receiveTcpData);
  tcp_err(pcb, handleTcpError);
}

err_t acceptTcpConnection(void *arg, tcp_pcb *newPcb, err_t err) {
  auto *state = static_cast<LwipSocketBackend::TcpHandle *>(arg);
  if (state == nullptr || newPcb == nullptr || err != ERR_OK)
    return ERR_VAL;

  if (state->pcb != nullptr || state->acquired) {
    tcp_abort(newPcb);
    return ERR_ABRT;
  }

  state->pcb = newPcb;
  state->fd = kInvalidSocket;
  state->acquired = false;
  state->connected = true;
  state->connecting = false;
  resetTcpReceiveBuffer(state);
  armTcpCallbacks(state, newPcb);
  tcp_accepted(newPcb);
  return ERR_OK;
}

void receiveUdpPacket(void *arg, udp_pcb *pcb, pbuf *packet,
                      const ip_addr_t *address, u16_t port) {
  (void)pcb;
  auto *state = static_cast<LwipSocketBackend::UdpState *>(arg);
  if (state == nullptr || packet == nullptr) {
    if (packet != nullptr)
      pbuf_free(packet);
    return;
  }

  size_t bytesToCopy = packet->tot_len;
  if (bytesToCopy > kUdpBufferSize)
    bytesToCopy = kUdpBufferSize;

  pbuf_copy_partial(packet, state->rx, bytesToCopy, 0);
  state->rxLength = bytesToCopy;
  state->rxIndex = 0;
  state->rxRemote = {rawIpAddressToHostOrder(address), port};
  pbuf_free(packet);
}
} // namespace
#endif

LwipSocketBackend::LwipSocketBackend()
    : _client(new TcpHandle), _secure(new TcpHandle),
      _accepted(new TcpHandle), _udp(new UdpState), _serverPcb(nullptr),
      _serverFd(kInvalidSocket), _serverPort(0) {}

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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_client == nullptr || _client->acquired)
    return nullptr;

  closeTcpHandle(_client);
  _client->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (_client->pcb == nullptr)
    return nullptr;

  armTcpCallbacks(_client, _client->pcb);
  _client->acquired = true;
  return _client;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  stopServer(_serverPort);

  tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (pcb == nullptr)
    return false;

  ip_addr_t address;
  ip_addr_set_any(0, &address);
  if (tcp_bind(pcb, &address, port) != ERR_OK) {
    tcp_abort(pcb);
    return false;
  }

  err_t listenError = ERR_OK;
  tcp_pcb *listenPcb = reinterpret_cast<tcp_pcb *>(
      tcp_listen_with_backlog_and_err(pcb, 1, &listenError));
  if (listenPcb == nullptr || listenError != ERR_OK) {
    tcp_abort(pcb);
    return false;
  }

  tcp_arg(listenPcb, _accepted);
  tcp_accept(listenPcb, acceptTcpConnection);
  _serverPcb = listenPcb;
  _serverPort = port;
  return true;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_serverPcb != nullptr) {
    auto *pcb = static_cast<tcp_pcb *>(_serverPcb);
    tcp_arg(pcb, nullptr);
    tcp_accept(pcb, nullptr);
    if (tcp_close(pcb) != ERR_OK)
      tcp_abort(pcb);
  }
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_serverFd >= 0)
    lwip_close(_serverFd);
#endif
  _serverPcb = nullptr;
  _serverFd = kInvalidSocket;
  _serverPort = 0;
  closeTcpHandle(_accepted);
}

void *LwipSocketBackend::acceptClientSocket(uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_accepted == nullptr || _accepted->acquired || _accepted->pcb == nullptr ||
      port != _serverPort)
    return nullptr;

  _accepted->acquired = true;
  return _accepted;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr)
    return false;

#if SIMIO_ETHERNET_HAS_LWIP_CORE
  return tcp->pcb != nullptr;
#else
  return true;
#endif
}

int LwipSocketBackend::connect(void *handle, IPAddress ip, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->pcb == nullptr)
    return 0;

  ip_addr_t address = makeRawIpAddress(ip);
  if (tcp_connect(tcp->pcb, &address, port, tcpConnected) != ERR_OK) {
    closeTcpHandle(tcp);
    return 0;
  }

  tcp->connecting = true;
  return 1;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  ip_addr_t address;
  if (!resolveRawHostImmediate(host, address))
    return 0;

  return connect(handle, rawIpAddressToIp(&address), port);
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->pcb == nullptr || !tcp->connected ||
      buffer == nullptr || size == 0)
    return 0;

  if (size > tcp_sndbuf(tcp->pcb))
    size = tcp_sndbuf(tcp->pcb);
  if (size == 0)
    return 0;

  if (tcp_write(tcp->pcb, buffer, static_cast<u16_t>(size),
                TCP_WRITE_FLAG_COPY) != ERR_OK)
    return 0;

  if (tcp_output(tcp->pcb) != ERR_OK)
    return 0;

  return size;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->rxIndex >= tcp->rxLength)
    return 0;

  return static_cast<int>(tcp->rxLength - tcp->rxIndex);
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || buffer == nullptr || size == 0 ||
      tcp->rxIndex >= tcp->rxLength)
    return 0;

  size_t bytesToRead = tcp->rxLength - tcp->rxIndex;
  if (bytesToRead > size)
    bytesToRead = size;

  memcpy(buffer, &tcp->rx[tcp->rxIndex], bytesToRead);
  tcp->rxIndex += bytesToRead;
  if (tcp->rxIndex >= tcp->rxLength)
    resetTcpReceiveBuffer(tcp);

  return static_cast<int>(bytesToRead);
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->rxIndex >= tcp->rxLength)
    return -1;

  return tcp->rx[tcp->rxIndex];
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->pcb == nullptr)
    return 0;

  return tcp->connected || tcp->connecting ? 1 : 0;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_udp == nullptr)
    return 0;

  stop();
  _udp->pcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (_udp->pcb == nullptr) {
    stop();
    return 0;
  }

  ip_addr_t address;
  ip_addr_set_any(0, &address);
  if (udp_bind(_udp->pcb, &address, port) != ERR_OK) {
    stop();
    return 0;
  }

  udp_recv(_udp->pcb, receiveUdpPacket, _udp);
  _udp->started = true;
  return 1;
#else
  (void)port;
  return 0;
#endif
}

uint8_t LwipSocketBackend::beginMulticast(IPAddress ip, uint16_t port) {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  uint8_t started = begin(port);
  if (!started)
    return 0;

#if LWIP_IGMP
  ip_addr_t groupAddress = makeRawIpAddress(ip);
  if (igmp_joingroup(IP4_ADDR_ANY, ip_2_ip4(&groupAddress)) != ERR_OK) {
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_udp != nullptr && _udp->pcb != nullptr) {
    udp_recv(_udp->pcb, nullptr, nullptr);
    udp_remove(_udp->pcb);
  }
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (_udp != nullptr && _udp->fd >= 0)
    lwip_close(_udp->fd);
#endif
  if (_udp == nullptr)
    return;

#if SIMIO_ETHERNET_HAS_LWIP_CORE
  _udp->pcb = nullptr;
#endif
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  ip_addr_t address;
  if (!resolveRawHostImmediate(host, address))
    return 0;

  return beginPacket(rawIpAddressToIp(&address), port);
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (_udp == nullptr || !_udp->started || !_udp->packetOpen ||
      _udp->pcb == nullptr)
    return 0;

  pbuf *packet = pbuf_alloc(PBUF_TRANSPORT, _udp->txLength, PBUF_RAM);
  if (packet == nullptr)
    return 0;

  if (pbuf_take(packet, _udp->tx, _udp->txLength) != ERR_OK) {
    pbuf_free(packet);
    return 0;
  }

  ip_addr_t address =
      makeRawIpAddress(hostOrderAddressToIp(_udp->txRemote.address));
  err_t result = udp_sendto(_udp->pcb, packet, &address, _udp->txRemote.port);
  pbuf_free(packet);
  _udp->packetOpen = false;
  _udp->txLength = 0;
  return result == ERR_OK ? 1 : 0;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  return available();
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
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

#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (handle->pcb != nullptr) {
    tcp_pcb *pcb = handle->pcb;
    detachTcpCallbacks(pcb);
    if (tcp_close(pcb) != ERR_OK)
      tcp_abort(pcb);
  }
  handle->pcb = nullptr;
#elif SIMIO_ETHERNET_HAS_LWIP_SOCKETS
  if (handle->fd >= 0)
    lwip_close(handle->fd);
#endif
  handle->fd = kInvalidSocket;
  handle->acquired = false;
  handle->connected = false;
  handle->connecting = false;
  resetTcpReceiveBuffer(handle);
}

size_t LwipSocketBackend::writeServerToAccepted(const uint8_t *buffer,
                                                size_t size) {
  return write(_accepted, buffer, size);
}
