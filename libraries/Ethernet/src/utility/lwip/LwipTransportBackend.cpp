#include "LwipTransportBackend.h"

#include <string.h>

#include <lwip/dns.h>
#include <lwip/igmp.h>
#include <lwip/ip_addr.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

namespace {

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

} // namespace

struct LwipTransportBackend::TcpHandle {
  tcp_pcb *pcb = nullptr;
  bool acquired = false;
  bool connected = false;
  bool connecting = false;
  uint8_t rx[kTcpBufferSize];
  size_t rxLength = 0;
  size_t rxIndex = 0;
};

struct LwipTransportBackend::UdpState {
  udp_pcb *pcb = nullptr;
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
void resetTcpReceiveBuffer(LwipTransportBackend::TcpHandle *state) {
  if (state == nullptr)
    return;

  state->rxLength = 0;
  state->rxIndex = 0;
}
} // namespace

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
  auto *state = static_cast<LwipTransportBackend::TcpHandle *>(arg);
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
  auto *state = static_cast<LwipTransportBackend::TcpHandle *>(arg);
  if (state == nullptr)
    return;

  state->pcb = nullptr;
  state->acquired = false;
  state->connected = false;
  state->connecting = false;
  resetTcpReceiveBuffer(state);
}

err_t tcpConnected(void *arg, tcp_pcb *pcb, err_t err) {
  auto *state = static_cast<LwipTransportBackend::TcpHandle *>(arg);
  if (state == nullptr || pcb == nullptr)
    return ERR_ARG;

  state->connecting = false;
  state->connected = err == ERR_OK;
  return err == ERR_OK ? ERR_OK : err;
}

void armTcpCallbacks(LwipTransportBackend::TcpHandle *state, tcp_pcb *pcb) {
  if (state == nullptr || pcb == nullptr)
    return;

  tcp_arg(pcb, state);
  tcp_recv(pcb, receiveTcpData);
  tcp_err(pcb, handleTcpError);
}

err_t acceptTcpConnection(void *arg, tcp_pcb *newPcb, err_t err) {
  auto *state = static_cast<LwipTransportBackend::TcpHandle *>(arg);
  if (state == nullptr || newPcb == nullptr || err != ERR_OK)
    return ERR_VAL;

  if (state->pcb != nullptr || state->acquired) {
    tcp_abort(newPcb);
    return ERR_ABRT;
  }

  state->pcb = newPcb;
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
  auto *state = static_cast<LwipTransportBackend::UdpState *>(arg);
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

LwipTransportBackend::LwipTransportBackend()
    : _client(new TcpHandle), _secure(new TcpHandle),
      _accepted(new TcpHandle), _udp(new UdpState), _serverPcb(nullptr),
      _serverPort(0) {}

LwipTransportBackend::~LwipTransportBackend() {
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

void *LwipTransportBackend::acquireClientSocket() {
  if (_client == nullptr || _client->acquired)
    return nullptr;

  closeTcpHandle(_client);
  _client->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (_client->pcb == nullptr)
    return nullptr;

  armTcpCallbacks(_client, _client->pcb);
  _client->acquired = true;
  return _client;
}

void *LwipTransportBackend::acquireSecureClientSocket() {
  if (_secure == nullptr || _secure->acquired)
    return nullptr;

  closeTcpHandle(_secure);
  _secure->pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (_secure->pcb == nullptr)
    return nullptr;

  armTcpCallbacks(_secure, _secure->pcb);
  _secure->acquired = true;
  return _secure;
}

void LwipTransportBackend::releaseSocket(void *handle) {
  closeTcpHandle(asTcpHandle(handle));
}

bool LwipTransportBackend::tlsAvailable() const { return _secure != nullptr; }

bool LwipTransportBackend::beginServer(uint16_t port) {
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
}

void LwipTransportBackend::stopServer(uint16_t port) {
  (void)port;
  if (_serverPcb != nullptr) {
    auto *pcb = static_cast<tcp_pcb *>(_serverPcb);
    tcp_arg(pcb, nullptr);
    tcp_accept(pcb, nullptr);
    if (tcp_close(pcb) != ERR_OK)
      tcp_abort(pcb);
  }
  _serverPcb = nullptr;
  _serverPort = 0;
  if (_accepted != nullptr && !_accepted->acquired)
    closeTcpHandle(_accepted);
}

void *LwipTransportBackend::acceptClientSocket(uint16_t port) {
  if (_accepted == nullptr || _accepted->acquired || _accepted->pcb == nullptr ||
      port != _serverPort)
    return nullptr;

  _accepted->acquired = true;
  return _accepted;
}

size_t LwipTransportBackend::writeServer(uint16_t port, uint8_t value) {
  return writeServer(port, &value, 1);
}

size_t LwipTransportBackend::writeServer(uint16_t port, const uint8_t *buffer,
                                      size_t size) {
  if (port != _serverPort)
    return 0;

  return writeServerToAccepted(buffer, size);
}

bool LwipTransportBackend::carrierUp(void *handle) const {
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr)
    return false;

  return tcp->pcb != nullptr;
}

int LwipTransportBackend::connect(void *handle, IPAddress ip, uint16_t port) {
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
}

int LwipTransportBackend::connect(void *handle, const char *host, uint16_t port) {
  ip_addr_t address;
  if (!resolveRawHostImmediate(host, address))
    return 0;

  return connect(handle, rawIpAddressToIp(&address), port);
}

size_t LwipTransportBackend::write(void *handle, uint8_t value) {
  return write(handle, &value, 1);
}

size_t LwipTransportBackend::write(void *handle, const uint8_t *buffer,
                                size_t size) {
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
}

int LwipTransportBackend::available(void *handle) {
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->rxIndex >= tcp->rxLength)
    return 0;

  return static_cast<int>(tcp->rxLength - tcp->rxIndex);
}

int LwipTransportBackend::read(void *handle) {
  uint8_t value = 0;
  int result = read(handle, &value, 1);
  return result == 1 ? value : -1;
}

int LwipTransportBackend::read(void *handle, uint8_t *buffer, size_t size) {
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
}

int LwipTransportBackend::peek(void *handle) {
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->rxIndex >= tcp->rxLength)
    return -1;

  return tcp->rx[tcp->rxIndex];
}

void LwipTransportBackend::flush(void *handle) { (void)handle; }

void LwipTransportBackend::stop(void *handle) {
  closeTcpHandle(asTcpHandle(handle));
}

uint8_t LwipTransportBackend::connected(void *handle) {
  TcpHandle *tcp = asTcpHandle(handle);
  if (tcp == nullptr || tcp->pcb == nullptr)
    return 0;

  return tcp->connected || tcp->connecting ? 1 : 0;
}

uint8_t LwipTransportBackend::begin(uint16_t port) {
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
}

uint8_t LwipTransportBackend::beginMulticast(IPAddress ip, uint16_t port) {
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
}

void LwipTransportBackend::stop() {
  if (_udp != nullptr && _udp->pcb != nullptr) {
    udp_recv(_udp->pcb, nullptr, nullptr);
    udp_remove(_udp->pcb);
  }
  if (_udp == nullptr)
    return;

  _udp->pcb = nullptr;
  _udp->started = false;
  _udp->packetOpen = false;
  _udp->txLength = 0;
  _udp->rxLength = 0;
  _udp->rxIndex = 0;
  _udp->txRemote = {0, 0};
  _udp->rxRemote = {0, 0};
}

int LwipTransportBackend::beginPacket(IPAddress ip, uint16_t port) {
  if (_udp == nullptr || !_udp->started)
    return 0;

  _udp->txRemote = {ipToHostOrderAddress(ip), port};
  _udp->txLength = 0;
  _udp->packetOpen = true;
  return 1;
}

int LwipTransportBackend::beginPacket(const char *host, uint16_t port) {
  ip_addr_t address;
  if (!resolveRawHostImmediate(host, address))
    return 0;

  return beginPacket(rawIpAddressToIp(&address), port);
}

int LwipTransportBackend::endPacket() {
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
}

size_t LwipTransportBackend::write(uint8_t value) { return write(&value, 1); }

size_t LwipTransportBackend::write(const uint8_t *buffer, size_t size) {
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

int LwipTransportBackend::parsePacket() {
  return available();
}

int LwipTransportBackend::available() {
  if (_udp == nullptr || !_udp->started || _udp->rxIndex >= _udp->rxLength)
    return 0;

  return static_cast<int>(_udp->rxLength - _udp->rxIndex);
}

int LwipTransportBackend::read() {
  if (available() <= 0)
    return -1;

  return _udp->rx[_udp->rxIndex++];
}

int LwipTransportBackend::read(uint8_t *buffer, size_t size) {
  if (buffer == nullptr || size == 0 || available() <= 0)
    return 0;

  size_t bytesToRead = static_cast<size_t>(available());
  if (bytesToRead > size)
    bytesToRead = size;

  memcpy(buffer, &_udp->rx[_udp->rxIndex], bytesToRead);
  _udp->rxIndex += bytesToRead;
  return static_cast<int>(bytesToRead);
}

int LwipTransportBackend::peek() {
  if (available() <= 0)
    return -1;

  return _udp->rx[_udp->rxIndex];
}

void LwipTransportBackend::flush() {
  if (_udp == nullptr)
    return;

  _udp->rxIndex = _udp->rxLength;
}

IPAddress LwipTransportBackend::remoteIP() {
  if (_udp == nullptr)
    return IPAddress();

  return hostOrderAddressToIp(_udp->rxRemote.address);
}

uint16_t LwipTransportBackend::remotePort() {
  return _udp == nullptr ? 0 : _udp->rxRemote.port;
}

LwipTransportBackend::TcpHandle *LwipTransportBackend::asTcpHandle(void *handle) const {
  if (handle == _client)
    return _client;
  if (handle == _secure)
    return _secure;
  if (handle == _accepted)
    return _accepted;

  return nullptr;
}

void LwipTransportBackend::closeTcpHandle(TcpHandle *handle) {
  if (handle == nullptr)
    return;

  if (handle->pcb != nullptr) {
    tcp_pcb *pcb = handle->pcb;
    detachTcpCallbacks(pcb);
    if (tcp_close(pcb) != ERR_OK)
      tcp_abort(pcb);
  }
  handle->pcb = nullptr;
  handle->acquired = false;
  handle->connected = false;
  handle->connecting = false;
  resetTcpReceiveBuffer(handle);
}

size_t LwipTransportBackend::writeServerToAccepted(const uint8_t *buffer,
                                                size_t size) {
  return write(_accepted, buffer, size);
}
