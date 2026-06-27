#include "LwipPort.h"

#include <string.h>

#if SIMIO_ETHERNET_HAS_LWIP_CORE
#include <lwip/dhcp.h>
#include <lwip/init.h>
#include <lwip/ip4_addr.h>
#include <lwip/pbuf.h>
#include <lwip/timeouts.h>
#include <netif/etharp.h>
#include <netif/ethernet.h>
#endif

#if SIMIO_ETHERNET_HAS_LWIP_CORE
namespace {
struct netif globalLwipNetif;
bool globalLwipInitialized = false;
bool globalLwipNetifAdded = false;
} // namespace
#endif

EthernetLwipPort::EthernetLwipPort(EthernetNetif &netif) : _netif(&netif) {}

EthernetLwipPort::~EthernetLwipPort() { end(); }

bool EthernetLwipPort::begin(EthernetPacketAllocator &allocator) {
  if (_netif == nullptr)
    return false;

#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (!beginLwipNetif())
    return false;
#endif

  _netif->setPacketAllocator(allocator);
  _netif->setInputCallback(inputThunk, this);
  _netif->setLinkChangeCallback(linkThunk, this);
  _started = _netif->begin();
  if (!_started) {
    _netif->clearInputCallback();
    _netif->clearLinkChangeCallback();
    _netif->clearPacketAllocator();
#if SIMIO_ETHERNET_HAS_LWIP_CORE
    endLwipNetif();
#endif
  }

  return _started;
}

void EthernetLwipPort::end() {
  if (_netif == nullptr)
    return;

  if (_tcpBackend != nullptr) {
    if (_clientSocket.attached())
      _tcpBackend->releaseSocket(_clientSocket.handle());
    if (_secureClientSocket.attached())
      _tcpBackend->releaseSocket(_secureClientSocket.handle());
    if (_acceptedSocket.attached())
      _tcpBackend->releaseSocket(_acceptedSocket.handle());
  }
  _clientSocket.detach();
  _secureClientSocket.detach();
  _acceptedSocket.detach();
  if (_udpBackend != nullptr)
    _udpBackend->stop();

  _netif->clearInputCallback();
  _netif->clearLinkChangeCallback();
  _netif->clearPacketAllocator();
  _netif->end();
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  endLwipNetif();
#endif
  _started = false;
}

bool EthernetLwipPort::service() {
  if (!_started || _netif == nullptr)
    return false;

  const bool progressed = _netif->service();
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  sys_check_timeouts();
#endif
  return progressed;
}

void EthernetLwipPort::setInputCallback(InputCallback callback,
                                        void *context) {
  _inputCallback = callback;
  _inputContext = context;
}

void EthernetLwipPort::clearInputCallback() {
  _inputCallback = nullptr;
  _inputContext = nullptr;
}

void EthernetLwipPort::setLinkChangeCallback(LinkChangeCallback callback,
                                             void *context) {
  _linkChangeCallback = callback;
  _linkChangeContext = context;
}

void EthernetLwipPort::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeContext = nullptr;
}

void EthernetLwipPort::setTcpBackend(LwipTcpSocketBackend &backend) {
  clearTcpBackend();
  _tcpBackend = &backend;
}

void EthernetLwipPort::clearTcpBackend() {
  if (_tcpBackend != nullptr) {
    if (_clientSocket.attached())
      _tcpBackend->releaseSocket(_clientSocket.handle());
    if (_secureClientSocket.attached())
      _tcpBackend->releaseSocket(_secureClientSocket.handle());
    if (_acceptedSocket.attached())
      _tcpBackend->releaseSocket(_acceptedSocket.handle());
  }

  _clientSocket.detach();
  _secureClientSocket.detach();
  _acceptedSocket.detach();
  _tcpBackend = nullptr;
}

void EthernetLwipPort::setUdpBackend(LwipUdpBackend &backend) {
  clearUdpBackend();
  _udpBackend = &backend;
}

void EthernetLwipPort::clearUdpBackend() {
  if (_udpBackend != nullptr)
    _udpBackend->stop();

  _udpBackend = nullptr;
}

EthernetLwipErr EthernetLwipPort::output(const uint8_t *frame,
                                         uint16_t length) {
  if (!_started || _netif == nullptr)
    return EthernetLwipErrUse;

  return mapOutputResult(_netif->outputResult(frame, length));
}

bool EthernetLwipPort::carrierUp() const {
  return _started && _netif != nullptr && _netif->carrierUp();
}

EthernetSocket *EthernetLwipPort::acquireClientSocket() {
  if (!_started || _tcpBackend == nullptr || _clientSocket.attached())
    return nullptr;

  void *handle = _tcpBackend->acquireClientSocket();
  if (handle == nullptr)
    return nullptr;

  _clientSocket.attach(*_tcpBackend, handle);
  return &_clientSocket;
}

EthernetSocket *EthernetLwipPort::acquireSecureClientSocket() {
  if (!_started || _tcpBackend == nullptr || !_tcpBackend->tlsAvailable() ||
      _secureClientSocket.attached())
    return nullptr;

  void *handle = _tcpBackend->acquireSecureClientSocket();
  if (handle == nullptr)
    return nullptr;

  _secureClientSocket.attach(*_tcpBackend, handle);
  return &_secureClientSocket;
}

void EthernetLwipPort::releaseSocket(EthernetSocket *socket) {
  if (_tcpBackend == nullptr || socket == nullptr)
    return;

  if (socket == &_clientSocket && _clientSocket.attached()) {
    _tcpBackend->releaseSocket(_clientSocket.handle());
    _clientSocket.detach();
  } else if (socket == &_secureClientSocket && _secureClientSocket.attached()) {
    _tcpBackend->releaseSocket(_secureClientSocket.handle());
    _secureClientSocket.detach();
  } else if (socket == &_acceptedSocket && _acceptedSocket.attached()) {
    _tcpBackend->releaseSocket(_acceptedSocket.handle());
    _acceptedSocket.detach();
  }
}

bool EthernetLwipPort::tlsAvailable() const {
  return _started && _tcpBackend != nullptr && _tcpBackend->tlsAvailable();
}

bool EthernetLwipPort::beginServer(uint16_t port) {
  if (!_started || _tcpBackend == nullptr)
    return false;

  return _tcpBackend->beginServer(port);
}

void EthernetLwipPort::stopServer(uint16_t port) {
  if (_tcpBackend == nullptr)
    return;

  if (_acceptedSocket.attached()) {
    _tcpBackend->releaseSocket(_acceptedSocket.handle());
    _acceptedSocket.detach();
  }

  _tcpBackend->stopServer(port);
}

EthernetSocket *EthernetLwipPort::acceptClientSocket(uint16_t port) {
  if (!_started || _tcpBackend == nullptr || _acceptedSocket.attached())
    return nullptr;

  void *handle = _tcpBackend->acceptClientSocket(port);
  if (handle == nullptr)
    return nullptr;

  _acceptedSocket.attach(*_tcpBackend, handle);
  return &_acceptedSocket;
}

size_t EthernetLwipPort::writeServer(uint16_t port, uint8_t value) {
  if (!_started || _tcpBackend == nullptr)
    return 0;

  return _tcpBackend->writeServer(port, value);
}

size_t EthernetLwipPort::writeServer(uint16_t port, const uint8_t *buffer,
                                     size_t size) {
  if (!_started || _tcpBackend == nullptr || buffer == nullptr || size == 0)
    return 0;

  return _tcpBackend->writeServer(port, buffer, size);
}

uint8_t EthernetLwipPort::beginUdp(uint16_t port) {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->begin(port);
}

uint8_t EthernetLwipPort::beginUdpMulticast(IPAddress ip, uint16_t port) {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->beginMulticast(ip, port);
}

void EthernetLwipPort::stopUdp() {
  if (_udpBackend != nullptr)
    _udpBackend->stop();
}

int EthernetLwipPort::beginUdpPacket(IPAddress ip, uint16_t port) {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->beginPacket(ip, port);
}

int EthernetLwipPort::beginUdpPacket(const char *host, uint16_t port) {
  if (!_started || _udpBackend == nullptr || host == nullptr || host[0] == '\0')
    return 0;

  return _udpBackend->beginPacket(host, port);
}

int EthernetLwipPort::endUdpPacket() {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->endPacket();
}

size_t EthernetLwipPort::writeUdp(uint8_t value) {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->write(value);
}

size_t EthernetLwipPort::writeUdp(const uint8_t *buffer, size_t size) {
  if (!_started || _udpBackend == nullptr || buffer == nullptr || size == 0)
    return 0;

  return _udpBackend->write(buffer, size);
}

int EthernetLwipPort::parseUdpPacket() {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->parsePacket();
}

int EthernetLwipPort::availableUdp() {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->available();
}

int EthernetLwipPort::readUdp() {
  if (!_started || _udpBackend == nullptr)
    return -1;

  return _udpBackend->read();
}

int EthernetLwipPort::readUdp(uint8_t *buffer, size_t size) {
  if (!_started || _udpBackend == nullptr || buffer == nullptr || size == 0)
    return 0;

  return _udpBackend->read(buffer, size);
}

int EthernetLwipPort::peekUdp() {
  if (!_started || _udpBackend == nullptr)
    return -1;

  return _udpBackend->peek();
}

void EthernetLwipPort::flushUdp() {
  if (_started && _udpBackend != nullptr)
    _udpBackend->flush();
}

IPAddress EthernetLwipPort::remoteUdpIP() {
  if (!_started || _udpBackend == nullptr)
    return IPAddress();

  return _udpBackend->remoteIP();
}

uint16_t EthernetLwipPort::remoteUdpPort() {
  if (!_started || _udpBackend == nullptr)
    return 0;

  return _udpBackend->remotePort();
}

EthernetLwipErr
EthernetLwipPort::mapOutputResult(EthernetNetifOutputResult result) {
  switch (result) {
  case EthernetNetifOutputSent:
    return EthernetLwipErrOk;
  case EthernetNetifOutputInvalidFrame:
    return EthernetLwipErrVal;
  case EthernetNetifOutputCarrierDown:
    return EthernetLwipErrUse;
  case EthernetNetifOutputDriverBusy:
    return EthernetLwipErrWouldBlock;
  case EthernetNetifOutputNotStarted:
  default:
    return EthernetLwipErrUse;
  }
}

bool EthernetLwipPort::handleInput(EthernetPacket *packet) {
  if (_inputCallback == nullptr) {
#if SIMIO_ETHERNET_HAS_LWIP_CORE
    return inputPacketToLwip(packet);
#else
    return false;
#endif
  }

  return _inputCallback(packet, _inputContext) == EthernetLwipErrOk;
}

void EthernetLwipPort::handleLinkChange(bool carrierUp,
                                        EthernetFrameLinkStatus status,
                                        EthernetFrameLinkSpeed speed,
                                        EthernetFrameDuplex duplex) {
  if (_linkChangeCallback != nullptr)
    _linkChangeCallback(carrierUp, status, speed, duplex, _linkChangeContext);

#if SIMIO_ETHERNET_HAS_LWIP_CORE
  if (globalLwipNetifAdded && globalLwipNetif.state == this) {
    if (carrierUp)
      netif_set_link_up(&globalLwipNetif);
    else
      netif_set_link_down(&globalLwipNetif);
  }
#endif
}

#if SIMIO_ETHERNET_HAS_LWIP_CORE
bool EthernetLwipPort::beginLwipNetif() {
  if (!globalLwipInitialized) {
    lwip_init();
    globalLwipInitialized = true;
  }

  if (globalLwipNetifAdded) {
    globalLwipNetif.state = this;
    return true;
  }

  ip4_addr_t ipaddr;
  ip4_addr_t netmask;
  ip4_addr_t gateway;
  ip4_addr_set_zero(&ipaddr);
  ip4_addr_set_zero(&netmask);
  ip4_addr_set_zero(&gateway);

  memset(&globalLwipNetif, 0, sizeof(globalLwipNetif));
  if (netif_add(&globalLwipNetif, &ipaddr, &netmask, &gateway, this,
                lwipNetifInit, ethernet_input) == nullptr)
    return false;

  netif_set_default(&globalLwipNetif);
  netif_set_up(&globalLwipNetif);
  if (_netif != nullptr && _netif->carrierUp())
    netif_set_link_up(&globalLwipNetif);
  else
    netif_set_link_down(&globalLwipNetif);

  globalLwipNetifAdded = true;
  return true;
}

void EthernetLwipPort::endLwipNetif() {
  if (!globalLwipNetifAdded || globalLwipNetif.state != this)
    return;

  netif_set_link_down(&globalLwipNetif);
  globalLwipNetif.state = nullptr;
}

bool EthernetLwipPort::inputPacketToLwip(EthernetPacket *packet) {
  if (!globalLwipNetifAdded || globalLwipNetif.state != this ||
      packet == nullptr || packet->data() == nullptr || packet->length() == 0)
    return false;

  struct pbuf *p = pbuf_alloc(PBUF_RAW, packet->length(), PBUF_POOL);
  if (p == nullptr)
    return false;

  const err_t takeResult = pbuf_take(p, packet->data(), packet->length());
  packet->release();
  if (takeResult != ERR_OK) {
    pbuf_free(p);
    return true;
  }

  if (globalLwipNetif.input(p, &globalLwipNetif) != ERR_OK)
    pbuf_free(p);

  return true;
}

EthernetLwipErr EthernetLwipPort::outputPbuf(struct pbuf *p) {
  if (p == nullptr || p->tot_len == 0 || p->tot_len > sizeof(_outputBuffer))
    return EthernetLwipErrVal;

  pbuf_copy_partial(p, _outputBuffer, p->tot_len, 0);
  return output(_outputBuffer, p->tot_len);
}

err_t EthernetLwipPort::lwipNetifInit(struct netif *netif) {
  if (netif == nullptr)
    return ERR_ARG;

  netif->name[0] = 's';
  netif->name[1] = 'e';
  netif->output = etharp_output;
  netif->linkoutput = lwipLinkOutput;
  netif->mtu = 1500;
  netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                 NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP;
  netif->hwaddr_len = ETH_HWADDR_LEN;
  netif->hwaddr[0] = 0x02;
  netif->hwaddr[1] = 0x00;
  netif->hwaddr[2] = 0x00;
  netif->hwaddr[3] = 0x00;
  netif->hwaddr[4] = 0x00;
  netif->hwaddr[5] = 0x01;
  return ERR_OK;
}

err_t EthernetLwipPort::lwipLinkOutput(struct netif *netif, struct pbuf *p) {
  if (netif == nullptr || netif->state == nullptr)
    return ERR_ARG;

  EthernetLwipPort *port = static_cast<EthernetLwipPort *>(netif->state);
  switch (port->outputPbuf(p)) {
  case EthernetLwipErrOk:
    return ERR_OK;
  case EthernetLwipErrMem:
    return ERR_MEM;
  case EthernetLwipErrVal:
    return ERR_VAL;
  case EthernetLwipErrWouldBlock:
    return ERR_WOULDBLOCK;
  case EthernetLwipErrUse:
  default:
    return ERR_USE;
  }
}
#endif

bool EthernetLwipPort::inputThunk(EthernetPacket *packet, void *context) {
  if (context == nullptr)
    return false;

  return static_cast<EthernetLwipPort *>(context)->handleInput(packet);
}

void EthernetLwipPort::linkThunk(bool carrierUp, EthernetFrameLinkStatus status,
                                 EthernetFrameLinkSpeed speed,
                                 EthernetFrameDuplex duplex, void *context) {
  if (context != nullptr)
    static_cast<EthernetLwipPort *>(context)->handleLinkChange(
        carrierUp, status, speed, duplex);
}
