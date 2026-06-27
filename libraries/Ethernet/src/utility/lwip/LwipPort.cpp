#include "LwipPort.h"

EthernetLwipPort::EthernetLwipPort(EthernetNetif &netif) : _netif(&netif) {}

bool EthernetLwipPort::begin(EthernetPacketAllocator &allocator) {
  if (_netif == nullptr)
    return false;

  _netif->setPacketAllocator(allocator);
  _netif->setInputCallback(inputThunk, this);
  _netif->setLinkChangeCallback(linkThunk, this);
  _started = _netif->begin();
  if (!_started) {
    _netif->clearInputCallback();
    _netif->clearLinkChangeCallback();
    _netif->clearPacketAllocator();
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

  _netif->clearInputCallback();
  _netif->clearLinkChangeCallback();
  _netif->clearPacketAllocator();
  _netif->end();
  _started = false;
}

bool EthernetLwipPort::service() {
  if (!_started || _netif == nullptr)
    return false;

  return _netif->service();
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

uint8_t EthernetLwipPort::beginUdp(uint16_t) { return 0; }

uint8_t EthernetLwipPort::beginUdpMulticast(IPAddress, uint16_t) { return 0; }

void EthernetLwipPort::stopUdp() {}

int EthernetLwipPort::beginUdpPacket(IPAddress, uint16_t) { return 0; }

int EthernetLwipPort::beginUdpPacket(const char *, uint16_t) { return 0; }

int EthernetLwipPort::endUdpPacket() { return 0; }

size_t EthernetLwipPort::writeUdp(uint8_t) { return 0; }

size_t EthernetLwipPort::writeUdp(const uint8_t *, size_t) { return 0; }

int EthernetLwipPort::parseUdpPacket() { return 0; }

int EthernetLwipPort::availableUdp() { return 0; }

int EthernetLwipPort::readUdp() { return -1; }

int EthernetLwipPort::readUdp(uint8_t *, size_t) { return 0; }

int EthernetLwipPort::peekUdp() { return -1; }

void EthernetLwipPort::flushUdp() {}

IPAddress EthernetLwipPort::remoteUdpIP() { return IPAddress(); }

uint16_t EthernetLwipPort::remoteUdpPort() { return 0; }

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
  if (_inputCallback == nullptr)
    return false;

  return _inputCallback(packet, _inputContext) == EthernetLwipErrOk;
}

void EthernetLwipPort::handleLinkChange(bool carrierUp,
                                        EthernetFrameLinkStatus status,
                                        EthernetFrameLinkSpeed speed,
                                        EthernetFrameDuplex duplex) {
  if (_linkChangeCallback != nullptr)
    _linkChangeCallback(carrierUp, status, speed, duplex, _linkChangeContext);
}

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
