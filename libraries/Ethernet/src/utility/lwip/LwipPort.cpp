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

EthernetLwipErr EthernetLwipPort::output(const uint8_t *frame,
                                         uint16_t length) {
  if (!_started || _netif == nullptr)
    return EthernetLwipErrUse;

  return mapOutputResult(_netif->outputResult(frame, length));
}

bool EthernetLwipPort::carrierUp() const {
  return _started && _netif != nullptr && _netif->carrierUp();
}

EthernetSocket *EthernetLwipPort::acquireClientSocket() { return nullptr; }

EthernetSocket *EthernetLwipPort::acquireSecureClientSocket() {
  return nullptr;
}

void EthernetLwipPort::releaseSocket(EthernetSocket *) {}

bool EthernetLwipPort::tlsAvailable() const { return false; }

bool EthernetLwipPort::beginServer(uint16_t) { return false; }

void EthernetLwipPort::stopServer(uint16_t) {}

EthernetSocket *EthernetLwipPort::acceptClientSocket(uint16_t) {
  return nullptr;
}

size_t EthernetLwipPort::writeServer(uint16_t, uint8_t) { return 0; }

size_t EthernetLwipPort::writeServer(uint16_t, const uint8_t *, size_t) {
  return 0;
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
