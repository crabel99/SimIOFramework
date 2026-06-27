#include "Netif.h"

EthernetNetif::EthernetNetif(EthernetFrameDriver &driver) : _driver(&driver) {}

bool EthernetNetif::begin() {
  if (_driver == nullptr)
    return false;

  refreshLinkState();
  _driver->setFrameReceiveCallback(frameThunk, this);
  _driver->setLinkChangeCallback(linkThunk, this);
  _driver->setCarrierCallback(carrierThunk, this);
  _started = true;
  return true;
}

void EthernetNetif::end() {
  if (_driver != nullptr) {
    _driver->clearFrameReceiveCallback();
    _driver->clearLinkChangeCallback();
    _driver->clearCarrierCallback();
  }

  _started = false;
}

bool EthernetNetif::service() {
  if (!_started || _driver == nullptr)
    return false;

  return _driver->service();
}

void EthernetNetif::setPacketAllocator(EthernetPacketAllocator &allocator) {
  _packetAllocator = &allocator;
}

void EthernetNetif::clearPacketAllocator() { _packetAllocator = nullptr; }

void EthernetNetif::setInputCallback(InputCallback callback, void *context) {
  _inputCallback = callback;
  _inputContext = context;
}

void EthernetNetif::clearInputCallback() {
  _inputCallback = nullptr;
  _inputContext = nullptr;
}

void EthernetNetif::setLinkChangeCallback(LinkChangeCallback callback,
                                          void *context) {
  _linkChangeCallback = callback;
  _linkChangeContext = context;
}

void EthernetNetif::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeContext = nullptr;
}

EthernetNetifOutputResult EthernetNetif::outputResult(const uint8_t *frame,
                                                      uint16_t length) {
  if (!_started || _driver == nullptr)
    return EthernetNetifOutputNotStarted;

  if (frame == nullptr || length == 0)
    return EthernetNetifOutputInvalidFrame;

  if (!_carrierUp)
    return EthernetNetifOutputCarrierDown;

  if (!_driver->writeFrame(frame, length))
    return EthernetNetifOutputDriverBusy;

  return EthernetNetifOutputSent;
}

bool EthernetNetif::output(const uint8_t *frame, uint16_t length) {
  return outputResult(frame, length) == EthernetNetifOutputSent;
}

void EthernetNetif::refreshLinkState() {
  _linkStatus = _driver->linkStatus();
  _linkSpeed = _driver->linkSpeed();
  _duplex = _driver->duplex();
  _carrierUp = _driver->carrierUp();
}

void EthernetNetif::notifyLinkChange() {
  if (_linkChangeCallback != nullptr)
    _linkChangeCallback(_carrierUp, _linkStatus, _linkSpeed, _duplex,
                        _linkChangeContext);
}

void EthernetNetif::handleFrame(const uint8_t *frame, uint16_t length) {
  if (_packetAllocator == nullptr || _inputCallback == nullptr ||
      frame == nullptr || length == 0)
    return;

  EthernetPacket *packet = _packetAllocator->allocateCopy(frame, length);
  if (packet == nullptr)
    return;

  if (!_inputCallback(packet, _inputContext))
    packet->release();
}

void EthernetNetif::handleLinkChange(EthernetFrameLinkStatus status,
                                     EthernetFrameLinkSpeed speed,
                                     EthernetFrameDuplex duplex) {
  const bool oldCarrier = _carrierUp;
  const EthernetFrameLinkStatus oldStatus = _linkStatus;
  const EthernetFrameLinkSpeed oldSpeed = _linkSpeed;
  const EthernetFrameDuplex oldDuplex = _duplex;

  _linkStatus = status;
  _linkSpeed = speed;
  _duplex = duplex;
  _carrierUp = _driver != nullptr ? _driver->carrierUp() : false;

  if (oldCarrier != _carrierUp || oldStatus != _linkStatus ||
      oldSpeed != _linkSpeed || oldDuplex != _duplex)
    notifyLinkChange();
}

void EthernetNetif::handleCarrierChange(bool carrierUp) {
  const bool oldCarrier = _carrierUp;
  const EthernetFrameLinkStatus oldStatus = _linkStatus;
  const EthernetFrameLinkSpeed oldSpeed = _linkSpeed;
  const EthernetFrameDuplex oldDuplex = _duplex;

  _carrierUp = carrierUp;
  if (_driver != nullptr) {
    _linkStatus = _driver->linkStatus();
    _linkSpeed = _driver->linkSpeed();
    _duplex = _driver->duplex();
  }

  if (oldCarrier == _carrierUp && oldStatus == _linkStatus &&
      oldSpeed == _linkSpeed && oldDuplex == _duplex)
    return;

  notifyLinkChange();
}

void EthernetNetif::frameThunk(const uint8_t *frame, uint16_t length,
                               void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleFrame(frame, length);
}

void EthernetNetif::linkThunk(EthernetFrameLinkStatus status,
                              EthernetFrameLinkSpeed speed,
                              EthernetFrameDuplex duplex, void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleLinkChange(status, speed,
                                                            duplex);
}

void EthernetNetif::carrierThunk(bool carrierUp, void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleCarrierChange(carrierUp);
}
