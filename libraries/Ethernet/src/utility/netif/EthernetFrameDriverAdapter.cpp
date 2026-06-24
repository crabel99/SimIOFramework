#include "EthernetFrameDriverAdapter.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
namespace {
EthernetFrameLinkStatus convertLinkStatus(EthernetLinkStatus status) {
  if (status == LinkON)
    return EthernetFrameLinkOn;

  if (status == LinkOFF)
    return EthernetFrameLinkOff;

  return EthernetFrameLinkUnknown;
}

EthernetFrameLinkSpeed convertLinkSpeed(EthernetPhyLinkSpeed speed) {
  if (speed == EthernetPhySpeed10M)
    return EthernetFrameSpeed10M;

  if (speed == EthernetPhySpeed100M)
    return EthernetFrameSpeed100M;

  return EthernetFrameSpeedUnknown;
}

EthernetFrameDuplex convertDuplex(EthernetPhyDuplex duplex) {
  if (duplex == EthernetPhyHalfDuplex)
    return EthernetFrameHalfDuplex;

  if (duplex == EthernetPhyFullDuplex)
    return EthernetFrameFullDuplex;

  return EthernetFrameDuplexUnknown;
}

} // namespace

EthernetClassFrameDriver::EthernetClassFrameDriver(EthernetClass &ethernet)
    : _ethernet(&ethernet) {}

EthernetFrameLinkStatus EthernetClassFrameDriver::linkStatus() const {
  return convertLinkStatus(_ethernet->linkStatus());
}

EthernetFrameLinkSpeed EthernetClassFrameDriver::linkSpeed() const {
  return convertLinkSpeed(_ethernet->linkSpeed());
}

EthernetFrameDuplex EthernetClassFrameDriver::duplex() const {
  return convertDuplex(_ethernet->duplex());
}

bool EthernetClassFrameDriver::carrierUp() const {
  return _ethernet->carrierUp();
}

void EthernetClassFrameDriver::setFrameReceiveCallback(
    FrameReceiveCallback callback, void *context) {
  _ethernet->setFrameReceiveCallback(callback, context);
}

void EthernetClassFrameDriver::clearFrameReceiveCallback() {
  _ethernet->clearFrameReceiveCallback();
}

void EthernetClassFrameDriver::setLinkChangeCallback(
    LinkChangeCallback callback, void *context) {
  _linkChangeCallback = callback;
  _linkChangeContext = context;
  _ethernet->setLinkChangeCallback(EthernetClassFrameDriver::handleLinkChange,
                                   this);
}

void EthernetClassFrameDriver::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeContext = nullptr;
  _ethernet->clearLinkChangeCallback();
}

void EthernetClassFrameDriver::setCarrierCallback(CarrierCallback callback,
                                                  void *context) {
  _ethernet->setCarrierCallback(callback, context);
}

void EthernetClassFrameDriver::clearCarrierCallback() {
  _ethernet->clearCarrierCallback();
}

bool EthernetClassFrameDriver::frameAvailable(uint16_t *length) {
  return _ethernet->frameAvailable(length);
}

bool EthernetClassFrameDriver::readFrame(uint8_t *buffer, uint16_t capacity,
                                         uint16_t *length) {
  return _ethernet->readFrame(buffer, capacity, length);
}

bool EthernetClassFrameDriver::writeFrame(const uint8_t *buffer,
                                          uint16_t length) {
  return _ethernet->writeFrame(buffer, length);
}

bool EthernetClassFrameDriver::service() { return _ethernet->service(); }

void EthernetClassFrameDriver::handleLinkChange(EthernetLinkStatus status,
                                                EthernetPhyLinkSpeed speed,
                                                EthernetPhyDuplex duplex,
                                                void *context) {
  EthernetClassFrameDriver *driver =
      static_cast<EthernetClassFrameDriver *>(context);
  if (driver == nullptr || driver->_linkChangeCallback == nullptr)
    return;

  driver->_linkChangeCallback(convertLinkStatus(status),
                              convertLinkSpeed(speed), convertDuplex(duplex),
                              driver->_linkChangeContext);
}
#endif /* ETHERNET_HARDWARE_AVAILABLE */
