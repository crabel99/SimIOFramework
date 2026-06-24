#pragma once

#include <utility/netif/EthernetFrameDriver.h>

#include <stdint.h>

class EthernetNetif {
public:
  using InputCallback = bool (*)(const uint8_t *frame, uint16_t length,
                                 void *context);
  using LinkChangeCallback = void (*)(bool carrierUp,
                                      EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);

  explicit EthernetNetif(EthernetFrameDriver &driver);

  bool begin();
  void end();
  bool service();

  void setInputCallback(InputCallback callback, void *context = nullptr);
  void clearInputCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();

  bool carrierUp() const { return _carrierUp; }
  EthernetFrameLinkStatus linkStatus() const { return _linkStatus; }
  EthernetFrameLinkSpeed linkSpeed() const { return _linkSpeed; }
  EthernetFrameDuplex duplex() const { return _duplex; }

  bool output(const uint8_t *frame, uint16_t length);

private:
  EthernetFrameDriver *_driver;
  InputCallback _inputCallback = nullptr;
  void *_inputContext = nullptr;
  LinkChangeCallback _linkChangeCallback = nullptr;
  void *_linkChangeContext = nullptr;
  bool _started = false;
  bool _carrierUp = false;
  EthernetFrameLinkStatus _linkStatus = EthernetFrameLinkUnknown;
  EthernetFrameLinkSpeed _linkSpeed = EthernetFrameSpeedUnknown;
  EthernetFrameDuplex _duplex = EthernetFrameDuplexUnknown;

  void refreshLinkState();
  void notifyLinkChange();
  void handleFrame(const uint8_t *frame, uint16_t length);
  void handleLinkChange(EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
  void handleCarrierChange(bool carrierUp);

  static void frameThunk(const uint8_t *frame, uint16_t length,
                         void *context);
  static void linkThunk(EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
  static void carrierThunk(bool carrierUp, void *context);
};

inline EthernetNetif::EthernetNetif(EthernetFrameDriver &driver)
    : _driver(&driver) {}

inline bool EthernetNetif::begin() {
  if (_driver == nullptr)
    return false;

  refreshLinkState();
  _driver->setFrameReceiveCallback(frameThunk, this);
  _driver->setLinkChangeCallback(linkThunk, this);
  _driver->setCarrierCallback(carrierThunk, this);
  _started = true;
  return true;
}

inline void EthernetNetif::end() {
  if (_driver != nullptr) {
    _driver->clearFrameReceiveCallback();
    _driver->clearLinkChangeCallback();
    _driver->clearCarrierCallback();
  }

  _started = false;
}

inline bool EthernetNetif::service() {
  if (!_started || _driver == nullptr)
    return false;

  return _driver->service();
}

inline void EthernetNetif::setInputCallback(InputCallback callback,
                                            void *context) {
  _inputCallback = callback;
  _inputContext = context;
}

inline void EthernetNetif::clearInputCallback() {
  _inputCallback = nullptr;
  _inputContext = nullptr;
}

inline void EthernetNetif::setLinkChangeCallback(LinkChangeCallback callback,
                                                 void *context) {
  _linkChangeCallback = callback;
  _linkChangeContext = context;
}

inline void EthernetNetif::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeContext = nullptr;
}

inline bool EthernetNetif::output(const uint8_t *frame, uint16_t length) {
  if (!_started || !_carrierUp || _driver == nullptr || frame == nullptr ||
      length == 0)
    return false;

  return _driver->writeFrame(frame, length);
}

inline void EthernetNetif::refreshLinkState() {
  _linkStatus = _driver->linkStatus();
  _linkSpeed = _driver->linkSpeed();
  _duplex = _driver->duplex();
  _carrierUp = _driver->carrierUp();
}

inline void EthernetNetif::notifyLinkChange() {
  if (_linkChangeCallback != nullptr)
    _linkChangeCallback(_carrierUp, _linkStatus, _linkSpeed, _duplex,
                        _linkChangeContext);
}

inline void EthernetNetif::handleFrame(const uint8_t *frame, uint16_t length) {
  if (_inputCallback != nullptr && frame != nullptr && length != 0)
    _inputCallback(frame, length, _inputContext);
}

inline void EthernetNetif::handleLinkChange(EthernetFrameLinkStatus status,
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

inline void EthernetNetif::handleCarrierChange(bool carrierUp) {
  _carrierUp = carrierUp;
}

inline void EthernetNetif::frameThunk(const uint8_t *frame, uint16_t length,
                                      void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleFrame(frame, length);
}

inline void EthernetNetif::linkThunk(EthernetFrameLinkStatus status,
                                     EthernetFrameLinkSpeed speed,
                                     EthernetFrameDuplex duplex,
                                     void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleLinkChange(status, speed,
                                                            duplex);
}

inline void EthernetNetif::carrierThunk(bool carrierUp, void *context) {
  if (context != nullptr)
    static_cast<EthernetNetif *>(context)->handleCarrierChange(carrierUp);
}
