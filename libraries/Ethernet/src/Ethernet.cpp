#include "Ethernet.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE

namespace {
EthernetPhy defaultPhy;

bool isUsableMac(const uint8_t mac[6]) {
  if (mac == nullptr) {
    return false;
  }

  bool anySet = false;
  bool allOnes = true;

  for (uint8_t i = 0; i < 6; ++i) {
    anySet = anySet || mac[i] != 0;
    allOnes = allOnes && mac[i] == 0xFFu;
  }

  return anySet && !allOnes && (mac[0] & 0x01u) == 0;
}
} // namespace

EthernetClass Ethernet;

EthernetClass::EthernetClass()
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phy(&defaultPhy) {}

EthernetClass::EthernetClass(const uint8_t mac[6])
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phy(&defaultPhy) {
  setMacAddress(mac);
}

EthernetClass::EthernetClass(EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false), _phy(&phy) {}

EthernetClass::EthernetClass(const uint8_t mac[6], EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false), _phy(&phy) {
  setMacAddress(mac);
}

EthernetHardwareStatus EthernetClass::hardwareStatus() const {
  return gmac::available() ? EthernetGmac : EthernetNoHardware;
}

EthernetLinkStatus EthernetClass::linkStatus() const {
  if (!_begun || _phy == nullptr) {
    return Unknown;
  }

  return _phy->linkUp() ? LinkON : LinkOFF;
}

void EthernetClass::setPhy(EthernetPhy &phy) {
  _phy = &phy;
  _begun = false;
}

EthernetPhy *EthernetClass::phy() const { return _phy; }

bool EthernetClass::setMacAddress(const uint8_t mac[6]) {
  if (!isUsableMac(mac)) {
    return false;
  }

  for (uint8_t i = 0; i < 6; ++i) {
    _mac[i] = mac[i];
  }

  _hasMac = true;
  return true;
}

void EthernetClass::macAddress(uint8_t mac[6]) const {
  if (mac == nullptr) {
    return;
  }

  for (uint8_t i = 0; i < 6; ++i) {
    mac[i] = _mac[i];
  }
}

int EthernetClass::begin() {
  _begun = false;

  if (hardwareStatus() == EthernetNoHardware) {
    return 0;
  }

  if (!_hasMac) {
    return 0;
  }

  if (_phy == nullptr) {
    return 0;
  }

  if (!gmac::beginManagement()) {
    return 0;
  }

  gmac::setMacAddress(_mac);
  if (!_phy->begin() || !_phy->configure()) {
    return 0;
  }

  _begun = true;
  return 1;
}

int EthernetClass::begin(const uint8_t *mac) {
  if (!setMacAddress(mac)) {
    return 0;
  }

  return begin();
}
#endif /* ETHERNET_HARDWARE_AVAILABLE */
