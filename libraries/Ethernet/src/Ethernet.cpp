#include "Ethernet.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <string.h>

namespace {
EthernetPhy defaultPhy;
constexpr uint8_t kRxDescriptorCount = 4;
constexpr uint8_t kTxDescriptorCount = 1;
constexpr uint16_t kFrameBufferSize = 1536;

alignas(4) gmac::Descriptor rxDescriptors[kRxDescriptorCount];
alignas(4) gmac::Descriptor txDescriptors[kTxDescriptorCount];
alignas(4) uint8_t rxBuffers[kRxDescriptorCount][kFrameBufferSize];
alignas(4) uint8_t txBuffers[kTxDescriptorCount][kFrameBufferSize];
bool txBufferInUse = false;

bool isUsableMac(const uint8_t mac[6]) {
  if (mac == nullptr)
    return false;

  bool anySet = false;
  bool allOnes = true;

  for (uint8_t i = 0; i < 6; ++i) {
    anySet = anySet || mac[i] != 0;
    allOnes = allOnes && mac[i] == 0xFFu;
  }

  return anySet && !allOnes && (mac[0] & 0x01u) == 0;
}

bool toGmacSpeed(EthernetPhyLinkSpeed phySpeed, gmac::LinkSpeed *gmacSpeed) {
  if (gmacSpeed == nullptr)
    return false;

  switch (phySpeed) {
  case EthernetPhySpeed10M:
    *gmacSpeed = gmac::LinkSpeed10M;
    return true;
  case EthernetPhySpeed100M:
    *gmacSpeed = gmac::LinkSpeed100M;
    return true;
  default:
    return false;
  }
}

bool toGmacDuplex(EthernetPhyDuplex phyDuplex, bool *fullDuplex) {
  if (fullDuplex == nullptr)
    return false;

  switch (phyDuplex) {
  case EthernetPhyHalfDuplex:
    *fullDuplex = false;
    return true;
  case EthernetPhyFullDuplex:
    *fullDuplex = true;
    return true;
  default:
    return false;
  }
}

bool configureEthernetFrameBuffers() {
  txBufferInUse = false;
  return gmac::configureFrameBuffers(&rxDescriptors[0], kRxDescriptorCount,
                                     &rxBuffers[0][0], kFrameBufferSize,
                                     &txDescriptors[0], kTxDescriptorCount);
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
  if (!_begun || _phy == nullptr)
    return Unknown;

  return _phy->linkUp() ? LinkON : LinkOFF;
}

void EthernetClass::setPhy(EthernetPhy &phy) {
  _phy = &phy;
  _begun = false;
}

EthernetPhy *EthernetClass::phy() const { return _phy; }

bool EthernetClass::setMacAddress(const uint8_t mac[6]) {
  if (!isUsableMac(mac))
    return false;

  for (uint8_t i = 0; i < 6; ++i)
    _mac[i] = mac[i];

  _hasMac = true;
  return true;
}

void EthernetClass::macAddress(uint8_t mac[6]) const {
  if (mac == nullptr)
    return;

  for (uint8_t i = 0; i < 6; ++i)
    mac[i] = _mac[i];
}

bool EthernetClass::updateLinkConfiguration() {
  if (_phy == nullptr)
    return false;

  if (!_phy->linkUp())
    return true;

  gmac::LinkSpeed speed = gmac::LinkSpeed10M;
  bool fullDuplex = false;

  if (!toGmacSpeed(_phy->linkSpeed(), &speed) ||
      !toGmacDuplex(_phy->duplex(), &fullDuplex))
    return false;

  gmac::configureLink(speed, fullDuplex);
  return true;
}

void EthernetClass::setPromiscuousMode(bool enabled) {
  gmac::setPromiscuousMode(enabled);
}

void EthernetClass::setBroadcastReception(bool enabled) {
  gmac::setBroadcastReception(enabled);
}

void EthernetClass::setHashFilter(uint32_t bottom, uint32_t top,
                                  bool multicastEnabled,
                                  bool unicastEnabled) {
  gmac::setHashFilter(bottom, top, multicastEnabled, unicastEnabled);
}

void EthernetClass::clearHashFilter() { gmac::clearHashFilter(); }

gmac::Status EthernetClass::status() const { return gmac::status(); }

void EthernetClass::clearStatus(uint32_t receiveMask, uint32_t transmitMask) {
  gmac::clearStatus(receiveMask, transmitMask);
}

gmac::Statistics EthernetClass::statistics() const { return gmac::statistics(); }

void EthernetClass::clearStatistics() { gmac::clearStatistics(); }

bool EthernetClass::frameAvailable(uint16_t *length) {
  if (!_begun)
    return false;

  uint16_t frameLength = 0;
  if (!gmac::receivedFrameSize(&frameLength))
    return false;

  if (length != nullptr)
    *length = frameLength;

  return true;
}

bool EthernetClass::readFrame(uint8_t *buffer, uint16_t capacity,
                              uint16_t *length) {
  if (!_begun)
    return false;

  return gmac::readReceivedFrame(buffer, capacity, length);
}

bool EthernetClass::writeFrame(const uint8_t *buffer, uint16_t length) {
  if (!_begun || buffer == nullptr || length == 0 || length > kFrameBufferSize)
    return false;

  if (txBufferInUse && gmac::reclaimTransmitDescriptors() > 0)
    txBufferInUse = false;

  if (txBufferInUse)
    return false;

  memcpy(&txBuffers[0][0], buffer, length);
  if (!gmac::queueTransmitBuffer(&txBuffers[0][0], length))
    return false;

  txBufferInUse = true;
  return true;
}

bool EthernetClass::discardFrame() {
  if (!_begun)
    return false;

  return gmac::discardReceivedFrame();
}

int EthernetClass::begin() {
  _begun = false;

  if (hardwareStatus() == EthernetNoHardware || !_hasMac || _phy == nullptr ||
      !gmac::beginManagement())
    return 0;

  gmac::setMacAddress(_mac);
  if (!_phy->begin() || !_phy->configure() || !updateLinkConfiguration() ||
      !configureEthernetFrameBuffers())
    return 0;

  gmac::enableFrameIo();
  _begun = true;
  return 1;
}

int EthernetClass::begin(const uint8_t *mac) {
  if (!setMacAddress(mac))
    return 0;

  return begin();
}
#endif /* ETHERNET_HARDWARE_AVAILABLE */
