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
alignas(4) uint8_t rxDrainBuffer[kFrameBufferSize];
alignas(4) uint8_t rxQueueBuffers[kRxDescriptorCount][kFrameBufferSize];
uint16_t rxQueueLengths[kRxDescriptorCount];
uint8_t rxQueueReadIndex = 0;
uint8_t rxQueueWriteIndex = 0;
uint8_t rxQueueCount = 0;
bool txBufferInUse = false;

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
}

uint8_t nextQueueIndex(uint8_t index) {
  ++index;
  if (index >= kRxDescriptorCount)
    return 0;

  return index;
}

void clearReceiveQueue() {
  const uint32_t primask = enterCritical();
  rxQueueReadIndex = 0;
  rxQueueWriteIndex = 0;
  rxQueueCount = 0;
  exitCritical(primask);
}

bool receiveQueueFull() {
  const uint32_t primask = enterCritical();
  const bool full = rxQueueCount >= kRxDescriptorCount;
  exitCritical(primask);
  return full;
}

bool queueReceivedFrame(const uint8_t *frame, uint16_t length) {
  if (frame == nullptr || length == 0 || length > kFrameBufferSize)
    return false;

  const uint32_t primask = enterCritical();
  const bool full = rxQueueCount >= kRxDescriptorCount;
  const uint8_t index = rxQueueWriteIndex;
  exitCritical(primask);

  if (full)
    return false;

  memcpy(&rxQueueBuffers[index][0], frame, length);

  const uint32_t publishPrimask = enterCritical();
  rxQueueLengths[index] = length;
  rxQueueWriteIndex = nextQueueIndex(rxQueueWriteIndex);
  ++rxQueueCount;
  exitCritical(publishPrimask);
  return true;
}

bool popReceivedFrame(uint8_t *buffer, uint16_t capacity, uint16_t *length) {
  if (buffer == nullptr || length == nullptr)
    return false;

  const uint32_t primask = enterCritical();
  if (rxQueueCount == 0) {
    exitCritical(primask);
    return false;
  }

  const uint8_t index = rxQueueReadIndex;
  const uint16_t queuedLength = rxQueueLengths[index];
  if (capacity < queuedLength) {
    *length = queuedLength;
    exitCritical(primask);
    return false;
  }

  memcpy(buffer, &rxQueueBuffers[index][0], queuedLength);
  rxQueueReadIndex = nextQueueIndex(rxQueueReadIndex);
  --rxQueueCount;
  exitCritical(primask);

  *length = queuedLength;
  return true;
}

bool queuedFrameAvailable(uint16_t *length) {
  const uint32_t primask = enterCritical();
  if (rxQueueCount == 0) {
    exitCritical(primask);
    return false;
  }

  if (length != nullptr)
    *length = rxQueueLengths[rxQueueReadIndex];

  exitCritical(primask);
  return true;
}

bool discardQueuedFrame() {
  const uint32_t primask = enterCritical();
  if (rxQueueCount == 0) {
    exitCritical(primask);
    return false;
  }

  rxQueueReadIndex = nextQueueIndex(rxQueueReadIndex);
  --rxQueueCount;
  exitCritical(primask);
  return true;
}

void drainReceivedFrames() {
  while (!receiveQueueFull()) {
    uint16_t length = 0;
    if (!gmac::receivedFrameSize(&length)) {
      if (!gmac::discardReceivedFrame())
        return;
      continue;
    }

    if (length == 0 || length > kFrameBufferSize) {
      gmac::discardReceivedFrame();
      continue;
    }

    if (!gmac::readReceivedFrame(rxDrainBuffer, sizeof(rxDrainBuffer),
                                 &length)) {
      gmac::discardReceivedFrame();
      return;
    }

    if (!queueReceivedFrame(rxDrainBuffer, length))
      return;
  }
}

void handleGmacEvents(gmac::EventMask events, void *) {
  if ((events & gmac::EventRxReady) != 0)
    drainReceivedFrames();

  if ((events & gmac::EventRxRecovered) != 0)
    clearReceiveQueue();

  if ((events & (gmac::EventTxComplete | gmac::EventTxRecovered)) != 0)
    txBufferInUse = false;
}

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
  clearReceiveQueue();
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

void EthernetClass::configureReceiveOptions(
    const gmac::ReceiveOptions &options) {
  gmac::configureReceiveOptions(options);
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

  return queuedFrameAvailable(length);
}

bool EthernetClass::readFrame(uint8_t *buffer, uint16_t capacity,
                              uint16_t *length) {
  if (!_begun)
    return false;

  return popReceivedFrame(buffer, capacity, length);
}

bool EthernetClass::writeFrame(const uint8_t *buffer, uint16_t length) {
  if (!_begun || buffer == nullptr || length == 0 || length > kFrameBufferSize)
    return false;

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

  return discardQueuedFrame();
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

  if (!gmac::registerEventCallback(handleGmacEvents))
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
