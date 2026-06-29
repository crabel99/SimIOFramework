#include "Ethernet.h"

/**
 * @file Ethernet.cpp
 * @brief SAME5x Ethernet coordinator implementation.
 *
 * This file wires GMAC frame events, the bounded MIIM manager, cached PHY link
 * state, and raw frame queues into the `EthernetClass` contract. It intentionally
 * stays below the IP/socket layer: no DHCP, DNS, TCP, UDP, TLS, lwIP pbuf, or
 * socket ownership belongs here.
 */

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>
#include <string.h>

namespace {
EthernetPhy defaultPhy;
#ifndef SIMIO_ETHERNET_RX_DESCRIPTOR_COUNT
#define SIMIO_ETHERNET_RX_DESCRIPTOR_COUNT 32
#endif
#ifndef SIMIO_ETHERNET_TX_DESCRIPTOR_COUNT
#define SIMIO_ETHERNET_TX_DESCRIPTOR_COUNT 8
#endif

constexpr uint8_t kRxDescriptorCount = SIMIO_ETHERNET_RX_DESCRIPTOR_COUNT;
constexpr uint8_t kTxDescriptorCount = SIMIO_ETHERNET_TX_DESCRIPTOR_COUNT;
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
EthernetClass::FrameReceiveCallback frameReceiveCallback = nullptr;
void *frameReceiveCallbackContext = nullptr;
bool txSlotInUse[kTxDescriptorCount] = {};
uint8_t txSlotWriteIndex = 0;
uint8_t txSlotCleanIndex = 0;
uint8_t txSlotCount = 0;

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

uint8_t nextTransmitSlotIndex(uint8_t index) {
  ++index;
  if (index >= kTxDescriptorCount)
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

void clearTransmitSlots() {
  const uint32_t primask = enterCritical();
  for (uint8_t i = 0; i < kTxDescriptorCount; ++i)
    txSlotInUse[i] = false;
  txSlotWriteIndex = 0;
  txSlotCleanIndex = 0;
  txSlotCount = 0;
  exitCritical(primask);
}

void releaseTransmitSlots(uint8_t count) {
  const uint32_t primask = enterCritical();
  while (count > 0 && txSlotCount > 0) {
    txSlotInUse[txSlotCleanIndex] = false;
    txSlotCleanIndex = nextTransmitSlotIndex(txSlotCleanIndex);
    --txSlotCount;
    --count;
  }
  exitCritical(primask);
}

bool receiveQueueFull() {
  const uint32_t primask = enterCritical();
  const bool full = rxQueueCount >= kRxDescriptorCount;
  exitCritical(primask);
  return full;
}

bool receiveCallbackRegistered() {
  const uint32_t primask = enterCritical();
  const bool registered = frameReceiveCallback != nullptr;
  exitCritical(primask);
  return registered;
}

bool deliverReceivedFrame(const uint8_t *frame, uint16_t length) {
  if (frame == nullptr || length == 0)
    return false;

  const uint32_t primask = enterCritical();
  EthernetClass::FrameReceiveCallback callback = frameReceiveCallback;
  void *context = frameReceiveCallbackContext;
  exitCritical(primask);

  if (callback == nullptr)
    return false;

  callback(frame, length, context);
  return true;
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
  for (uint8_t drained = 0; drained < kRxDescriptorCount; ++drained) {
    if (!receiveCallbackRegistered() && receiveQueueFull())
      return;

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

    if (deliverReceivedFrame(rxDrainBuffer, length))
      continue;

    if (!queueReceivedFrame(rxDrainBuffer, length))
      return;
  }
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

bool configureEthernetFrameBuffers() {
  clearReceiveQueue();
  clearTransmitSlots();
  return gmac::configureFrameBuffers(&rxDescriptors[0], kRxDescriptorCount,
                                     &rxBuffers[0][0], kFrameBufferSize,
                                     &txDescriptors[0], kTxDescriptorCount);
}

} // namespace

EthernetClass Ethernet;

EthernetClass::EthernetClass()
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phyLink(defaultPhy) {}

EthernetClass::EthernetClass(const uint8_t mac[6])
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phyLink(defaultPhy) {
  setMacAddress(mac);
}

EthernetClass::EthernetClass(EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phyLink(phy) {}

EthernetClass::EthernetClass(const uint8_t mac[6], EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phyLink(phy) {
  setMacAddress(mac);
}

EthernetClass::~EthernetClass() {
  clearFrameReceiveCallback();

  if (_begun) {
    gmac::disableFrameIo();
    gmac::clearEventCallback();
    clearReceiveQueue();
    clearTransmitSlots();

    _begun = false;
  }
}

EthernetHardwareStatus EthernetClass::hardwareStatus() const {
  return gmac::available() ? EthernetGmac : EthernetNoHardware;
}

EthernetLinkStatus EthernetClass::linkStatus() const {
  return _phyLink.linkStatus();
}

EthernetPhyLinkSpeed EthernetClass::linkSpeed() const {
  return _phyLink.linkSpeed();
}

EthernetPhyDuplex EthernetClass::duplex() const { return _phyLink.duplex(); }

bool EthernetClass::carrierUp() const { return _phyLink.carrierUp(); }

EthernetLinkRefreshState EthernetClass::linkRefreshState() const {
  return _phyLink.linkRefreshState();
}

EthernetPhySetupState EthernetClass::phySetupState() const {
  return _phyLink.phySetupState();
}

void EthernetClass::setPhy(EthernetPhy &phy) {
  _begun = false;
  _phyLink.setPhy(phy);
}

EthernetPhy *EthernetClass::phy() const { return _phyLink.phy(); }

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
  return _phyLink.updateLinkConfiguration();
}

bool EthernetClass::requestLinkRefresh() {
  return _phyLink.requestLinkRefresh();
}

bool EthernetClass::requestPhyReset() { return _phyLink.requestPhyReset(); }

bool EthernetClass::requestPhySetup() {
  return _phyLink.requestPhySetup();
}

void EthernetClass::requestLinkRefreshFromIsr() {
  _phyLink.requestLinkRefreshFromIsr();
}

bool EthernetClass::setPhyInterruptPin(uint32_t pin, uint32_t mode) {
  return _phyLink.setPhyInterruptPin(pin, mode);
}

void EthernetClass::clearPhyInterruptPin() {
  _phyLink.clearPhyInterruptPin();
}

bool EthernetClass::service() {
  return _phyLink.service();
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

void EthernetClass::setFrameReceiveCallback(FrameReceiveCallback callback,
                                            void *context) {
  const uint32_t primask = enterCritical();
  frameReceiveCallback = callback;
  frameReceiveCallbackContext = context;
  exitCritical(primask);

  clearReceiveQueue();
}

void EthernetClass::clearFrameReceiveCallback() {
  const uint32_t primask = enterCritical();
  frameReceiveCallback = nullptr;
  frameReceiveCallbackContext = nullptr;
  exitCritical(primask);
}

void EthernetClass::setLinkChangeCallback(LinkChangeCallback callback,
                                          void *context) {
  _phyLink.setLinkChangeCallback(callback, context);
}

void EthernetClass::clearLinkChangeCallback() {
  _phyLink.clearLinkChangeCallback();
}

void EthernetClass::setCarrierCallback(CarrierCallback callback,
                                       void *context) {
  _phyLink.setCarrierCallback(callback, context);
}

void EthernetClass::clearCarrierCallback() {
  _phyLink.clearCarrierCallback();
}

void EthernetClass::handleGmacEvents(gmac::EventMask events) {
  if ((events & gmac::EventRxReady) != 0)
    drainReceivedFrames();

  if ((events & gmac::EventRxRecovered) != 0)
    clearReceiveQueue();

  if ((events & (gmac::EventTxComplete | gmac::EventTxRecovered)) != 0) {
    if ((events & gmac::EventTxRecovered) != 0)
      clearTransmitSlots();
    else
      releaseTransmitSlots(gmac::lastReclaimedTransmitDescriptors());
  }

  if ((events & gmac::EventManagementComplete) != 0)
    service();
}

void EthernetClass::handleGmacEvents(gmac::EventMask events, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleGmacEvents(events);
}

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

  uint32_t primask = enterCritical();
  if (txSlotCount >= kTxDescriptorCount) {
    exitCritical(primask);
    return false;
  }
  const uint8_t slot = txSlotWriteIndex;
  txSlotInUse[slot] = true;
  txSlotWriteIndex = nextTransmitSlotIndex(txSlotWriteIndex);
  ++txSlotCount;
  exitCritical(primask);

  memcpy(&txBuffers[slot][0], buffer, length);
  if (!gmac::queueTransmitBuffer(&txBuffers[slot][0], length)) {
    primask = enterCritical();
    txSlotInUse[slot] = false;
    txSlotWriteIndex = slot;
    --txSlotCount;
    exitCritical(primask);
    return false;
  }

  return true;
}

bool EthernetClass::discardFrame() {
  if (!_begun)
    return false;

  return discardQueuedFrame();
}

int EthernetClass::begin() {
  _begun = false;

  if (hardwareStatus() == EthernetNoHardware || !_hasMac || phy() == nullptr ||
      !_phyLink.begin())
    return 0;

  gmac::setMacAddress(_mac);
  if (!configureEthernetFrameBuffers())
    return 0;

  if (!gmac::registerEventCallback(EthernetClass::handleGmacEvents, this))
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
