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
#include <utility/phy/PhyRegisters.h>
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
EthernetClass::FrameReceiveCallback frameReceiveCallback = nullptr;
void *frameReceiveCallbackContext = nullptr;
bool txBufferInUse = false;
EthernetClass *phyInterruptOwner = nullptr;

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
  const uint32_t primask = enterCritical();
  txBufferInUse = false;
  exitCritical(primask);
  return gmac::configureFrameBuffers(&rxDescriptors[0], kRxDescriptorCount,
                                     &rxBuffers[0][0], kFrameBufferSize,
                                     &txDescriptors[0], kTxDescriptorCount);
}

} // namespace

EthernetClass Ethernet;

EthernetClass::EthernetClass()
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phy(&defaultPhy), _linkStatus(Unknown),
      _linkSpeed(EthernetPhySpeedUnknown), _duplex(EthernetPhyDuplexUnknown),
      _linkChangeCallback(nullptr), _linkChangeCallbackContext(nullptr),
      _carrierCallback(nullptr), _carrierCallbackContext(nullptr), _miim(),
      _phySetupPending(false), _phySetupState(PhySetupIdle),
      _linkRefreshPending(false), _linkRefreshState(LinkRefreshIdle),
      _linkRefreshRequested(false), _phyInterruptStatusRequested(false),
      _phyInterruptStatusPending(false), _phyInterruptAttached(false),
      _phyInterruptPin(0), _phyInterruptMode(FALLING), _phyId1(0),
      _phyInterruptEvents(0), _linkAdvertisement(0) {}

EthernetClass::EthernetClass(const uint8_t mac[6])
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false),
      _phy(&defaultPhy), _linkStatus(Unknown),
      _linkSpeed(EthernetPhySpeedUnknown), _duplex(EthernetPhyDuplexUnknown),
      _linkChangeCallback(nullptr), _linkChangeCallbackContext(nullptr),
      _carrierCallback(nullptr), _carrierCallbackContext(nullptr), _miim(),
      _phySetupPending(false), _phySetupState(PhySetupIdle),
      _linkRefreshPending(false), _linkRefreshState(LinkRefreshIdle),
      _linkRefreshRequested(false), _phyInterruptStatusRequested(false),
      _phyInterruptStatusPending(false), _phyInterruptAttached(false),
      _phyInterruptPin(0), _phyInterruptMode(FALLING), _phyId1(0),
      _phyInterruptEvents(0), _linkAdvertisement(0) {
  setMacAddress(mac);
}

EthernetClass::EthernetClass(EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false), _phy(&phy),
      _linkStatus(Unknown), _linkSpeed(EthernetPhySpeedUnknown),
      _duplex(EthernetPhyDuplexUnknown), _linkChangeCallback(nullptr),
      _linkChangeCallbackContext(nullptr), _carrierCallback(nullptr),
      _carrierCallbackContext(nullptr), _miim(), _phySetupPending(false),
      _phySetupState(PhySetupIdle), _linkRefreshPending(false),
      _linkRefreshState(LinkRefreshIdle), _linkRefreshRequested(false),
      _phyInterruptStatusRequested(false), _phyInterruptStatusPending(false),
      _phyInterruptAttached(false), _phyInterruptPin(0),
      _phyInterruptMode(FALLING), _phyId1(0), _phyInterruptEvents(0),
      _linkAdvertisement(0) {
  _miim.setPhyAddress(phy.address());
}

EthernetClass::EthernetClass(const uint8_t mac[6], EthernetPhy &phy)
    : _mac{0, 0, 0, 0, 0, 0}, _hasMac(false), _begun(false), _phy(&phy),
      _linkStatus(Unknown), _linkSpeed(EthernetPhySpeedUnknown),
      _duplex(EthernetPhyDuplexUnknown), _linkChangeCallback(nullptr),
      _linkChangeCallbackContext(nullptr), _carrierCallback(nullptr),
      _carrierCallbackContext(nullptr), _miim(), _phySetupPending(false),
      _phySetupState(PhySetupIdle), _linkRefreshPending(false),
      _linkRefreshState(LinkRefreshIdle), _linkRefreshRequested(false),
      _phyInterruptStatusRequested(false), _phyInterruptStatusPending(false),
      _phyInterruptAttached(false), _phyInterruptPin(0),
      _phyInterruptMode(FALLING), _phyId1(0), _phyInterruptEvents(0),
      _linkAdvertisement(0) {
  setMacAddress(mac);
  _miim.setPhyAddress(phy.address());
}

EthernetHardwareStatus EthernetClass::hardwareStatus() const {
  return gmac::available() ? EthernetGmac : EthernetNoHardware;
}

EthernetLinkStatus EthernetClass::linkStatus() const {
  return _linkStatus;
}

EthernetPhyLinkSpeed EthernetClass::linkSpeed() const { return _linkSpeed; }

EthernetPhyDuplex EthernetClass::duplex() const { return _duplex; }

bool EthernetClass::carrierUp() const { return _linkStatus == LinkON; }

EthernetLinkRefreshState EthernetClass::linkRefreshState() const {
  return _linkRefreshState;
}

EthernetPhySetupState EthernetClass::phySetupState() const {
  return _phySetupState;
}

void EthernetClass::setPhy(EthernetPhy &phy) {
  if (_phyInterruptAttached && _phy != nullptr)
    _phy->clearInterruptCallback();

  _phy = &phy;
  if (_phyInterruptAttached)
    _phy->setInterruptCallback(EthernetClass::handlePhyInterruptCallback,
                               this);
  _begun = false;
  _miim.reset();
  _miim.setPhyAddress(phy.address());
  _phySetupPending = false;
  _phySetupState = PhySetupIdle;
  _phyId1 = 0;
  _linkRefreshPending = false;
  _linkRefreshState = LinkRefreshIdle;
  _linkRefreshRequested = false;
  _phyInterruptStatusRequested = false;
  _phyInterruptStatusPending = false;
  _phyInterruptEvents = 0;
  updateCachedLink(Unknown, EthernetPhySpeedUnknown, EthernetPhyDuplexUnknown);
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
  if (_linkStatus != LinkON || _linkSpeed == EthernetPhySpeedUnknown ||
      _duplex == EthernetPhyDuplexUnknown)
    return false;

  gmac::configureLink(_linkSpeed == EthernetPhySpeed100M ? gmac::LinkSpeed100M
                                                         : gmac::LinkSpeed10M,
                      _duplex == EthernetPhyFullDuplex);
  return true;
}

bool EthernetClass::requestLinkRefresh() {
  if (_phy == nullptr || _linkRefreshPending)
    return false;

  _linkRefreshPending = true;
  _linkRefreshState = LinkRefreshReadingStatus;
  if (queueLinkStatusRead())
    return true;

  _linkRefreshPending = false;
  _linkRefreshState = LinkRefreshFailed;
  return false;
}

bool EthernetClass::requestPhySetup() {
  if (_phy == nullptr || _phySetupPending)
    return false;

  _phySetupPending = true;
  _phyId1 = 0;
  if (_phy->address() == EthernetPhy::BROADCAST_ADDRESS) {
    _phySetupState = PhySetupScanning;
    if (queuePhyScan())
      return true;
  } else {
    _phySetupState = PhySetupReadingId1;
    if (queuePhyId1Read())
      return true;
  }

  _phySetupPending = false;
  _phySetupState = PhySetupFailed;
  return false;
}

void EthernetClass::requestLinkRefreshFromIsr() {
  uint8_t registerAddress = 0;
  if (_phy != nullptr && _phy->interruptControlStatusRegister(&registerAddress)) {
    _phyInterruptStatusRequested = true;
  } else {
    _linkRefreshRequested = true;
  }
  gmac::scheduleEvent(gmac::EventManagementComplete);
}

bool EthernetClass::setPhyInterruptPin(uint32_t pin, uint32_t mode) {
  clearPhyInterruptPin();
  if (_phy == nullptr)
    return false;

  uint8_t interruptRegister = 0;
  const bool phyInterruptsSupported =
      _phy->interruptControlStatusRegister(&interruptRegister);
  const int32_t interruptNumber =
      static_cast<int32_t>(digitalPinToInterrupt(pin));
  if (interruptNumber == NOT_AN_INTERRUPT)
    return false;

  pinMode(pin, INPUT_PULLUP);
  phyInterruptOwner = this;
  _phy->setInterruptCallback(EthernetClass::handlePhyInterruptCallback, this);
  _phyInterruptPin = pin;
  _phyInterruptMode = mode;
  attachInterrupt(static_cast<uint32_t>(interruptNumber),
                  EthernetClass::handlePhyInterrupt, mode);
  _phyInterruptAttached = true;
  if (phyInterruptsSupported && !_phySetupPending) {
    if (_phySetupState == PhySetupVerified) {
      if (queuePhyInterruptEnableWrite()) {
        _phySetupPending = true;
        gmac::scheduleEvent(gmac::EventManagementComplete);
      }
    } else if (_phySetupState == PhySetupIdle) {
      if (requestPhySetup())
        gmac::scheduleEvent(gmac::EventManagementComplete);
    }
  }
  return true;
}

void EthernetClass::clearPhyInterruptPin() {
  if (_phyInterruptAttached) {
    const int32_t interruptNumber =
        static_cast<int32_t>(digitalPinToInterrupt(_phyInterruptPin));
    if (interruptNumber != NOT_AN_INTERRUPT)
      detachInterrupt(static_cast<uint32_t>(interruptNumber));
  }

  if (phyInterruptOwner == this)
    phyInterruptOwner = nullptr;

  if (_phy != nullptr)
    _phy->clearInterruptCallback();

  _phyInterruptAttached = false;
}

bool EthernetClass::service() {
  return _miim.service();
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
  _linkChangeCallback = callback;
  _linkChangeCallbackContext = context;
}

void EthernetClass::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeCallbackContext = nullptr;
}

void EthernetClass::setCarrierCallback(CarrierCallback callback,
                                       void *context) {
  _carrierCallback = callback;
  _carrierCallbackContext = context;
}

void EthernetClass::clearCarrierCallback() {
  _carrierCallback = nullptr;
  _carrierCallbackContext = nullptr;
}

bool EthernetClass::updateCachedLink(EthernetLinkStatus status,
                                     EthernetPhyLinkSpeed speed,
                                     EthernetPhyDuplex duplex) {
  const bool changed = _linkStatus != status || _linkSpeed != speed ||
                       _duplex != duplex;
  const bool carrierChanged = (_linkStatus == LinkON) != (status == LinkON);

  _linkStatus = status;
  _linkSpeed = speed;
  _duplex = duplex;

  if (!changed)
    return false;

  if (status == LinkON)
    updateLinkConfiguration();

  if (carrierChanged && _carrierCallback != nullptr)
    _carrierCallback(status == LinkON, _carrierCallbackContext);

  if (_linkChangeCallback != nullptr)
    _linkChangeCallback(status, speed, duplex, _linkChangeCallbackContext);

  return true;
}

bool EthernetClass::queuePhyId1Read() {
  const bool queued =
      _miim.read(_phy->address(), PHY_REG_PHYID1,
                 EthernetClass::handlePhyId1Read, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupReadingId1;
  return queued;
}

bool EthernetClass::queuePhyId2Read() {
  const bool queued =
      _miim.read(_phy->address(), PHY_REG_PHYID2,
                 EthernetClass::handlePhyId2Read, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupReadingId2;
  return queued;
}

bool EthernetClass::queuePhyScan() {
  const bool queued =
      _miim.scan(PHY_REG_PHYID1, 0, 31, EthernetClass::handlePhyScanRead,
                 this) != MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupScanning;
  return queued;
}

bool EthernetClass::queuePhyInterruptEnableWrite() {
  uint8_t registerAddress = 0;
  uint16_t registerValue = 0;
  constexpr uint16_t events = EthernetPhyInterruptLinkUp |
                              EthernetPhyInterruptLinkDown |
                              EthernetPhyInterruptAutoNegotiationComplete;
  if (_phy == nullptr ||
      !_phy->interruptControlStatusRegister(&registerAddress) ||
      !_phy->encodeInterruptEnable(events, &registerValue)) {
    return false;
  }

  const bool queued =
      _miim.write(_phy->address(), registerAddress, registerValue,
                  EthernetClass::handlePhyInterruptEnableWrite, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupConfiguringInterrupts;
  return queued;
}

bool EthernetClass::queuePhyInterruptStatusRead() {
  uint8_t registerAddress = 0;
  if (_phy == nullptr ||
      !_phy->interruptControlStatusRegister(&registerAddress)) {
    return false;
  }

  const bool queued =
      _miim.read(_phy->address(), registerAddress,
                 EthernetClass::handlePhyInterruptStatusRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phyInterruptStatusPending = true;
  return queued;
}

bool EthernetClass::queueLinkStatusRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegBmstat::addr),
                 EthernetClass::handleLinkStatusRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingStatus;
  return queued;
}

bool EthernetClass::queueVendorModeRead() {
  uint8_t registerAddress = 0;
  if (_phy == nullptr || !_phy->resolvedModeRegister(&registerAddress)) {
    return false;
  }

  const bool queued =
      _miim.read(_phy->address(), registerAddress,
                 EthernetClass::handleVendorModeRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingVendorMode;
  return queued;
}

bool EthernetClass::queueLinkAdvertisementRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegAnad::addr),
                 EthernetClass::handleLinkAdvertisementRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingAdvertisement;
  return queued;
}

bool EthernetClass::queueLinkPartnerAbilityRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegAnlpad::addr),
                 EthernetClass::handleLinkPartnerAbilityRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingPartnerAbility;
  return queued;
}

void EthernetClass::handleGmacEvents(gmac::EventMask events) {
  if ((events & gmac::EventRxReady) != 0)
    drainReceivedFrames();

  if ((events & gmac::EventRxRecovered) != 0)
    clearReceiveQueue();

  if ((events & (gmac::EventTxComplete | gmac::EventTxRecovered)) != 0) {
    const uint32_t primask = enterCritical();
    txBufferInUse = false;
    exitCritical(primask);
  }

  if (_phyInterruptStatusRequested && !_phyInterruptStatusPending) {
    _phyInterruptStatusRequested = false;
    if (!queuePhyInterruptStatusRead())
      _linkRefreshRequested = true;
  }

  if (_linkRefreshRequested && !_linkRefreshPending) {
    _linkRefreshRequested = false;
    requestLinkRefresh();
  }

  if ((events & gmac::EventManagementComplete) != 0)
    service();
}

void EthernetClass::handlePhyId1Read(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value) {
  _miim.release(handle);

  if (result != MiimManager::ResultOk) {
    _phySetupPending = false;
    _phySetupState = PhySetupFailed;
    return;
  }

  _phyId1 = value;
  if (!queuePhyId2Read()) {
    _phySetupPending = false;
    _phySetupState = PhySetupFailed;
  }
}

void EthernetClass::handlePhyScanRead(MiimManager::OperationHandle handle,
                                      MiimManager::OperationResult result,
                                      uint16_t value) {
  uint8_t discoveredAddress = EthernetPhy::BROADCAST_ADDRESS;
  _miim.operationPhyAddress(handle, &discoveredAddress);
  _miim.release(handle);

  if (result == MiimManager::ResultNotFound) {
    _phySetupPending = false;
    _phySetupState = PhySetupScanNotFound;
    return;
  }

  if (result != MiimManager::ResultOk || _phy == nullptr ||
      !_phy->setAddress(discoveredAddress)) {
    _phySetupPending = false;
    _phySetupState = PhySetupFailed;
    return;
  }

  _miim.setPhyAddress(discoveredAddress);
  _phyId1 = value;
  if (!queuePhyId2Read()) {
    _phySetupPending = false;
    _phySetupState = PhySetupFailed;
  }
}

void EthernetClass::handlePhyId2Read(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value) {
  _miim.release(handle);
  _phySetupPending = false;

  if (result != MiimManager::ResultOk) {
    _phySetupState = PhySetupFailed;
    return;
  }

  const uint32_t rawId = (static_cast<uint32_t>(_phyId1) << 16) | value;
  EthernetPhyId phyId = {};
  phyId.raw = rawId;
  phyId.oui = (rawId >> 10) & 0x00FFFFFFu;
  phyId.model = static_cast<uint8_t>((rawId >> 4) & 0x3Fu);
  phyId.revision = static_cast<uint8_t>(rawId & 0x0Fu);

  _phySetupState =
      (_phy != nullptr && _phy->acceptsPhyId(phyId)) ? PhySetupVerified
                                                     : PhySetupInvalidId;
  if (_phySetupState != PhySetupVerified)
    return;

  if (_phyInterruptAttached && queuePhyInterruptEnableWrite()) {
    _phySetupPending = true;
    return;
  }
}

void EthernetClass::handlePhyInterruptEnableWrite(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  (void)value;
  _miim.release(handle);
  _phySetupPending = false;
  _phySetupState =
      result == MiimManager::ResultOk ? PhySetupVerified : PhySetupFailed;
}

void EthernetClass::handlePhyInterruptStatusRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  _miim.release(handle);
  _phyInterruptStatusPending = false;
  _phyInterruptEvents = 0;

  if (result == MiimManager::ResultOk && _phy != nullptr) {
    _phy->decodeInterruptStatus(value, &_phyInterruptEvents);
  }

  if (!_linkRefreshPending) {
    requestLinkRefresh();
  } else {
    _linkRefreshRequested = true;
  }
}

void EthernetClass::handleLinkStatusRead(MiimManager::OperationHandle handle,
                                         MiimManager::OperationResult result,
                                         uint16_t value) {
  _miim.release(handle);

  if (result != MiimManager::ResultOk) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(Unknown, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  if (!EthernetPhy::basicStatusReportsLinkUp(value)) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshLinkDown;
    updateCachedLink(LinkOFF, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  if ((value & PhyRegBmstat::bit::AutoNegotiationAbility) == 0) {
    if (queueVendorModeRead()) {
      return;
    }

    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshAutoNegotiationUnsupported;
    updateCachedLink(LinkON, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  if ((value & PhyRegBmstat::bit::AutoNegotiationComplete) == 0) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshAutoNegotiationActive;
    updateCachedLink(Unknown, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  if (!queueLinkAdvertisementRead()) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(LinkON, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
  }
}

void EthernetClass::handleVendorModeRead(MiimManager::OperationHandle handle,
                                         MiimManager::OperationResult result,
                                         uint16_t value) {
  _miim.release(handle);
  _linkRefreshPending = false;

  if (result != MiimManager::ResultOk) {
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(Unknown, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  EthernetPhyLinkSpeed speed = EthernetPhySpeedUnknown;
  EthernetPhyDuplex duplex = EthernetPhyDuplexUnknown;
  if (_phy == nullptr || !_phy->resolveVendorLinkMode(value, &speed, &duplex)) {
    _linkRefreshState = LinkRefreshVendorModeUnresolved;
    updateCachedLink(LinkON, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  _linkRefreshState = LinkRefreshVendorModeResolved;
  updateCachedLink(LinkON, speed, duplex);
}

void EthernetClass::handleLinkAdvertisementRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  _miim.release(handle);

  if (result != MiimManager::ResultOk) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(Unknown, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  _linkAdvertisement = value;
  if (!queueLinkPartnerAbilityRead()) {
    _linkRefreshPending = false;
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(LinkON, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
  }
}

void EthernetClass::handleLinkPartnerAbilityRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  _miim.release(handle);
  _linkRefreshPending = false;

  if (result != MiimManager::ResultOk) {
    _linkRefreshState = LinkRefreshFailed;
    updateCachedLink(Unknown, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  EthernetPhyLinkSpeed speed = EthernetPhySpeedUnknown;
  EthernetPhyDuplex duplex = EthernetPhyDuplexUnknown;
  if (!EthernetPhy::resolveAutoNegotiatedLink(_linkAdvertisement, value, &speed,
                                              &duplex)) {
    _linkRefreshState = LinkRefreshUnresolved;
    updateCachedLink(LinkON, EthernetPhySpeedUnknown,
                     EthernetPhyDuplexUnknown);
    return;
  }

  _linkRefreshState = LinkRefreshResolved;
  updateCachedLink(LinkON, speed, duplex);
}

void EthernetClass::handleGmacEvents(gmac::EventMask events, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleGmacEvents(events);
}

void EthernetClass::handlePhyId1Read(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handlePhyId1Read(handle, result, value);
}

void EthernetClass::handlePhyScanRead(MiimManager::OperationHandle handle,
                                      MiimManager::OperationResult result,
                                      uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handlePhyScanRead(handle, result, value);
}

void EthernetClass::handlePhyId2Read(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handlePhyId2Read(handle, result, value);
}

void EthernetClass::handlePhyInterruptEnableWrite(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handlePhyInterruptEnableWrite(handle, result, value);
}

void EthernetClass::handlePhyInterruptStatusRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handlePhyInterruptStatusRead(handle, result, value);
}

void EthernetClass::handleLinkStatusRead(MiimManager::OperationHandle handle,
                                         MiimManager::OperationResult result,
                                         uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleLinkStatusRead(handle, result, value);
}

void EthernetClass::handleVendorModeRead(MiimManager::OperationHandle handle,
                                         MiimManager::OperationResult result,
                                         uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleVendorModeRead(handle, result, value);
}

void EthernetClass::handleLinkAdvertisementRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleLinkAdvertisementRead(handle, result, value);
}

void EthernetClass::handleLinkPartnerAbilityRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->handleLinkPartnerAbilityRead(handle, result, value);
}

void EthernetClass::handlePhyInterrupt() {
  if (phyInterruptOwner != nullptr && phyInterruptOwner->_phy != nullptr)
    phyInterruptOwner->_phy->notifyInterruptFromIsr();
}

void EthernetClass::handlePhyInterruptCallback(void *context) {
  EthernetClass *ethernet = static_cast<EthernetClass *>(context);
  if (ethernet != nullptr)
    ethernet->requestLinkRefreshFromIsr();
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
  if (txBufferInUse) {
    exitCritical(primask);
    return false;
  }
  txBufferInUse = true;
  exitCritical(primask);

  memcpy(&txBuffers[0][0], buffer, length);
  if (!gmac::queueTransmitBuffer(&txBuffers[0][0], length)) {
    primask = enterCritical();
    txBufferInUse = false;
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

  if (hardwareStatus() == EthernetNoHardware || !_hasMac || _phy == nullptr ||
      !_miim.setup())
    return 0;

  _miim.reset();
  _miim.setPhyAddress(_phy->address());
  _phySetupPending = false;
  _phySetupState = PhySetupIdle;
  _phyId1 = 0;
  _linkRefreshPending = false;
  _linkRefreshState = LinkRefreshIdle;
  _linkRefreshRequested = false;
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
