#include "PhyLinkManager.h"

/**
 * @file PhyLinkManager.cpp
 * @brief Bounded PHY setup, interrupt, link refresh, and autonegotiation flow.
 */

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>
#include <PendSV.h>
#include <utility/phy/PhyRegisters.h>

namespace {
PhyLinkManager *phyInterruptOwner = nullptr;
}

PhyLinkManager::PhyLinkManager(EthernetPhy &phy)
    : _phy(&phy), _linkStatus(Unknown),
      _linkSpeed(EthernetPhySpeedUnknown), _duplex(EthernetPhyDuplexUnknown),
      _linkChangeCallback(nullptr), _linkChangeCallbackContext(nullptr),
      _carrierCallback(nullptr), _carrierCallbackContext(nullptr), _miim(),
      _phySetupPending(false), _phySetupState(PhySetupIdle),
      _linkRefreshPending(false), _linkRefreshState(LinkRefreshIdle),
      _linkRefreshRequested(false), _phyInterruptStatusRequested(false),
      _phyInterruptStatusPending(false), _phyInterruptAttached(false),
      _phyInterruptPin(0), _phyInterruptMode(FALLING), _phyId1(0),
      _phyInterruptEvents(0), _linkAdvertisement(0) {
  _miim.setPhyAddress(phy.address());
}

PhyLinkManager::~PhyLinkManager() {
  clearPhyInterruptPin(false);
  PendSV::instance().clearService(PendSVChannels::Phy);
}

EthernetLinkStatus PhyLinkManager::linkStatus() const { return _linkStatus; }

EthernetPhyLinkSpeed PhyLinkManager::linkSpeed() const { return _linkSpeed; }

EthernetPhyDuplex PhyLinkManager::duplex() const { return _duplex; }

bool PhyLinkManager::carrierUp() const { return _linkStatus == LinkON; }

EthernetLinkRefreshState PhyLinkManager::linkRefreshState() const {
  return _linkRefreshState;
}

EthernetPhySetupState PhyLinkManager::phySetupState() const {
  return _phySetupState;
}

void PhyLinkManager::setPhy(EthernetPhy &phy) {
  if (_phyInterruptAttached && _phy != nullptr)
    _phy->clearInterruptCallback();

  _phy = &phy;
  if (_phyInterruptAttached)
    _phy->setInterruptCallback(PhyLinkManager::handlePhyInterruptCallback,
                               this);
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

EthernetPhy *PhyLinkManager::phy() const { return _phy; }

bool PhyLinkManager::begin() {
  if (_phy == nullptr || !_miim.setup())
    return false;

  _miim.reset();
  _miim.setPhyAddress(_phy->address());
  _phySetupPending = false;
  _phySetupState = PhySetupIdle;
  _phyId1 = 0;
  _linkRefreshPending = false;
  _linkRefreshState = LinkRefreshIdle;
  _linkRefreshRequested = false;
  _phyInterruptStatusRequested = false;
  _phyInterruptStatusPending = false;
  _phyInterruptEvents = 0;
  return ensurePhyPendSvServiceRegistered();
}

bool PhyLinkManager::updateLinkConfiguration() {
  if (_linkStatus != LinkON || _linkSpeed == EthernetPhySpeedUnknown ||
      _duplex == EthernetPhyDuplexUnknown)
    return false;

  gmac::configureLink(_linkSpeed == EthernetPhySpeed100M ? gmac::LinkSpeed100M
                                                         : gmac::LinkSpeed10M,
                      _duplex == EthernetPhyFullDuplex);
  return true;
}

bool PhyLinkManager::requestLinkRefresh() {
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

bool PhyLinkManager::requestPhySetup() {
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

void PhyLinkManager::requestLinkRefreshFromIsr() {
  uint8_t registerAddress = 0;
  if (_phy != nullptr && _phy->interruptControlStatusRegister(&registerAddress)) {
    _phyInterruptStatusRequested = true;
  } else {
    _linkRefreshRequested = true;
  }
  PendSV::instance().setPending(PendSVChannels::Phy);
}

bool PhyLinkManager::setPhyInterruptPin(uint32_t pin, uint32_t mode) {
  clearPhyInterruptPin(false);
  if (_phy == nullptr)
    return false;

  uint8_t interruptRegister = 0;
  const bool phyInterruptsSupported =
      _phy->interruptControlStatusRegister(&interruptRegister);
  const int32_t interruptNumber =
      static_cast<int32_t>(digitalPinToInterrupt(pin));
  if (interruptNumber == NOT_AN_INTERRUPT)
    return false;

  if (!ensurePhyPendSvServiceRegistered())
    return false;

  pinMode(pin, INPUT_PULLUP);
  phyInterruptOwner = this;
  _phy->setInterruptCallback(PhyLinkManager::handlePhyInterruptCallback, this);
  _phyInterruptPin = pin;
  _phyInterruptMode = mode;
  attachInterrupt(static_cast<uint32_t>(interruptNumber),
                  PhyLinkManager::handlePhyInterrupt, mode);
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

void PhyLinkManager::clearPhyInterruptPin() { clearPhyInterruptPin(true); }

void PhyLinkManager::clearPhyInterruptPin(bool disablePhyInterrupts) {
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

  if (disablePhyInterrupts && _phyInterruptAttached &&
      _phySetupState == PhySetupVerified && !_phySetupPending &&
      queuePhyInterruptDisableWrite()) {
    _phySetupPending = true;
    gmac::scheduleEvent(gmac::EventManagementComplete);
  }

  _phyInterruptAttached = false;
}

bool PhyLinkManager::service() { return _miim.service(); }

void PhyLinkManager::setLinkChangeCallback(LinkChangeCallback callback,
                                           void *context) {
  _linkChangeCallback = callback;
  _linkChangeCallbackContext = context;
}

void PhyLinkManager::clearLinkChangeCallback() {
  _linkChangeCallback = nullptr;
  _linkChangeCallbackContext = nullptr;
}

void PhyLinkManager::setCarrierCallback(CarrierCallback callback,
                                        void *context) {
  _carrierCallback = callback;
  _carrierCallbackContext = context;
}

void PhyLinkManager::clearCarrierCallback() {
  _carrierCallback = nullptr;
  _carrierCallbackContext = nullptr;
}

bool PhyLinkManager::ensurePhyPendSvServiceRegistered() {
  return PendSV::instance().registerService(PendSVChannels::Phy,
                                            PhyLinkManager::handlePhyPendSv,
                                            this);
}

bool PhyLinkManager::updateCachedLink(EthernetLinkStatus status,
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

bool PhyLinkManager::queuePhyId1Read() {
  const bool queued =
      _miim.read(_phy->address(), PHY_REG_PHYID1,
                 PhyLinkManager::handlePhyId1Read, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupReadingId1;
  return queued;
}

bool PhyLinkManager::queuePhyId2Read() {
  const bool queued =
      _miim.read(_phy->address(), PHY_REG_PHYID2,
                 PhyLinkManager::handlePhyId2Read, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupReadingId2;
  return queued;
}

bool PhyLinkManager::queuePhyScan() {
  const bool queued =
      _miim.scan(PHY_REG_PHYID1, 0, 31, PhyLinkManager::handlePhyScanRead,
                 this) != MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupScanning;
  return queued;
}

bool PhyLinkManager::queuePhyInterruptEnableWrite() {
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
                  PhyLinkManager::handlePhyInterruptEnableWrite, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupConfiguringInterrupts;
  return queued;
}

bool PhyLinkManager::queuePhyInterruptDisableWrite() {
  uint8_t registerAddress = 0;
  if (_phy == nullptr ||
      !_phy->interruptControlStatusRegister(&registerAddress)) {
    return false;
  }

  const bool queued =
      _miim.write(_phy->address(), registerAddress, 0,
                  PhyLinkManager::handlePhyInterruptEnableWrite, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phySetupState = PhySetupConfiguringInterrupts;
  return queued;
}

bool PhyLinkManager::queuePhyInterruptStatusRead() {
  uint8_t registerAddress = 0;
  if (_phy == nullptr ||
      !_phy->interruptControlStatusRegister(&registerAddress)) {
    return false;
  }

  const bool queued =
      _miim.read(_phy->address(), registerAddress,
                 PhyLinkManager::handlePhyInterruptStatusRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _phyInterruptStatusPending = true;
  return queued;
}

bool PhyLinkManager::queueLinkStatusRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegBmstat::addr),
                 PhyLinkManager::handleLinkStatusRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingStatus;
  return queued;
}

bool PhyLinkManager::queueVendorModeRead() {
  uint8_t registerAddress = 0;
  if (_phy == nullptr || !_phy->resolvedModeRegister(&registerAddress)) {
    return false;
  }

  const bool queued =
      _miim.read(_phy->address(), registerAddress,
                 PhyLinkManager::handleVendorModeRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingVendorMode;
  return queued;
}

bool PhyLinkManager::queueLinkAdvertisementRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegAnad::addr),
                 PhyLinkManager::handleLinkAdvertisementRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingAdvertisement;
  return queued;
}

bool PhyLinkManager::queueLinkPartnerAbilityRead() {
  const bool queued =
      _miim.read(_phy->address(), static_cast<uint8_t>(PhyRegAnlpad::addr),
                 PhyLinkManager::handleLinkPartnerAbilityRead, this) !=
      MiimManager::InvalidOperationHandle;
  if (queued)
    _linkRefreshState = LinkRefreshReadingPartnerAbility;
  return queued;
}

void PhyLinkManager::handlePhyId1Read(MiimManager::OperationHandle handle,
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

void PhyLinkManager::handlePhyScanRead(MiimManager::OperationHandle handle,
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

void PhyLinkManager::handlePhyId2Read(MiimManager::OperationHandle handle,
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

void PhyLinkManager::handlePhyInterruptEnableWrite(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  (void)value;
  _miim.release(handle);
  _phySetupPending = false;
  _phySetupState =
      result == MiimManager::ResultOk ? PhySetupVerified : PhySetupFailed;
}

void PhyLinkManager::handlePhyInterruptStatusRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value) {
  _miim.release(handle);
  _phyInterruptStatusPending = false;
  _phyInterruptEvents = 0;
  bool handled = false;

  if (result == MiimManager::ResultOk && _phy != nullptr) {
    handled = _phy->decodeInterruptStatus(value, &_phyInterruptEvents) &&
              handlePhyInterruptEvents(_phyInterruptEvents);
  }

  if (!handled && !_linkRefreshPending) {
    requestLinkRefresh();
  } else if (!handled) {
    _linkRefreshRequested = true;
  }
}

bool PhyLinkManager::handlePhyInterruptEvents(uint16_t events) {
  bool handled = false;

  if ((events & EthernetPhyInterruptLinkDown) != 0)
    handled = handlePhyLinkDownInterrupt() || handled;

  if ((events & EthernetPhyInterruptLinkUp) != 0)
    handled = handlePhyLinkUpInterrupt() || handled;

  if ((events & EthernetPhyInterruptAutoNegotiationComplete) != 0)
    handled = handlePhyAutoNegotiationCompleteInterrupt() || handled;

  return handled;
}

bool PhyLinkManager::handlePhyLinkDownInterrupt() {
  _linkRefreshPending = false;
  _linkRefreshRequested = false;
  _linkRefreshState = LinkRefreshLinkDown;
  updateCachedLink(LinkOFF, EthernetPhySpeedUnknown, EthernetPhyDuplexUnknown);
  return true;
}

bool PhyLinkManager::handlePhyLinkUpInterrupt() {
  if (!_linkRefreshPending)
    return requestLinkRefresh();

  _linkRefreshRequested = true;
  return true;
}

bool PhyLinkManager::handlePhyAutoNegotiationCompleteInterrupt() {
  if (!_linkRefreshPending)
    return requestLinkRefresh();

  _linkRefreshRequested = true;
  return true;
}

void PhyLinkManager::handleLinkStatusRead(MiimManager::OperationHandle handle,
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

void PhyLinkManager::handleVendorModeRead(MiimManager::OperationHandle handle,
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

void PhyLinkManager::handleLinkAdvertisementRead(
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

void PhyLinkManager::handleLinkPartnerAbilityRead(
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

void PhyLinkManager::handlePhyId1Read(MiimManager::OperationHandle handle,
                                      MiimManager::OperationResult result,
                                      uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handlePhyId1Read(handle, result, value);
}

void PhyLinkManager::handlePhyScanRead(MiimManager::OperationHandle handle,
                                       MiimManager::OperationResult result,
                                       uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handlePhyScanRead(handle, result, value);
}

void PhyLinkManager::handlePhyId2Read(MiimManager::OperationHandle handle,
                                      MiimManager::OperationResult result,
                                      uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handlePhyId2Read(handle, result, value);
}

void PhyLinkManager::handlePhyInterruptEnableWrite(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handlePhyInterruptEnableWrite(handle, result, value);
}

void PhyLinkManager::handlePhyInterruptStatusRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handlePhyInterruptStatusRead(handle, result, value);
}

void PhyLinkManager::handleLinkStatusRead(MiimManager::OperationHandle handle,
                                          MiimManager::OperationResult result,
                                          uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handleLinkStatusRead(handle, result, value);
}

void PhyLinkManager::handleVendorModeRead(MiimManager::OperationHandle handle,
                                          MiimManager::OperationResult result,
                                          uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handleVendorModeRead(handle, result, value);
}

void PhyLinkManager::handleLinkAdvertisementRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handleLinkAdvertisementRead(handle, result, value);
}

void PhyLinkManager::handleLinkPartnerAbilityRead(
    MiimManager::OperationHandle handle, MiimManager::OperationResult result,
    uint16_t value, void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->handleLinkPartnerAbilityRead(handle, result, value);
}

void PhyLinkManager::handlePhyPendSv(uint8_t serviceId, void *context) {
  (void)serviceId;
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager == nullptr)
    return;

  if (manager->_phyInterruptStatusRequested &&
      !manager->_phyInterruptStatusPending) {
    manager->_phyInterruptStatusRequested = false;
    if (!manager->queuePhyInterruptStatusRead())
      manager->_linkRefreshRequested = true;
  }

  if (manager->_linkRefreshRequested && !manager->_linkRefreshPending) {
    manager->_linkRefreshRequested = false;
    manager->requestLinkRefresh();
  }

  manager->service();
}

void PhyLinkManager::handlePhyInterrupt() {
  if (phyInterruptOwner != nullptr && phyInterruptOwner->_phy != nullptr)
    phyInterruptOwner->_phy->notifyInterruptFromIsr();
}

void PhyLinkManager::handlePhyInterruptCallback(void *context) {
  PhyLinkManager *manager = static_cast<PhyLinkManager *>(context);
  if (manager != nullptr)
    manager->requestLinkRefreshFromIsr();
}

#endif /* ETHERNET_HARDWARE_AVAILABLE */
