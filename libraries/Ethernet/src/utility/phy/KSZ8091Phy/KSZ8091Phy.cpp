#include "KSZ8091Phy.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE

namespace {
constexpr uint16_t kStrapOverridePmeEnable = 1u << 15;
constexpr uint16_t kStrapOverridePhyAddress0Unique = 1u << 9;
constexpr uint16_t kStrapOverrideRmiiBackToBack = 1u << 6;
constexpr uint16_t kStrapOverrideRmii = 1u << 1;
constexpr uint16_t kStrapStatusPhyAddressMask = 0xE000u;
constexpr uint16_t kStrapStatusPhyAddressShift = 13;
constexpr uint16_t kStrapStatusRmii = 1u << 1;
constexpr uint16_t kExpandedControlEdpdDisabled = 1u << 11;
constexpr uint16_t kExpandedControl10BaseTPreambleRestore = 1u << 6;
constexpr uint16_t kLinkMdStart = 1u << 15;
constexpr uint16_t kLinkMdResultMask = 0x6000u;
constexpr uint16_t kLinkMdResultShift = 13;
constexpr uint16_t kLinkMdShortCable = 1u << 12;
constexpr uint16_t kLinkMdFaultCounterMask = 0x01FFu;
constexpr uint16_t kPhyControl2HpAutoMdiMdiX = 1u << 15;
constexpr uint16_t kPhyControl2MdiMdiXSelect = 1u << 14;
constexpr uint16_t kPhyControl2PairSwapDisable = 1u << 13;
constexpr uint16_t kPhyControl2ForceLink = 1u << 11;
constexpr uint16_t kPhyControl2PowerSaving = 1u << 10;
constexpr uint16_t kPhyControl2InterruptLevel = 1u << 9;
constexpr uint16_t kPhyControl2JabberEnable = 1u << 8;
constexpr uint16_t kPhyControl2RmiiReferenceClockSelect = 1u << 7;
constexpr uint16_t kPhyControl2LedModeMask = 0x0030u;
constexpr uint16_t kPhyControl2LedModeShift = 4;
constexpr uint16_t kPhyControl2TransmitterDisable = 1u << 3;
constexpr uint16_t kPhyControl2RemoteLoopback = 1u << 2;
constexpr uint16_t kPhyControl2DataScramblingDisable = 1u << 0;
constexpr uint16_t kPmaPmdControlLpiEnable = 1u << 12;
constexpr uint16_t kPmaPmdStatusLpiEntered = 1u << 8;
constexpr uint16_t kPmaPmdStatusLpiActive = 1u << 3;
constexpr uint16_t kEee100BaseTX = 1u << 1;
constexpr uint16_t kWolMagicPacketDetectEnable = 1u << 6;
constexpr uint16_t kInterruptEnableShift = 8;
constexpr uint16_t kInterruptStatusMask = 0x00FFu;

bool readModifyWrite(KSZ8091Phy &phy, uint8_t reg, uint16_t mask,
                     bool enabled) {
  uint16_t value = 0;

  if (!phy.readRegister(reg, &value)) {
    return false;
  }

  if (enabled) {
    value |= mask;
  } else {
    value &= static_cast<uint16_t>(~mask);
  }

  return phy.writeRegister(reg, value);
}

bool writeBits(KSZ8091Phy &phy, uint8_t reg, uint16_t mask, uint16_t value) {
  uint16_t current = 0;

  if (!phy.readRegister(reg, &current)) {
    return false;
  }

  current = static_cast<uint16_t>((current & ~mask) | (value & mask));
  return phy.writeRegister(reg, current);
}
} // namespace

bool KSZ8091Phy::begin() {
  return EthernetPhy::begin() && isExpectedPhy();
}

bool KSZ8091Phy::configure() {
  uint16_t interruptStatus = 0;

  return EthernetPhy::configure() && configureInterrupts(0) &&
         clearInterruptStatus(&interruptStatus);
}

bool KSZ8091Phy::isExpectedPhy() const {
  EthernetPhyId phyId = {};

  if (!readId(&phyId)) {
    return false;
  }

  return phyId.oui == EXPECTED_OUI && phyId.model == EXPECTED_MODEL;
}

bool KSZ8091Phy::decodeOperationMode(uint16_t phyControl1,
                                     OperationMode *mode) {
  if (mode == nullptr) {
    return false;
  }

  if ((phyControl1 & PHY_CONTROL_1_LINK_STATUS) == 0) {
    *mode = OperationModeAutoNegotiating;
    return true;
  }

  const uint16_t rawMode = phyControl1 & PHY_CONTROL_1_OPERATION_MODE_MASK;

  switch (rawMode) {
  case OperationModeAutoNegotiating:
  case OperationMode10Half:
  case OperationMode100Half:
  case OperationMode10Full:
  case OperationMode100Full:
    *mode = static_cast<OperationMode>(rawMode);
    break;
  default:
    *mode = OperationModeReserved;
    break;
  }

  return true;
}

EthernetPhyLinkSpeed
KSZ8091Phy::speedForOperationMode(OperationMode mode) {
  switch (mode) {
  case OperationMode10Half:
  case OperationMode10Full:
    return EthernetPhySpeed10M;
  case OperationMode100Half:
  case OperationMode100Full:
    return EthernetPhySpeed100M;
  default:
    return EthernetPhySpeedUnknown;
  }
}

EthernetPhyDuplex KSZ8091Phy::duplexForOperationMode(OperationMode mode) {
  switch (mode) {
  case OperationMode10Half:
  case OperationMode100Half:
    return EthernetPhyHalfDuplex;
  case OperationMode10Full:
  case OperationMode100Full:
    return EthernetPhyFullDuplex;
  default:
    return EthernetPhyDuplexUnknown;
  }
}

bool KSZ8091Phy::resolvedModeRegister(uint8_t *registerAddress) const {
  if (registerAddress == nullptr) {
    return false;
  }

  *registerAddress = PHY_CONTROL_1_REGISTER;
  return true;
}

bool KSZ8091Phy::resolveVendorLinkMode(uint16_t registerValue,
                                       EthernetPhyLinkSpeed *speed,
                                       EthernetPhyDuplex *duplex) const {
  if (speed == nullptr || duplex == nullptr) {
    return false;
  }

  OperationMode mode = OperationModeReserved;
  if (!decodeOperationMode(registerValue, &mode)) {
    return false;
  }

  *speed = speedForOperationMode(mode);
  *duplex = duplexForOperationMode(mode);
  return *speed != EthernetPhySpeedUnknown &&
         *duplex != EthernetPhyDuplexUnknown;
}

EthernetPhyLinkSpeed KSZ8091Phy::linkSpeed() const {
  OperationMode mode = OperationModeReserved;

  if (!readOperationMode(&mode)) {
    return EthernetPhySpeedUnknown;
  }

  return speedForOperationMode(mode);
}

EthernetPhyDuplex KSZ8091Phy::duplex() const {
  OperationMode mode = OperationModeReserved;

  if (!readOperationMode(&mode)) {
    return EthernetPhyDuplexUnknown;
  }

  return duplexForOperationMode(mode);
}

bool KSZ8091Phy::configureInterrupts(uint16_t mask) {
  return writeRegister(INTERRUPT_CONTROL_STATUS_REGISTER,
                       static_cast<uint16_t>((mask & kInterruptStatusMask)
                                             << kInterruptEnableShift));
}

bool KSZ8091Phy::readInterruptStatus(uint16_t *status) const {
  if (status == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(INTERRUPT_CONTROL_STATUS_REGISTER, &value)) {
    return false;
  }

  *status = value & kInterruptStatusMask;
  return true;
}

bool KSZ8091Phy::clearInterruptStatus(uint16_t *status) const {
  uint16_t scratch = 0;
  return readInterruptStatus(status == nullptr ? &scratch : status);
}

bool KSZ8091Phy::setInterruptActiveHigh(bool activeHigh) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2InterruptLevel, activeHigh);
}

bool KSZ8091Phy::setRmii50MHzClockMode(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2RmiiReferenceClockSelect, enabled);
}

bool KSZ8091Phy::readOperationMode(OperationMode *mode) const {
  if (mode == nullptr) {
    return false;
  }

  uint16_t control = 0;

  if (!readRegister(PHY_CONTROL_1_REGISTER, &control)) {
    return false;
  }

  return decodeOperationMode(control, mode);
}

bool KSZ8091Phy::readStrapStatus(StrapStatus *status) const {
  if (status == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(OPERATION_MODE_STRAP_STATUS_REGISTER, &value)) {
    return false;
  }

  status->phyAddress =
      static_cast<uint8_t>((value & kStrapStatusPhyAddressMask) >>
                           kStrapStatusPhyAddressShift);
  status->rmii = (value & kStrapStatusRmii) != 0;
  return true;
}

bool KSZ8091Phy::setPmeEnabled(bool enabled) {
  return readModifyWrite(*this, OPERATION_MODE_STRAP_OVERRIDE_REGISTER,
                         kStrapOverridePmeEnable, enabled);
}

bool KSZ8091Phy::setPhyAddress0IsUnique(bool enabled) {
  return readModifyWrite(*this, OPERATION_MODE_STRAP_OVERRIDE_REGISTER,
                         kStrapOverridePhyAddress0Unique, enabled);
}

bool KSZ8091Phy::setRmiiOverride(bool enabled) {
  return readModifyWrite(*this, OPERATION_MODE_STRAP_OVERRIDE_REGISTER,
                         kStrapOverrideRmii, enabled);
}

bool KSZ8091Phy::setRmiiBackToBackOverride(bool enabled) {
  return readModifyWrite(*this, OPERATION_MODE_STRAP_OVERRIDE_REGISTER,
                         kStrapOverrideRmiiBackToBack, enabled);
}

bool KSZ8091Phy::setHpAutoMdiMdiX(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2HpAutoMdiMdiX, enabled);
}

bool KSZ8091Phy::setAutoMdiMdiXEnabled(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2PairSwapDisable, !enabled);
}

bool KSZ8091Phy::setMdiMode(MdiMode mode) {
  if (mode != MdiModeMdi && mode != MdiModeMdiX) {
    return false;
  }

  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2MdiMdiXSelect, mode == MdiModeMdiX);
}

bool KSZ8091Phy::setForceLink(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER, kPhyControl2ForceLink,
                         enabled);
}

bool KSZ8091Phy::setPowerSaving(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2PowerSaving, enabled);
}

bool KSZ8091Phy::setJabberEnabled(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2JabberEnable, enabled);
}

bool KSZ8091Phy::setLedMode(LedMode mode) {
  if (mode != LedModeLinkActivity && mode != LedModeLink) {
    return false;
  }

  return writeBits(*this, PHY_CONTROL_2_REGISTER, kPhyControl2LedModeMask,
                   static_cast<uint16_t>(mode) << kPhyControl2LedModeShift);
}

bool KSZ8091Phy::setTransmitterEnabled(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2TransmitterDisable, !enabled);
}

bool KSZ8091Phy::setRemoteLoopbackEnabled(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2RemoteLoopback, enabled);
}

bool KSZ8091Phy::setDataScramblingEnabled(bool enabled) {
  return readModifyWrite(*this, PHY_CONTROL_2_REGISTER,
                         kPhyControl2DataScramblingDisable, !enabled);
}

bool KSZ8091Phy::setEnergyDetectPowerDownEnabled(bool enabled) {
  return readModifyWrite(*this, EXPANDED_CONTROL_REGISTER,
                         kExpandedControlEdpdDisabled, !enabled);
}

bool KSZ8091Phy::set10BaseTPreambleRestore(bool enabled) {
  return readModifyWrite(*this, EXPANDED_CONTROL_REGISTER,
                         kExpandedControl10BaseTPreambleRestore, enabled);
}

bool KSZ8091Phy::startLinkMd() {
  return setAutoMdiMdiXEnabled(false) &&
         writeRegister(LINKMD_CONTROL_STATUS_REGISTER, kLinkMdStart);
}

bool KSZ8091Phy::readLinkMdStatus(LinkMdStatus *status) const {
  if (status == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(LINKMD_CONTROL_STATUS_REGISTER, &value)) {
    return false;
  }

  status->complete = (value & kLinkMdStart) == 0;
  status->result = static_cast<LinkMdResult>((value & kLinkMdResultMask) >>
                                             kLinkMdResultShift);
  status->shortCable = (value & kLinkMdShortCable) != 0;
  status->faultCounter = value & kLinkMdFaultCounterMask;
  return true;
}

bool KSZ8091Phy::readLinkMdReport(uint16_t *report) const {
  if (report == nullptr) {
    return false;
  }

  LinkMdReport decoded = {};

  if (!readLinkMdReport(&decoded)) {
    return false;
  }

  *report = decoded.packed;
  return true;
}

bool KSZ8091Phy::readLinkMdReport(LinkMdReport *report) const {
  if (report == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(LINKMD_CONTROL_STATUS_REGISTER, &value)) {
    return false;
  }

  const LinkMdResult result = static_cast<LinkMdResult>(
      (value & kLinkMdResultMask) >> kLinkMdResultShift);
  uint16_t packed = static_cast<uint16_t>(result) << 14;

  if (result == LinkMdOpen || result == LinkMdShort) {
    packed |= value & kLinkMdFaultCounterMask;
  }

  report->packed = packed;
  report->distanceMeters =
      (result == LinkMdOpen || result == LinkMdShort)
          ? static_cast<float>(value & kLinkMdFaultCounterMask) * 0.38f
          : 0.0f;
  return true;
}

bool KSZ8091Phy::set100BaseTXEeeAdvertisement(bool enabled) {
  uint16_t value = 0;

  if (!readMmd(EEE_MMD_DEVICE_ADDRESS, EEE_ADVERTISEMENT_REGISTER, &value)) {
    return false;
  }

  if (enabled) {
    value |= kEee100BaseTX;
  } else {
    value &= static_cast<uint16_t>(~kEee100BaseTX);
  }

  return writeMmd(EEE_MMD_DEVICE_ADDRESS, EEE_ADVERTISEMENT_REGISTER, value);
}

bool KSZ8091Phy::read100BaseTXEeeAdvertisement(bool *enabled) {
  if (enabled == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readMmd(EEE_MMD_DEVICE_ADDRESS, EEE_ADVERTISEMENT_REGISTER, &value)) {
    return false;
  }

  *enabled = (value & kEee100BaseTX) != 0;
  return true;
}

bool KSZ8091Phy::linkPartner100BaseTXEeeCapable(bool *capable) {
  if (capable == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readMmd(EEE_MMD_DEVICE_ADDRESS,
               EEE_LINK_PARTNER_ADVERTISEMENT_REGISTER, &value)) {
    return false;
  }

  *capable = (value & kEee100BaseTX) != 0;
  return true;
}

bool KSZ8091Phy::setLpiEnabled(bool enabled) {
  uint16_t value = 0;

  if (!readMmd(PMA_PMD_MMD_DEVICE_ADDRESS, PMA_PMD_CONTROL_1_REGISTER,
               &value)) {
    return false;
  }

  if (enabled) {
    value |= kPmaPmdControlLpiEnable;
  } else {
    value &= static_cast<uint16_t>(~kPmaPmdControlLpiEnable);
  }

  return writeMmd(PMA_PMD_MMD_DEVICE_ADDRESS, PMA_PMD_CONTROL_1_REGISTER,
                  value);
}

bool KSZ8091Phy::readLpiStatus(LpiStatus *status) {
  if (status == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readMmd(PMA_PMD_MMD_DEVICE_ADDRESS, PMA_PMD_STATUS_1_REGISTER,
               &value)) {
    return false;
  }

  status->entered = (value & kPmaPmdStatusLpiEntered) != 0;
  status->active = (value & kPmaPmdStatusLpiActive) != 0;
  return true;
}

bool KSZ8091Phy::setMagicPacketWakeEnabled(bool enabled) {
  uint16_t value = 0;

  if (!readMmd(WOL_MMD_DEVICE_ADDRESS, WOL_CONTROL_REGISTER, &value)) {
    return false;
  }

  if (enabled) {
    value |= kWolMagicPacketDetectEnable;
  } else {
    value &= static_cast<uint16_t>(~kWolMagicPacketDetectEnable);
  }

  return writeMmd(WOL_MMD_DEVICE_ADDRESS, WOL_CONTROL_REGISTER, value);
}

bool KSZ8091Phy::readMagicPacketWakeEnabled(bool *enabled) {
  if (enabled == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readMmd(WOL_MMD_DEVICE_ADDRESS, WOL_CONTROL_REGISTER, &value)) {
    return false;
  }

  *enabled = (value & kWolMagicPacketDetectEnable) != 0;
  return true;
}

bool KSZ8091Phy::setMagicPacketMacAddress(const uint8_t mac[6]) {
  if (mac == nullptr) {
    return false;
  }

  const uint16_t da0 =
      static_cast<uint16_t>(mac[0]) | (static_cast<uint16_t>(mac[1]) << 8);
  const uint16_t da1 =
      static_cast<uint16_t>(mac[2]) | (static_cast<uint16_t>(mac[3]) << 8);
  const uint16_t da2 =
      static_cast<uint16_t>(mac[4]) | (static_cast<uint16_t>(mac[5]) << 8);

  return writeMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_0_REGISTER,
                  da0) &&
         writeMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_1_REGISTER,
                  da1) &&
         writeMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_2_REGISTER,
                  da2);
}

bool KSZ8091Phy::readMagicPacketMacAddress(uint8_t mac[6]) {
  if (mac == nullptr) {
    return false;
  }

  uint16_t da0 = 0;
  uint16_t da1 = 0;
  uint16_t da2 = 0;

  if (!readMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_0_REGISTER,
               &da0) ||
      !readMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_1_REGISTER,
               &da1) ||
      !readMmd(WOL_MMD_DEVICE_ADDRESS, WOL_MAGIC_PACKET_MAC_DA_2_REGISTER,
               &da2)) {
    return false;
  }

  mac[0] = static_cast<uint8_t>(da0 & 0xFFu);
  mac[1] = static_cast<uint8_t>((da0 >> 8) & 0xFFu);
  mac[2] = static_cast<uint8_t>(da1 & 0xFFu);
  mac[3] = static_cast<uint8_t>((da1 >> 8) & 0xFFu);
  mac[4] = static_cast<uint8_t>(da2 & 0xFFu);
  mac[5] = static_cast<uint8_t>((da2 >> 8) & 0xFFu);
  return true;
}

#endif /* ETHERNET_HARDWARE_AVAILABLE */
