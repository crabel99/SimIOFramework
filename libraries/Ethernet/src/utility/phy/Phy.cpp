#include "Phy.h"
#include "PhyRegisters.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>

namespace {
void decodeAutoNegotiationAbility(
    uint16_t value, EthernetPhyAutoNegotiationAbility *ability) {
  ability->selector = static_cast<uint8_t>(value & PhyRegAnad::mask::Selector);
  ability->tenBaseTHalf = (value & PhyRegAnad::bit::TenBaseTHalf) != 0;
  ability->tenBaseTFull = (value & PhyRegAnad::bit::TenBaseTFull) != 0;
  ability->hundredBaseTXHalf = (value & PhyRegAnad::bit::HundredBaseTXHalf) != 0;
  ability->hundredBaseTXFull = (value & PhyRegAnad::bit::HundredBaseTXFull) != 0;
  ability->hundredBaseT4 = (value & PhyRegAnad::bit::HundredBaseT4) != 0;
  ability->pause =
      static_cast<uint8_t>((value & PhyRegAnad::mask::Pause) >> PhyRegAnad::shift::Pause);
  ability->remoteFault = (value & PhyRegAnad::bit::RemoteFault) != 0;
  ability->acknowledge = (value & PhyRegAnad::bit::Acknowledge) != 0;
  ability->nextPage = (value & PhyRegAnad::bit::NextPage) != 0;
}

uint16_t encodeAutoNegotiationAbility(
    const EthernetPhyAutoNegotiationAbility &ability) {
  uint16_t value = ability.selector & PhyRegAnad::mask::Selector;

  if (ability.tenBaseTHalf) {
    value |= PhyRegAnad::bit::TenBaseTHalf;
  }
  if (ability.tenBaseTFull) {
    value |= PhyRegAnad::bit::TenBaseTFull;
  }
  if (ability.hundredBaseTXHalf) {
    value |= PhyRegAnad::bit::HundredBaseTXHalf;
  }
  if (ability.hundredBaseTXFull) {
    value |= PhyRegAnad::bit::HundredBaseTXFull;
  }
  if (ability.hundredBaseT4) {
    value |= PhyRegAnad::bit::HundredBaseT4;
  }
  value |= static_cast<uint16_t>((ability.pause & 0x03u) << PhyRegAnad::shift::Pause);
  if (ability.remoteFault) {
    value |= PhyRegAnad::bit::RemoteFault;
  }
  if (ability.acknowledge) {
    value |= PhyRegAnad::bit::Acknowledge;
  }
  if (ability.nextPage) {
    value |= PhyRegAnad::bit::NextPage;
  }

  return value;
}
} // namespace

bool EthernetPhy::begin() {
  if (!gmac::beginManagement()) {
    return false;
  }

  if (_address == BROADCAST_ADDRESS) {
    return detect();
  }

  if (_address > 31) {
    return false;
  }

  uint32_t phyId = 0;
  return readId(&phyId) && phyId != 0 && phyId != 0xFFFFFFFFUL;
}

bool EthernetPhy::configure() { return true; }

bool EthernetPhy::detect() {
  for (uint8_t address = 0; address < 32; ++address) {
    EthernetPhy candidate(address);
    uint32_t phyId = 0;

    if (candidate.readId(&phyId) && phyId != 0 && phyId != 0xFFFFFFFFUL) {
      _address = address;
      return true;
    }
  }

  return false;
}

bool EthernetPhy::updateBasicControl(uint16_t mask, bool enabled) {
  uint16_t control = 0;

  if (!readBasicControl(&control)) {
    return false;
  }

  if (enabled) {
    control |= mask;
  } else {
    control &= static_cast<uint16_t>(~mask);
  }

  return writeRegister(PhyRegBmcon::addr, control);
}

bool EthernetPhy::reset() {
  return gmac::mdioWriteStart(_address, PhyRegBmcon::addr,
                              PhyRegBmcon::bit::Reset);
}

bool EthernetPhy::restartAutoNegotiation() {
  return updateBasicControl(PhyRegBmcon::bit::AutoNegotiationEnable |
                                PhyRegBmcon::bit::RestartAutoNegotiation,
                            true);
}

bool EthernetPhy::forceMode(EthernetPhyLinkSpeed speed,
                            EthernetPhyDuplex duplex) {
  if ((speed != EthernetPhySpeed10M && speed != EthernetPhySpeed100M) ||
      (duplex != EthernetPhyHalfDuplex && duplex != EthernetPhyFullDuplex)) {
    return false;
  }

  uint16_t control = 0;

  if (!readBasicControl(&control)) {
    return false;
  }

  control &= static_cast<uint16_t>(~(PhyRegBmcon::bit::AutoNegotiationEnable |
                                    PhyRegBmcon::bit::RestartAutoNegotiation |
                                    PhyRegBmcon::bit::SpeedSelect | PhyRegBmcon::bit::DuplexMode));

  if (speed == EthernetPhySpeed100M) {
    control |= PhyRegBmcon::bit::SpeedSelect;
  }
  if (duplex == EthernetPhyFullDuplex) {
    control |= PhyRegBmcon::bit::DuplexMode;
  }

  return writeRegister(PhyRegBmcon::addr, control);
}

bool EthernetPhy::setSpeed(EthernetPhyLinkSpeed speed) {
  if (speed != EthernetPhySpeed10M && speed != EthernetPhySpeed100M) {
    return false;
  }

  return updateBasicControl(PhyRegBmcon::bit::SpeedSelect, speed == EthernetPhySpeed100M);
}

bool EthernetPhy::setDuplex(EthernetPhyDuplex duplex) {
  if (duplex != EthernetPhyHalfDuplex && duplex != EthernetPhyFullDuplex) {
    return false;
  }

  return updateBasicControl(PhyRegBmcon::bit::DuplexMode, duplex == EthernetPhyFullDuplex);
}

bool EthernetPhy::setAutoNegotiationEnabled(bool enabled) {
  return updateBasicControl(PhyRegBmcon::bit::AutoNegotiationEnable, enabled);
}

bool EthernetPhy::setLoopbackEnabled(bool enabled) {
  return updateBasicControl(PhyRegBmcon::bit::Loopback, enabled);
}

bool EthernetPhy::setPowerDown(bool enabled) {
  return updateBasicControl(PhyRegBmcon::bit::PowerDown, enabled);
}

bool EthernetPhy::setIsolated(bool enabled) {
  return updateBasicControl(PhyRegBmcon::bit::Isolate, enabled);
}

bool EthernetPhy::setCollisionTestEnabled(bool enabled) {
  return updateBasicControl(PhyRegBmcon::bit::CollisionTest, enabled);
}

bool EthernetPhy::autoNegotiationSupported() const {
  uint16_t status = 0;

  if (!readBasicStatus(&status)) {
    return false;
  }

  return (status & PhyRegBmstat::bit::AutoNegotiationAbility) != 0;
}

bool EthernetPhy::autoNegotiationComplete() const {
  uint16_t status = 0;

  if (!readBasicStatus(&status)) {
    return false;
  }

  return (status & PhyRegBmstat::bit::AutoNegotiationComplete) != 0;
}

bool EthernetPhy::readRegister(uint8_t registerAddress, uint16_t *value) const {
  if (_address > 31) {
    return false;
  }

  return gmac::mdioRead(_address, registerAddress, value);
}

bool EthernetPhy::writeRegister(uint8_t registerAddress, uint16_t value) const {
  if (_address > 31) {
    return false;
  }

  return gmac::mdioWrite(_address, registerAddress, value);
}

bool EthernetPhy::readBasicControl(uint16_t *control) const {
  if (control == nullptr) {
    return false;
  }

  return readRegister(PhyRegBmcon::addr, control);
}

bool EthernetPhy::readBasicStatus(uint16_t *status) const {
  if (status == nullptr) {
    return false;
  }

  uint16_t first = 0;
  uint16_t second = 0;

  if (!readRegister(PhyRegBmstat::addr, &first) ||
      !readRegister(PhyRegBmstat::addr, &second)) {
    return false;
  }

  *status = second;
  return true;
}

bool EthernetPhy::readAutoNegotiationAdvertisement(
    uint16_t *advertisement) const {
  if (advertisement == nullptr) {
    return false;
  }

  return readRegister(PhyRegAnad::addr, advertisement);
}

bool EthernetPhy::readAutoNegotiationAdvertisement(
    EthernetPhyAutoNegotiationAbility *advertisement) const {
  if (advertisement == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readAutoNegotiationAdvertisement(&value)) {
    return false;
  }

  decodeAutoNegotiationAbility(value, advertisement);
  return true;
}

bool EthernetPhy::writeAutoNegotiationAdvertisement(uint16_t advertisement) {
  return writeRegister(PhyRegAnad::addr, advertisement);
}

bool EthernetPhy::writeAutoNegotiationAdvertisement(
    const EthernetPhyAutoNegotiationAbility &advertisement) {
  return writeAutoNegotiationAdvertisement(
      encodeAutoNegotiationAbility(advertisement));
}

bool EthernetPhy::advertiseCapabilities(
    const EthernetPhyCapabilities &capabilities, uint8_t pause) {
  EthernetPhyAutoNegotiationAbility advertisement = {};

  advertisement.selector = 1;
  advertisement.tenBaseTHalf = capabilities.tenBaseTHalf;
  advertisement.tenBaseTFull = capabilities.tenBaseTFull;
  advertisement.hundredBaseTXHalf = capabilities.hundredBaseTXHalf;
  advertisement.hundredBaseTXFull = capabilities.hundredBaseTXFull;
  advertisement.hundredBaseT4 = capabilities.hundredBaseT4;
  advertisement.pause = pause & 0x03u;

  return writeAutoNegotiationAdvertisement(advertisement);
}

bool EthernetPhy::advertiseAllSupported(uint8_t pause) {
  EthernetPhyCapabilities capabilities = {};

  if (!readCapabilities(&capabilities)) {
    return false;
  }

  return advertiseCapabilities(capabilities, pause);
}

bool EthernetPhy::advertiseAllSupportedAndRestart(uint8_t pause) {
  return advertiseAllSupported(pause) && restartAutoNegotiation();
}

bool EthernetPhy::readLinkPartnerAbility(uint16_t *ability) const {
  if (ability == nullptr) {
    return false;
  }

  return readRegister(PhyRegAnlpad::addr, ability);
}

bool EthernetPhy::readLinkPartnerAbility(
    EthernetPhyAutoNegotiationAbility *ability) const {
  if (ability == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readLinkPartnerAbility(&value)) {
    return false;
  }

  decodeAutoNegotiationAbility(value, ability);
  return true;
}

bool EthernetPhy::readAutoNegotiationExpansion(
    EthernetPhyAutoNegotiationExpansion *expansion) const {
  if (expansion == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(PhyRegAnexp::addr, &value)) {
    return false;
  }

  expansion->linkPartnerAutoNegotiationAble =
      (value & PhyRegAnexp::bit::LinkPartnerAutoNegotiationAble) != 0;
  expansion->pageReceived = (value & PhyRegAnexp::bit::PageReceived) != 0;
  expansion->nextPageAble = (value & PhyRegAnexp::bit::NextPageAble) != 0;
  expansion->linkPartnerNextPageAble =
      (value & PhyRegAnexp::bit::LinkPartnerNextPageAble) != 0;
  expansion->parallelDetectionFault =
      (value & PhyRegAnexp::bit::ParallelDetectionFault) != 0;
  return true;
}

bool EthernetPhy::readNextPage(uint16_t *nextPage) const {
  if (nextPage == nullptr) {
    return false;
  }

  return readRegister(PhyRegAnptr::addr, nextPage);
}

bool EthernetPhy::writeNextPage(uint16_t nextPage) {
  return writeRegister(PhyRegAnptr::addr, nextPage);
}

bool EthernetPhy::readLinkPartnerNextPage(uint16_t *nextPage) const {
  if (nextPage == nullptr) {
    return false;
  }

  return readRegister(PhyRegAnlprnp::addr,
                      nextPage);
}

bool EthernetPhy::readExtendedStatus(EthernetPhyExtendedStatus *status) const {
  if (status == nullptr) {
    return false;
  }

  uint16_t value = 0;

  if (!readRegister(PhyRegExtStat::addr, &value)) {
    return false;
  }

  status->thousandBaseXFull = (value & PhyRegExtStat::bit::ThousandBaseXFull) != 0;
  status->thousandBaseXHalf = (value & PhyRegExtStat::bit::ThousandBaseXHalf) != 0;
  status->thousandBaseTFull = (value & PhyRegExtStat::bit::ThousandBaseTFull) != 0;
  status->thousandBaseTHalf = (value & PhyRegExtStat::bit::ThousandBaseTHalf) != 0;
  return true;
}

bool EthernetPhy::readMmd(uint8_t deviceAddress, uint16_t registerAddress,
                          uint16_t *value) {
  if (value == nullptr || deviceAddress > PhyRegMmdControl::mask::DeviceAddress) {
    return false;
  }

  if (!writeRegister(PhyRegMmdControl::addr,
                     PhyRegMmdControl::bit::RegisterMode | deviceAddress) ||
      !writeRegister(PhyRegMmdData::addr, registerAddress) ||
      !writeRegister(PhyRegMmdControl::addr,
                     PhyRegMmdControl::bit::DataNoPostIncrement | deviceAddress) ||
      !readRegister(PhyRegMmdData::addr, value)) {
    return false;
  }

  return true;
}

bool EthernetPhy::writeMmd(uint8_t deviceAddress, uint16_t registerAddress,
                           uint16_t value) {
  if (deviceAddress > PhyRegMmdControl::mask::DeviceAddress) {
    return false;
  }

  if (!writeRegister(PhyRegMmdControl::addr,
                     PhyRegMmdControl::bit::RegisterMode | deviceAddress) ||
      !writeRegister(PhyRegMmdData::addr, registerAddress) ||
      !writeRegister(PhyRegMmdControl::addr,
                     PhyRegMmdControl::bit::DataNoPostIncrement | deviceAddress) ||
      !writeRegister(PhyRegMmdData::addr, value)) {
    return false;
  }

  return true;
}

bool EthernetPhy::readId(uint32_t *phyId) const {
  if (phyId == nullptr) {
    return false;
  }

  uint16_t id1 = 0;
  uint16_t id2 = 0;

  if (!readRegister(PHY_REG_PHYID1, &id1) ||
      !readRegister(PHY_REG_PHYID2, &id2)) {
    return false;
  }

  *phyId = (static_cast<uint32_t>(id1) << 16) | id2;
  return true;
}

bool EthernetPhy::readId(EthernetPhyId *phyId) const {
  if (phyId == nullptr) {
    return false;
  }

  uint32_t raw = 0;

  if (!readId(&raw)) {
    return false;
  }

  phyId->raw = raw;
  phyId->oui = (raw >> 10) & 0x00FFFFFFu;
  phyId->model = static_cast<uint8_t>((raw >> 4) & 0x3Fu);
  phyId->revision = static_cast<uint8_t>(raw & 0x0Fu);
  return true;
}

bool EthernetPhy::readCapabilities(
    EthernetPhyCapabilities *capabilities) const {
  if (capabilities == nullptr) {
    return false;
  }

  uint16_t status = 0;

  if (!readBasicStatus(&status)) {
    return false;
  }

  capabilities->extendedStatus = (status & PhyRegBmstat::bit::ExtendedStatus) != 0;
  capabilities->autoNegotiation =
      (status & PhyRegBmstat::bit::AutoNegotiationAbility) != 0;
  capabilities->tenBaseTHalf = (status & PhyRegBmstat::bit::TenBaseTHalf) != 0;
  capabilities->tenBaseTFull = (status & PhyRegBmstat::bit::TenBaseTFull) != 0;
  capabilities->hundredBaseTXHalf = (status & PhyRegBmstat::bit::HundredBaseTXHalf) != 0;
  capabilities->hundredBaseTXFull = (status & PhyRegBmstat::bit::HundredBaseTXFull) != 0;
  capabilities->hundredBaseT4 = (status & PhyRegBmstat::bit::HundredBaseT4) != 0;
  return true;
}

bool EthernetPhy::linkUp() const {
  uint16_t status = 0;

  if (!readBasicStatus(&status)) {
    return false;
  }

  return (status & PhyRegBmstat::bit::LinkStatus) != 0;
}

EthernetPhyLinkSpeed EthernetPhy::linkSpeed() const {
  return EthernetPhySpeedUnknown;
}

EthernetPhyDuplex EthernetPhy::duplex() const {
  return EthernetPhyDuplexUnknown;
}

bool EthernetPhy::configureInterrupts(uint16_t mask) {
  (void)mask;
  return false;
}

#endif /* ETHERNET_HARDWARE_AVAILABLE */
