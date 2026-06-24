#pragma once

#include <stdint.h>
#include <GMAC.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE
enum EthernetPhyLinkSpeed {
  EthernetPhySpeedUnknown = 0,
  EthernetPhySpeed10M = 10,
  EthernetPhySpeed100M = 100,
};

enum EthernetPhyDuplex {
  EthernetPhyDuplexUnknown = 0,
  EthernetPhyHalfDuplex = 1,
  EthernetPhyFullDuplex = 2,
};

struct EthernetPhyId {
  uint32_t raw;
  uint32_t oui;
  uint8_t model;
  uint8_t revision;
};

struct EthernetPhyCapabilities {
  bool extendedStatus;
  bool autoNegotiation;
  bool tenBaseTHalf;
  bool tenBaseTFull;
  bool hundredBaseTXHalf;
  bool hundredBaseTXFull;
  bool hundredBaseT4;
};

struct EthernetPhyAutoNegotiationExpansion {
  bool linkPartnerAutoNegotiationAble;
  bool pageReceived;
  bool nextPageAble;
  bool linkPartnerNextPageAble;
  bool parallelDetectionFault;
};

struct EthernetPhyAutoNegotiationAbility {
  uint8_t selector;
  bool tenBaseTHalf;
  bool tenBaseTFull;
  bool hundredBaseTXHalf;
  bool hundredBaseTXFull;
  bool hundredBaseT4;
  uint8_t pause;
  bool remoteFault;
  bool acknowledge;
  bool nextPage;
};

struct EthernetPhyExtendedStatus {
  bool thousandBaseXFull;
  bool thousandBaseXHalf;
  bool thousandBaseTFull;
  bool thousandBaseTHalf;
};

/**
 * Generic IEEE 802.3 clause-22 PHY controlled through GMAC MDIO/MDC.
 *
 * This class implements the common MII register behavior shared by compliant
 * PHYs. Board- or vendor-specific PHYs should derive from this class and
 * override only the endpoints that require vendor registers, such as resolved
 * speed/duplex, interrupt setup, strap status, LED modes, diagnostics, or EEE.
 *
 * A board package can expose a child PHY and pass it into EthernetClass:
 *
 *   KSZ8091Phy phy(0);
 *   EthernetClass ethernet(mac, phy);
 */
class EthernetPhy {
public:
  static constexpr uint8_t BROADCAST_ADDRESS = 0xFF;

  EthernetPhy(uint8_t address = 0) : _address(address) {}
  virtual ~EthernetPhy() = default;

  uint8_t address() const { return _address; }
  virtual bool begin();
  virtual bool configure();
  virtual bool detect();
  virtual bool reset();
  virtual bool restartAutoNegotiation();
  virtual bool forceMode(EthernetPhyLinkSpeed speed, EthernetPhyDuplex duplex);
  virtual bool setSpeed(EthernetPhyLinkSpeed speed);
  virtual bool setDuplex(EthernetPhyDuplex duplex);
  virtual bool setAutoNegotiationEnabled(bool enabled);
  virtual bool setLoopbackEnabled(bool enabled);
  virtual bool setPowerDown(bool enabled);
  virtual bool setIsolated(bool enabled);
  virtual bool setCollisionTestEnabled(bool enabled);
  virtual bool autoNegotiationSupported() const;
  virtual bool autoNegotiationComplete() const;
  bool readRegister(uint8_t registerAddress, uint16_t *value) const;
  bool writeRegister(uint8_t registerAddress, uint16_t value) const;
  bool readBasicStatus(uint16_t *status) const;
  bool readBasicControl(uint16_t *control) const;
  bool readAutoNegotiationAdvertisement(uint16_t *advertisement) const;
  bool readAutoNegotiationAdvertisement(
      EthernetPhyAutoNegotiationAbility *advertisement) const;
  bool writeAutoNegotiationAdvertisement(uint16_t advertisement);
  bool writeAutoNegotiationAdvertisement(
      const EthernetPhyAutoNegotiationAbility &advertisement);
  bool advertiseCapabilities(const EthernetPhyCapabilities &capabilities,
                             uint8_t pause = 0);
  bool advertiseAllSupported(uint8_t pause = 0);
  bool advertiseAllSupportedAndRestart(uint8_t pause = 0);
  bool readLinkPartnerAbility(uint16_t *ability) const;
  bool readLinkPartnerAbility(EthernetPhyAutoNegotiationAbility *ability) const;
  bool readAutoNegotiationExpansion(
      EthernetPhyAutoNegotiationExpansion *expansion) const;
  bool readNextPage(uint16_t *nextPage) const;
  bool writeNextPage(uint16_t nextPage);
  bool readLinkPartnerNextPage(uint16_t *nextPage) const;
  bool readExtendedStatus(EthernetPhyExtendedStatus *status) const;
  bool readMmd(uint8_t deviceAddress, uint16_t registerAddress,
               uint16_t *value);
  bool writeMmd(uint8_t deviceAddress, uint16_t registerAddress,
                uint16_t value);
  bool readId(uint32_t *phyId) const;
  bool readId(EthernetPhyId *phyId) const;
  bool readCapabilities(EthernetPhyCapabilities *capabilities) const;
  virtual bool linkUp() const;
  virtual EthernetPhyLinkSpeed linkSpeed() const;
  virtual EthernetPhyDuplex duplex() const;
  virtual bool configureInterrupts(uint16_t mask);

protected:
  bool updateBasicControl(uint16_t mask, bool enabled);

  uint8_t _address;
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
