#pragma once

/**
 * @file Phy.h
 * @brief Generic IEEE 802.3 Clause-22 Ethernet PHY model.
 *
 * `EthernetPhy` owns generic external PHY register behavior and decode helpers
 * above the GMAC MDIO controller. The synchronous helpers in this file are for
 * explicit setup, configuration, discovery, and diagnostics. Runtime link
 * monitoring must use the bounded MIIM/link-management path rather than
 * calling these helpers from RX/TX frame service.
 */

#include <stdint.h>
#include <GMAC.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE
/**
 * @brief Resolved PHY link speed.
 */
enum EthernetPhyLinkSpeed {
  EthernetPhySpeedUnknown = 0,
  EthernetPhySpeed10M = 10,
  EthernetPhySpeed100M = 100,
};

/**
 * @brief Resolved PHY duplex mode.
 */
enum EthernetPhyDuplex {
  EthernetPhyDuplexUnknown = 0,
  EthernetPhyHalfDuplex = 1,
  EthernetPhyFullDuplex = 2,
};

/**
 * @brief Generic PHY interrupt events surfaced to the Ethernet coordinator.
 */
enum EthernetPhyInterruptEvent : uint16_t {
  EthernetPhyInterruptLinkUp = 1u << 0,
  EthernetPhyInterruptLinkDown = 1u << 1,
  EthernetPhyInterruptAutoNegotiationComplete = 1u << 2,
  EthernetPhyInterruptRemoteFault = 1u << 3,
  EthernetPhyInterruptError = 1u << 4,
};

/**
 * @brief Decoded PHY identifier from Clause-22 ID registers.
 */
struct EthernetPhyId {
  uint32_t raw;
  uint32_t oui;
  uint8_t model;
  uint8_t revision;
};

/**
 * @brief Generic Clause-22 PHY capability bits.
 */
struct EthernetPhyCapabilities {
  bool extendedStatus;
  bool autoNegotiation;
  bool tenBaseTHalf;
  bool tenBaseTFull;
  bool hundredBaseTXHalf;
  bool hundredBaseTXFull;
  bool hundredBaseT4;
};

/**
 * @brief Decoded auto-negotiation expansion register.
 */
struct EthernetPhyAutoNegotiationExpansion {
  bool linkPartnerAutoNegotiationAble;
  bool pageReceived;
  bool nextPageAble;
  bool linkPartnerNextPageAble;
  bool parallelDetectionFault;
};

/**
 * @brief Decoded auto-negotiation advertisement or partner ability register.
 */
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

/**
 * @brief Decoded extended status register.
 */
struct EthernetPhyExtendedStatus {
  bool thousandBaseXFull;
  bool thousandBaseXHalf;
  bool thousandBaseTFull;
  bool thousandBaseTHalf;
};

/**
 * @brief Generic IEEE 802.3 Clause-22 PHY controlled through GMAC MDIO/MDC.
 *
 * This class implements the common MII register behavior shared by compliant
 * PHYs. Board- or vendor-specific PHYs should derive from this class and
 * override only the endpoints that require vendor registers, such as resolved
 * speed/duplex, interrupt setup, strap status, LED modes, diagnostics, or EEE.
 *
 * A board package can expose a child PHY and pass it into EthernetClass:
 *
 * @code
 *   KSZ8091Phy phy(0);
 *   EthernetClass ethernet(mac, phy);
 * @endcode
 *
 * Contract:
 * - Owns generic PHY address, identification, capability decode,
 *   advertisement, reset/configuration helpers, and diagnostic register access.
 * - Synchronous methods may block on MDIO and are allowed only at explicit
 *   setup/configuration/diagnostic boundaries.
 * - Runtime Ethernet RX/TX service and callbacks must not call these
 *   synchronous helpers.
 * - Vendor subclasses own chip-specific ID matching, interrupt status/ack,
 *   strap/clock/MDIX/EEE/WOL/diagnostic quirks, and vendor register decode.
 *   Vendor interrupt support layers onto the generic callback path by
 *   overriding interrupt register, mask encode, and status decode hooks; it
 *   must not replace the MAC/PHY coordinator or perform MDIO from the ISR.
 * - MAC speed/duplex application belongs to `EthernetClass`, not this class.
 */
class EthernetPhy {
public:
  static constexpr uint8_t BROADCAST_ADDRESS = 0xFF;

  using InterruptCallback = void (*)(void *context);

  EthernetPhy(uint8_t address = 0)
      : _address(address), _interruptCallback(nullptr),
        _interruptCallbackContext(nullptr) {}
  virtual ~EthernetPhy() = default;

  /**
   * @brief Return the configured or detected PHY address.
   */
  uint8_t address() const { return _address; }

  /**
   * @brief Set the configured or detected PHY address.
   *
   * Accepts Clause-22 addresses 0..31 and `BROADCAST_ADDRESS`. Runtime
   * discovery uses this after the bounded MIIM scan resolves the real address.
   */
  bool setAddress(uint8_t address);

  /**
   * @brief Verify or detect a PHY using already-configured management access.
   *
   * The caller must configure the MIIM/GMAC management controller first, either
   * through `MiimManager::setup()` or an explicit setup/diagnostic call to
   * `gmac::beginManagement()`. This method is synchronous setup work and must
   * not be called from the runtime frame path.
   */
  virtual bool begin();

  /**
   * @brief Apply generic PHY configuration.
   */
  virtual bool configure();

  /**
   * @brief Scan Clause-22 PHY addresses and retain the first valid address.
   */
  virtual bool detect();

  /**
   * @brief Request a PHY reset through the synchronous setup/diagnostic path.
   *
   * This writes the Clause-22 BMCR reset bit using the blocking register helper.
   * Runtime reset policy belongs in the bounded PHY management state machine,
   * not in Ethernet frame RX/TX service.
   */
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

  /**
   * @brief Blocking Clause-22 register read for setup/diagnostics.
   */
  bool readRegister(uint8_t registerAddress, uint16_t *value) const;

  /**
   * @brief Blocking Clause-22 register write for setup/diagnostics.
   */
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

  /**
   * @brief Return true when a decoded PHY ID is acceptable for this PHY object.
   *
   * Generic PHYs accept any nonzero, non-all-ones Clause-22 ID. Vendor PHYs
   * should override this to enforce expected OUI/model matching without forcing
   * runtime setup code to perform synchronous ID reads.
   */
  virtual bool acceptsPhyId(const EthernetPhyId &phyId) const;

  /**
   * @brief Decode the Clause-22 basic status link bit.
   *
   * This helper exists so Ethernet coordination code does not need to know the
   * BMSR bit layout. Callers are still responsible for the standard latched-low
   * double-read behavior when reading the register from hardware.
   */
  static bool basicStatusReportsLinkUp(uint16_t basicStatus);

  /**
   * @brief Resolve speed and duplex from advertised Clause-22 abilities.
   *
   * The priority order follows IEEE 802.3 auto-negotiation preference for the
   * 10/100 modes supported by this stack: 100/full, 100/half, 10/full,
   * 10/half. Returns false when no common supported mode is present.
   */
  static bool resolveAutoNegotiatedLink(uint16_t localAdvertisement,
                                        uint16_t partnerAbility,
                                        EthernetPhyLinkSpeed *speed,
                                        EthernetPhyDuplex *duplex);

  /**
   * @brief Return the vendor register used for async resolved-mode reads.
   *
   * Generic Clause-22 PHYs do not define a resolved fixed-mode register. Vendor
   * PHYs can override this so `EthernetClass` may queue a non-blocking MIIM
   * read when auto-negotiation is unsupported or bypassed.
   */
  virtual bool resolvedModeRegister(uint8_t *registerAddress) const;

  /**
   * @brief Decode a vendor resolved-mode register value.
   *
   * Returns false when the value does not describe a usable speed/duplex mode.
   * The base implementation has no vendor register and always returns false.
   */
  virtual bool resolveVendorLinkMode(uint16_t registerValue,
                                     EthernetPhyLinkSpeed *speed,
                                     EthernetPhyDuplex *duplex) const;

  /**
   * @brief Return the vendor interrupt control/status register.
   *
   * Generic Clause-22 does not define a common interrupt register. Vendor PHYs
   * override this so `EthernetClass` can queue async MIIM interrupt
   * configuration and acknowledgement without knowing vendor register numbers.
   */
  virtual bool interruptControlStatusRegister(uint8_t *registerAddress) const;

  /**
   * @brief Encode generic interrupt events for the vendor register write path.
   */
  virtual bool encodeInterruptEnable(uint16_t events,
                                     uint16_t *registerValue) const;

  /**
   * @brief Decode vendor interrupt status bits into generic interrupt events.
   */
  virtual bool decodeInterruptStatus(uint16_t registerValue,
                                     uint16_t *events) const;

  /**
   * @brief Register the callback invoked by board-level PHY interrupt wiring.
   *
   * `EthernetClass` owns the MCU pin attachment. The selected PHY owns this
   * callback endpoint so board interrupt notification flows through the PHY
   * object before deferred MIIM work is scheduled.
   */
  void setInterruptCallback(InterruptCallback callback, void *context);

  /**
   * @brief Clear the registered PHY interrupt callback.
   */
  void clearInterruptCallback();

  /**
   * @brief Notify the selected PHY object that its interrupt pin fired.
   *
   * Safe for ISR use when the registered callback is ISR-safe.
   */
  void notifyInterruptFromIsr();

  /**
   * @brief Synchronous generic link-status helper.
   *
   * Runtime link monitoring should prefer the bounded MIIM/link-refresh state
   * machine rather than polling this helper.
   */
  virtual bool linkUp() const;

  /**
   * @brief Synchronous resolved speed helper.
   *
   * Generic Clause-22 does not always expose resolved speed directly, so the
   * base implementation returns `EthernetPhySpeedUnknown`. Vendor PHYs may
   * override this for explicit diagnostics/configuration reads.
   */
  virtual EthernetPhyLinkSpeed linkSpeed() const;

  /**
   * @brief Synchronous resolved duplex helper.
   *
   * Generic Clause-22 does not always expose resolved duplex directly, so the
   * base implementation returns `EthernetPhyDuplexUnknown`. Vendor PHYs may
   * override this for explicit diagnostics/configuration reads.
   */
  virtual EthernetPhyDuplex duplex() const;

  /**
   * @brief Configure vendor PHY interrupt mask when supported.
   */
  virtual bool configureInterrupts(uint16_t mask);

protected:
  bool updateBasicControl(uint16_t mask, bool enabled);

  uint8_t _address;
  InterruptCallback _interruptCallback;
  void *_interruptCallbackContext;
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
