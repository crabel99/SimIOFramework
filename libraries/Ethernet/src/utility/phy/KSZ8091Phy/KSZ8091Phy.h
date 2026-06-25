#pragma once

/**
 * @file KSZ8091Phy.h
 * @brief Microchip/Micrel KSZ8091 vendor PHY extension.
 *
 * This file owns KSZ8091-specific register decode and policy hooks layered on
 * top of the generic `EthernetPhy` Clause-22 behavior. It is the correct place
 * for KSZ8091 interrupt status/ack, RMII strap/clock policy, MDIX, EEE, WOL,
 * LinkMD diagnostics, and vendor resolved-mode reads.
 */

#include "../Phy.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
/**
 * @brief Microchip/Micrel KSZ8091 PHY driver.
 *
 * The SAM E54 Xplained Pro uses a KSZ8091RNACA PHY at MDIO address 0. This
 * child class demonstrates how board-specific PHY support plugs into
 * EthernetClass through the generic EthernetPhy parent. KSZ8091-specific
 * speed/duplex, interrupt, LED, strap, diagnostic, and EEE behavior should be
 * implemented here from the KSZ8091 datasheet rather than in EthernetPhy.
 *
 * Contract:
 * - Verify the expected PHY ID before accepting the device.
 * - Keep KSZ8091 vendor register operations in this class.
 * - Provide synchronous configuration/diagnostic helpers only for explicit
 *   setup, policy, and tests.
 * - Runtime carrier/link changes should be surfaced through PHY interrupt
 *   status plus the bounded Ethernet/MIIM link-refresh state machine, not by
 *   polling these helpers from the RX/TX frame path.
 */
class KSZ8091Phy : public EthernetPhy {
public:
  enum OperationMode {
    OperationModeAutoNegotiating = 0,
    OperationMode10Half = 1,
    OperationMode100Half = 2,
    OperationMode10Full = 5,
    OperationMode100Full = 6,
    OperationModeReserved = 7,
  };

  enum Interrupt : uint16_t {
    InterruptLinkUp = 1u << 0,
    InterruptRemoteFault = 1u << 1,
    InterruptLinkDown = 1u << 2,
    InterruptLinkPartnerAcknowledge = 1u << 3,
    InterruptParallelDetectFault = 1u << 4,
    InterruptPageReceived = 1u << 5,
    InterruptReceiveError = 1u << 6,
    InterruptJabber = 1u << 7,
  };

  enum LedMode {
    LedModeLinkActivity = 0,
    LedModeLink = 1,
  };

  enum MdiMode {
    MdiModeMdi = 0,
    MdiModeMdiX = 1,
  };

  enum LinkMdResult {
    LinkMdNormal = 0,
    LinkMdOpen = 1,
    LinkMdShort = 2,
    LinkMdFailed = 3,
  };

  struct StrapStatus {
    uint8_t phyAddress;
    bool rmii;
  };

  struct LinkMdStatus {
    bool complete;
    LinkMdResult result;
    bool shortCable;
    uint16_t faultCounter;
  };

  struct LinkMdReport {
    uint16_t packed;
    float distanceMeters;
  };

  struct LpiStatus {
    bool entered;
    bool active;
  };

  static constexpr uint8_t OPERATION_MODE_STRAP_OVERRIDE_REGISTER = 0x16;
  static constexpr uint8_t OPERATION_MODE_STRAP_STATUS_REGISTER = 0x17;
  static constexpr uint8_t EXPANDED_CONTROL_REGISTER = 0x18;
  static constexpr uint8_t INTERRUPT_CONTROL_STATUS_REGISTER = 0x1B;
  static constexpr uint8_t LINKMD_CONTROL_STATUS_REGISTER = 0x1D;
  static constexpr uint8_t PHY_CONTROL_1_REGISTER = 0x1E;
  static constexpr uint8_t PHY_CONTROL_2_REGISTER = 0x1F;
  static constexpr uint16_t PHY_CONTROL_1_LINK_STATUS = 1u << 8;
  static constexpr uint16_t PHY_CONTROL_1_OPERATION_MODE_MASK = 0x0007u;
  static constexpr uint8_t EEE_MMD_DEVICE_ADDRESS = 0x07;
  static constexpr uint8_t PMA_PMD_MMD_DEVICE_ADDRESS = 0x01;
  static constexpr uint8_t WOL_MMD_DEVICE_ADDRESS = 0x1F;
  static constexpr uint16_t PMA_PMD_CONTROL_1_REGISTER = 0x0000;
  static constexpr uint16_t PMA_PMD_STATUS_1_REGISTER = 0x0001;
  static constexpr uint16_t EEE_ADVERTISEMENT_REGISTER = 0x003C;
  static constexpr uint16_t EEE_LINK_PARTNER_ADVERTISEMENT_REGISTER = 0x003D;
  static constexpr uint16_t WOL_CONTROL_REGISTER = 0x0000;
  static constexpr uint16_t WOL_MAGIC_PACKET_MAC_DA_0_REGISTER = 0x0019;
  static constexpr uint16_t WOL_MAGIC_PACKET_MAC_DA_1_REGISTER = 0x001A;
  static constexpr uint16_t WOL_MAGIC_PACKET_MAC_DA_2_REGISTER = 0x001B;
  static constexpr uint32_t EXPECTED_OUI = 2181;
  static constexpr uint8_t EXPECTED_MODEL = 22;

  explicit KSZ8091Phy(uint8_t address = 0) : EthernetPhy(address) {}

  bool begin() override;
  bool configure() override;
  bool isExpectedPhy() const;
  bool acceptsPhyId(const EthernetPhyId &phyId) const override;

  /**
   * @brief Decode the KSZ8091 PHY Control 1 operation mode field.
   *
   * This is vendor-specific pure decode. `readOperationMode()` owns the MDIO
   * register read; this helper owns interpretation of the KSZ8091 register
   * layout so tests can enforce the vendor contract without live hardware.
   */
  static bool decodeOperationMode(uint16_t phyControl1, OperationMode *mode);

  /**
   * @brief Map a decoded KSZ8091 operation mode to generic link speed.
   */
  static EthernetPhyLinkSpeed speedForOperationMode(OperationMode mode);

  /**
   * @brief Map a decoded KSZ8091 operation mode to generic duplex.
   */
  static EthernetPhyDuplex duplexForOperationMode(OperationMode mode);

  bool resolvedModeRegister(uint8_t *registerAddress) const override;
  bool resolveVendorLinkMode(uint16_t registerValue,
                             EthernetPhyLinkSpeed *speed,
                             EthernetPhyDuplex *duplex) const override;
  EthernetPhyLinkSpeed linkSpeed() const override;
  EthernetPhyDuplex duplex() const override;
  bool configureInterrupts(uint16_t mask) override;
  bool readInterruptStatus(uint16_t *status) const;
  bool clearInterruptStatus(uint16_t *status = nullptr) const;
  bool setInterruptActiveHigh(bool activeHigh);
  bool setRmii50MHzClockMode(bool enabled);
  bool readOperationMode(OperationMode *mode) const;
  bool readStrapStatus(StrapStatus *status) const;
  bool setPmeEnabled(bool enabled);
  bool setPhyAddress0IsUnique(bool enabled);
  bool setRmiiOverride(bool enabled);
  bool setRmiiBackToBackOverride(bool enabled);
  bool setHpAutoMdiMdiX(bool enabled);
  bool setAutoMdiMdiXEnabled(bool enabled);
  bool setMdiMode(MdiMode mode);
  bool setForceLink(bool enabled);
  bool setPowerSaving(bool enabled);
  bool setJabberEnabled(bool enabled);
  bool setLedMode(LedMode mode);
  bool setTransmitterEnabled(bool enabled);
  bool setRemoteLoopbackEnabled(bool enabled);
  bool setDataScramblingEnabled(bool enabled);
  bool setEnergyDetectPowerDownEnabled(bool enabled);
  bool set10BaseTPreambleRestore(bool enabled);
  bool startLinkMd();
  bool readLinkMdStatus(LinkMdStatus *status) const;
  bool readLinkMdReport(LinkMdReport *report) const;
  bool readLinkMdReport(uint16_t *report) const;
  bool set100BaseTXEeeAdvertisement(bool enabled);
  bool read100BaseTXEeeAdvertisement(bool *enabled);
  bool linkPartner100BaseTXEeeCapable(bool *capable);
  bool setLpiEnabled(bool enabled);
  bool readLpiStatus(LpiStatus *status);
  bool setMagicPacketWakeEnabled(bool enabled);
  bool readMagicPacketWakeEnabled(bool *enabled);
  bool setMagicPacketMacAddress(const uint8_t mac[6]);
  bool readMagicPacketMacAddress(uint8_t mac[6]);
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
