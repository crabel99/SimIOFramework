#pragma once

/**
 * @file PhyLinkManager.h
 * @brief Bounded PHY link, interrupt, and autonegotiation coordinator.
 *
 * `PhyLinkManager` owns the Linux phylib / Harmony ETHPHY-style coordination
 * layer for this Ethernet library: selected PHY object, queued MIIM operations,
 * cached link/carrier state, PHY interrupt dispatch, and GMAC speed/duplex
 * reconfiguration. It does not own Ethernet frames, MAC address programming,
 * sockets, IP addressing, or lwIP packet lifetimes.
 *
 * Runtime link management requires a board-wired PHY interrupt pin. The
 * manager does not contain a hidden polling fallback; boards without a PHY IRQ
 * must request explicit bounded refreshes from application/service code until
 * a separate polling monitor is designed.
 *
 * Link-status refresh follows the Harmony ETHPHY correctness pattern for
 * Clause-22 BMSR's latched-low link bit: a refreshed read that reports link
 * down is confirmed with one additional BMSR read before cached carrier state
 * is changed to down.
 *
 * PHY software reset is explicit. `requestPhyReset()` queues a bounded BMCR
 * reset write and invalidates cached link state on completion; setup
 * verification does not reset the external PHY implicitly.
 */

#include <GMAC.h>
#include <utility/miim/MiimManager.h>
#include <utility/phy/Phy.h>

#include <stdint.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE

enum EthernetLinkStatus {
  LinkOFF = 0,
  LinkON = 1,
  Unknown = 2,
};

enum EthernetPhySetupState {
  PhySetupIdle = 0,
  PhySetupResetting,
  PhySetupScanning,
  PhySetupReadingId1,
  PhySetupReadingId2,
  PhySetupClearingInterruptStatus,
  PhySetupConfiguringInterrupts,
  PhySetupVerified,
  PhySetupInvalidId,
  PhySetupScanNotFound,
  PhySetupFailed,
};

enum EthernetLinkRefreshState {
  LinkRefreshIdle = 0,
  LinkRefreshReadingStatus,
  LinkRefreshAutoNegotiationActive,
  LinkRefreshAutoNegotiationUnsupported,
  LinkRefreshReadingVendorMode,
  LinkRefreshReadingAdvertisement,
  LinkRefreshReadingPartnerAbility,
  LinkRefreshLinkDown,
  LinkRefreshResolved,
  LinkRefreshUnresolved,
  LinkRefreshVendorModeResolved,
  LinkRefreshVendorModeUnresolved,
  LinkRefreshFailed,
};

class PhyLinkManager {
public:
  using LinkChangeCallback = void (*)(EthernetLinkStatus status,
                                      EthernetPhyLinkSpeed speed,
                                      EthernetPhyDuplex duplex,
                                      void *context);
  using CarrierCallback = void (*)(bool carrierUp, void *context);

  explicit PhyLinkManager(EthernetPhy &phy);
  ~PhyLinkManager();

  EthernetLinkStatus linkStatus() const;
  EthernetPhyLinkSpeed linkSpeed() const;
  EthernetPhyDuplex duplex() const;
  bool carrierUp() const;
  EthernetLinkRefreshState linkRefreshState() const;
  EthernetPhySetupState phySetupState() const;

  /**
   * @brief Replace the selected PHY object.
   *
   * Clears pending MIIM/link state, resets cached carrier to unknown, and
   * rebinds the existing board interrupt callback when one is attached. The
   * caller owns the PHY object lifetime.
   */
  void setPhy(EthernetPhy &phy);
  EthernetPhy *phy() const;

  /**
   * @brief Configure MIIM management and register the PHY PendSV service.
   *
   * This is hardware setup. It does not reset or verify the external PHY; use
   * `requestPhyReset()` and `requestPhySetup()` explicitly for those steps.
   */
  bool begin();

  /**
   * @brief Apply cached resolved speed/duplex to GMAC.
   *
   * Does not read PHY registers or call synchronous PHY helpers. Returns false
   * if cached link state is not fully resolved.
   */
  bool updateLinkConfiguration();

  /**
   * @brief Queue a bounded asynchronous link refresh.
   *
   * Reads BMSR through `MiimManager`, confirms link-down with one additional
   * BMSR read, resolves autonegotiation through advertisement/partner ability,
   * and applies resolved speed/duplex to GMAC. Returns false if refresh work is
   * already pending or the first MIIM operation cannot be queued.
   */
  bool requestLinkRefresh();

  /**
   * @brief Queue an explicit bounded PHY software reset.
   *
   * Writes BMCR reset through `MiimManager`, invalidates cached link state on
   * completion, and returns setup state to idle. Rejected while setup,
   * link-refresh, or PHY interrupt-status work is active.
   */
  bool requestPhyReset();

  /**
   * @brief Queue selected-PHY verification or broadcast-address discovery.
   *
   * Fixed addresses queue PHY ID1/ID2 reads. Broadcast address queues a bounded
   * Clause-22 scan over 0..31, binds the discovered address, then verifies ID2
   * through the selected PHY object. If a PHY interrupt is already attached,
   * setup clears stale vendor interrupt status before enabling the interrupt
   * mask.
   */
  bool requestPhySetup();

  /**
   * @brief Schedule PHY interrupt work from ISR context.
   *
   * Marks either vendor interrupt-status work or a generic link refresh and
   * sets the PHY PendSV channel. It never performs MIIM work directly.
   */
  void requestLinkRefreshFromIsr();

  /**
   * @brief Attach the board PHY interrupt GPIO.
   *
   * Configures the pin as input pull-up, attaches the Arduino interrupt, binds
   * the selected PHY callback, and queues setup/interrupt-mask work when
   * appropriate. Automatic runtime link-change detection requires this path.
   */
  bool setPhyInterruptPin(uint32_t pin, uint32_t mode);

  /**
   * @brief Detach the board PHY interrupt GPIO and disable PHY IRQ sources.
   *
   * Clears deferred interrupt requests, removes the PHY callback, detaches the
   * GPIO interrupt, and queues a zero vendor interrupt mask when the PHY is
   * verified and idle.
   */
  void clearPhyInterruptPin();

  /**
   * @brief Advance one bounded MIIM management step.
   */
  bool service();

  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();
  void setCarrierCallback(CarrierCallback callback, void *context = nullptr);
  void clearCarrierCallback();

private:
  EthernetPhy *_phy;
  EthernetLinkStatus _linkStatus;
  EthernetPhyLinkSpeed _linkSpeed;
  EthernetPhyDuplex _duplex;
  LinkChangeCallback _linkChangeCallback;
  void *_linkChangeCallbackContext;
  CarrierCallback _carrierCallback;
  void *_carrierCallbackContext;
  MiimManager _miim;
  bool _phySetupPending;
  EthernetPhySetupState _phySetupState;
  bool _linkRefreshPending;
  EthernetLinkRefreshState _linkRefreshState;
  bool _linkStatusConfirmingDown;
  volatile bool _linkRefreshRequested;
  volatile bool _phyInterruptStatusRequested;
  bool _phyInterruptStatusPending;
  bool _phyInterruptAttached;
  uint32_t _phyInterruptPin;
  uint32_t _phyInterruptMode;
  uint16_t _phyId1;
  uint16_t _phyInterruptEvents;
  uint16_t _linkAdvertisement;

  bool ensurePhyPendSvServiceRegistered();
  void clearPhyInterruptPin(bool disablePhyInterrupts);
  bool updateCachedLink(EthernetLinkStatus status, EthernetPhyLinkSpeed speed,
                        EthernetPhyDuplex duplex);
  bool queuePhyId1Read();
  bool queuePhyId2Read();
  bool queuePhyResetWrite();
  bool queuePhyScan();
  bool queuePhyInterruptClearRead();
  bool queuePhyInterruptEnableWrite();
  bool queuePhyInterruptDisableWrite();
  bool queuePhyInterruptStatusRead();
  bool queueLinkStatusRead();
  bool queueVendorModeRead();
  bool queueLinkAdvertisementRead();
  bool queueLinkPartnerAbilityRead();
  void handlePhyId1Read(MiimManager::OperationHandle handle,
                        MiimManager::OperationResult result, uint16_t value);
  void handlePhyScanRead(MiimManager::OperationHandle handle,
                         MiimManager::OperationResult result, uint16_t value);
  void handlePhyId2Read(MiimManager::OperationHandle handle,
                        MiimManager::OperationResult result, uint16_t value);
  void handlePhyResetWrite(MiimManager::OperationHandle handle,
                           MiimManager::OperationResult result,
                           uint16_t value);
  void handlePhyInterruptClearRead(MiimManager::OperationHandle handle,
                                   MiimManager::OperationResult result,
                                   uint16_t value);
  void handlePhyInterruptEnableWrite(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value);
  void handlePhyInterruptStatusRead(MiimManager::OperationHandle handle,
                                    MiimManager::OperationResult result,
                                    uint16_t value);
  bool handlePhyInterruptEvents(uint16_t events);
  bool handlePhyLinkDownInterrupt();
  bool handlePhyLinkUpInterrupt();
  bool handlePhyAutoNegotiationCompleteInterrupt();
  void handleLinkStatusRead(MiimManager::OperationHandle handle,
                            MiimManager::OperationResult result,
                            uint16_t value);
  void handleVendorModeRead(MiimManager::OperationHandle handle,
                            MiimManager::OperationResult result,
                            uint16_t value);
  void handleLinkAdvertisementRead(MiimManager::OperationHandle handle,
                                   MiimManager::OperationResult result,
                                   uint16_t value);
  void handleLinkPartnerAbilityRead(MiimManager::OperationHandle handle,
                                    MiimManager::OperationResult result,
                                    uint16_t value);
  static void handlePhyId1Read(MiimManager::OperationHandle handle,
                               MiimManager::OperationResult result,
                               uint16_t value, void *context);
  static void handlePhyScanRead(MiimManager::OperationHandle handle,
                                MiimManager::OperationResult result,
                                uint16_t value, void *context);
  static void handlePhyId2Read(MiimManager::OperationHandle handle,
                               MiimManager::OperationResult result,
                               uint16_t value, void *context);
  static void handlePhyResetWrite(MiimManager::OperationHandle handle,
                                  MiimManager::OperationResult result,
                                  uint16_t value, void *context);
  static void handlePhyInterruptClearRead(
      MiimManager::OperationHandle handle, MiimManager::OperationResult result,
      uint16_t value, void *context);
  static void handlePhyInterruptEnableWrite(
      MiimManager::OperationHandle handle, MiimManager::OperationResult result,
      uint16_t value, void *context);
  static void handlePhyInterruptStatusRead(
      MiimManager::OperationHandle handle, MiimManager::OperationResult result,
      uint16_t value, void *context);
  static void handleLinkStatusRead(MiimManager::OperationHandle handle,
                                   MiimManager::OperationResult result,
                                   uint16_t value, void *context);
  static void handleVendorModeRead(MiimManager::OperationHandle handle,
                                   MiimManager::OperationResult result,
                                   uint16_t value, void *context);
  static void handleLinkAdvertisementRead(MiimManager::OperationHandle handle,
                                          MiimManager::OperationResult result,
                                          uint16_t value, void *context);
  static void handleLinkPartnerAbilityRead(MiimManager::OperationHandle handle,
                                           MiimManager::OperationResult result,
                                           uint16_t value, void *context);
  static void handlePhyPendSv(uint8_t serviceId, void *context);
  static void handlePhyInterrupt();
  static void handlePhyInterruptCallback(void *context);
};

#endif /* ETHERNET_HARDWARE_AVAILABLE */
