#pragma once

/**
 * @file Ethernet.h
 * @brief SAME5x Ethernet MAC/PHY coordinator and low-level frame API.
 *
 * `EthernetClass` is the boundary between the SAME5x GMAC hardware driver,
 * the selected external PHY object, and higher Ethernet-library layers. It
 * owns hardware bring-up, raw frame RX/TX, cached link state, PHY interrupt
 * scheduling, MIIM link-refresh operations, and carrier/link callbacks.
 *
 * This file intentionally does not define TCP, UDP, DHCP, DNS, TLS, lwIP pbuf
 * ownership, or socket behavior. Those belong above this boundary.
 */

#include <GMAC.h>
#include <utility/miim/MiimManager.h>
#include <utility/phy/Phy.h>

#include <stdint.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE

/**
 * @brief Detected Ethernet hardware state.
 */
enum EthernetHardwareStatus {
  /// No supported Ethernet MAC hardware is visible.
  EthernetNoHardware = 0,
  /// SAME5x GMAC hardware is available.
  EthernetGmac = 1,
};

/**
 * @brief Cached Ethernet carrier/link state.
 */
enum EthernetLinkStatus {
  /// PHY reports link down or no carrier.
  LinkOFF = 0,
  /// PHY reports link up.
  LinkON = 1,
  /// Link state has not been resolved or a management operation failed.
  Unknown = 2,
};

/**
 * @brief Runtime PHY setup/verification state.
 *
 * This state describes the bounded management flow that verifies the selected
 * PHY address without calling synchronous PHY helpers from runtime service.
 */
enum EthernetPhySetupState {
  /// No runtime PHY setup has been requested or the state was reset.
  PhySetupIdle = 0,
  /// PHY address scan has been queued or is active.
  PhySetupScanning,
  /// PHY ID1 read has been queued or is active.
  PhySetupReadingId1,
  /// PHY ID2 read has been queued or is active.
  PhySetupReadingId2,
  /// PHY interrupt mask write has been queued or is active.
  PhySetupConfiguringInterrupts,
  /// PHY ID was read and accepted by the selected PHY object.
  PhySetupVerified,
  /// PHY ID was readable but rejected by the selected PHY object.
  PhySetupInvalidId,
  /// Address scan completed without finding a readable PHY ID1 register.
  PhySetupScanNotFound,
  /// PHY setup failed because a management operation failed or could not queue.
  PhySetupFailed,
};

/**
 * @brief Runtime PHY link-refresh state.
 *
 * This state describes the bounded management flow that updates cached link
 * status. It is intentionally separate from `EthernetLinkStatus`: link status
 * is the resolved carrier cache, while link-refresh state describes the
 * management operation currently in progress or the last terminal refresh
 * outcome.
 */
enum EthernetLinkRefreshState {
  /// No runtime link refresh has been requested or the state was reset.
  LinkRefreshIdle = 0,
  /// BMSR/link-status read has been queued or is active.
  LinkRefreshReadingStatus,
  /// Link is up, but auto-negotiation is still active.
  LinkRefreshAutoNegotiationActive,
  /// Link is up, but Clause-22 auto-negotiation is not available.
  LinkRefreshAutoNegotiationUnsupported,
  /// Vendor resolved-mode register read has been queued or is active.
  LinkRefreshReadingVendorMode,
  /// Local advertisement read has been queued or is active.
  LinkRefreshReadingAdvertisement,
  /// Link partner ability read has been queued or is active.
  LinkRefreshReadingPartnerAbility,
  /// Refresh completed and resolved link down.
  LinkRefreshLinkDown,
  /// Refresh completed and resolved link up speed/duplex.
  LinkRefreshResolved,
  /// Refresh completed with link up but unresolved speed/duplex.
  LinkRefreshUnresolved,
  /// Refresh completed and resolved link up through a vendor mode register.
  LinkRefreshVendorModeResolved,
  /// Refresh completed with link up but unresolved vendor mode.
  LinkRefreshVendorModeUnresolved,
  /// Refresh failed because a management operation failed or could not queue.
  LinkRefreshFailed,
};

/**
 * @brief Low-level Ethernet hardware coordinator.
 *
 * Contract:
 * - Owns the GMAC/PHY/MIIM coordination needed for raw Ethernet frames.
 * - Frame APIs are non-blocking: they return queued/available/failure state
 *   immediately and never wait for descriptor or PHY state to change.
 * - Link status APIs return cached state. Runtime refresh is scheduled through
 *   `requestLinkRefresh()`, a PHY interrupt, and bounded `service()` calls.
 * - PHY management is routed through `MiimManager`; synchronous PHY helpers are
 *   not used on the frame RX/TX path.
 * - Carrier and link callbacks notify upper layers when cached link state
 *   changes so stack code does not need to inspect PHY registers.
 *
 * `EthernetClass` is not a TCP/IP stack. It does not own sockets, IP
 * addresses, DHCP, DNS, TLS state, or lwIP packet lifetimes.
 */
class EthernetClass {
public:
  /**
   * @brief Callback for received raw Ethernet frames.
   *
   * The callback is invoked from GMAC event/PendSV service context. The frame
   * pointer is valid only for the duration of the callback. Registering this
   * callback makes the callback path own RX delivery; frames delivered this way
   * are not also queued for `readFrame()`.
   */
  using FrameReceiveCallback = void (*)(const uint8_t *frame, uint16_t length,
                                        void *context);

  /**
   * @brief Callback for resolved link-state changes.
   */
  using LinkChangeCallback = void (*)(EthernetLinkStatus status,
                                      EthernetPhyLinkSpeed speed,
                                      EthernetPhyDuplex duplex,
                                      void *context);

  /**
   * @brief Stack-facing carrier callback.
   *
   * The callback fires only when carrier transitions between up and not-up.
   */
  using CarrierCallback = void (*)(bool carrierUp, void *context);

  /**
   * @brief Create an Ethernet coordinator using the default generic IEEE PHY.
   *
   * Board packages or user code can provide a vendor-specific child of
   * `EthernetPhy` with the overloads that accept `EthernetPhy&`.
   */
  EthernetClass();

  /**
   * @brief Create an Ethernet coordinator with a MAC address.
   */
  explicit EthernetClass(const uint8_t mac[6]);

  /**
   * @brief Create an Ethernet coordinator with an explicit PHY object.
   */
  explicit EthernetClass(EthernetPhy &phy);

  /**
   * @brief Create an Ethernet coordinator with a MAC address and PHY object.
   */
  EthernetClass(const uint8_t mac[6], EthernetPhy &phy);

  /**
   * @brief Return whether the SAME5x GMAC hardware is available.
   */
  EthernetHardwareStatus hardwareStatus() const;

  /**
   * @brief Return cached link status.
   *
   * This does not read PHY registers. Use `requestLinkRefresh()` plus
   * `service()` or a configured PHY interrupt to update the cache.
   */
  EthernetLinkStatus linkStatus() const;

  /**
   * @brief Return cached resolved link speed.
   */
  EthernetPhyLinkSpeed linkSpeed() const;

  /**
   * @brief Return cached resolved duplex mode.
   */
  EthernetPhyDuplex duplex() const;

  /**
   * @brief Return true when cached link status is `LinkON`.
   */
  bool carrierUp() const;

  /**
   * @brief Return the runtime PHY link-refresh state.
   *
   * This is intended for stack coordination and tests that need to distinguish
   * pending management work from the cached resolved carrier state.
   */
  EthernetLinkRefreshState linkRefreshState() const;

  /**
   * @brief Return the runtime PHY setup state.
   */
  EthernetPhySetupState phySetupState() const;

  /**
   * @brief Select the PHY implementation used by `EthernetClass`.
   *
   * The argument is stored by pointer. Pass a long-lived object; stack objects
   * must outlive `EthernetClass` and any Ethernet operation.
   */
  void setPhy(EthernetPhy &phy);

  /**
   * @brief Return the selected PHY object.
   */
  EthernetPhy *phy() const;

  /**
   * @brief Set the local unicast MAC address.
   *
   * Rejects null, all-zero, all-ones, and multicast addresses.
   */
  bool setMacAddress(const uint8_t mac[6]);

  /**
   * @brief Copy the current local MAC address into `mac`.
   */
  void macAddress(uint8_t mac[6]) const;

  /**
   * @brief Apply cached link speed and duplex to GMAC.
   *
   * Returns false when link is down or speed/duplex is unresolved.
   */
  bool updateLinkConfiguration();

  /**
   * @brief Queue an asynchronous PHY link-state refresh.
   *
   * The refresh uses `MiimManager` reads and is advanced by `service()` or a
   * GMAC management-complete event. It returns false if a refresh is already
   * pending or the first MIIM operation could not be queued.
   */
  bool requestLinkRefresh();

  /**
   * @brief Queue asynchronous verification of the selected PHY address.
   *
   * If the selected PHY uses `EthernetPhy::BROADCAST_ADDRESS`, setup first
   * scans Clause-22 addresses 0..31 for a readable PHY ID1 register and binds
   * the discovered address to the PHY object. It then reads PHY ID2 and asks
   * the selected PHY object whether the decoded ID is acceptable.
   */
  bool requestPhySetup();

  /**
   * @brief Schedule a deferred link refresh from an interrupt.
   *
   * Safe for the PHY interrupt path; actual MIIM work happens later through the
   * GMAC/PendSV event path.
   */
  void requestLinkRefreshFromIsr();

  /**
   * @brief Attach a board PHY interrupt pin.
   *
   * The interrupt only schedules deferred link refresh work. It does not run
   * MIIM transactions directly inside the ISR.
   */
  bool setPhyInterruptPin(uint32_t pin, uint32_t mode);

  /**
   * @brief Detach the configured PHY interrupt pin.
   */
  void clearPhyInterruptPin();

  /**
   * @brief Advance pending MIIM/link-management work by one bounded step.
   */
  bool service();

  /**
   * @brief Configure GMAC receive filtering options.
   */
  void configureReceiveOptions(const gmac::ReceiveOptions &options);

  /**
   * @brief Enable or disable promiscuous receive mode.
   */
  void setPromiscuousMode(bool enabled);

  /**
   * @brief Enable or disable broadcast frame reception.
   */
  void setBroadcastReception(bool enabled);

  /**
   * @brief Program the GMAC hash filter registers and enable bits.
   */
  void setHashFilter(uint32_t bottom, uint32_t top, bool multicastEnabled,
                     bool unicastEnabled);

  /**
   * @brief Clear hash filtering.
   */
  void clearHashFilter();

  /**
   * @brief Return a snapshot of GMAC status registers.
   */
  gmac::Status status() const;

  /**
   * @brief Clear selected GMAC receive/transmit status bits.
   */
  void clearStatus(uint32_t receiveMask, uint32_t transmitMask);

  /**
   * @brief Return a snapshot of GMAC hardware statistics.
   */
  gmac::Statistics statistics() const;

  /**
   * @brief Clear GMAC hardware statistics counters.
   */
  void clearStatistics();

  /**
   * @brief Register a raw-frame receive callback.
   *
   * Registering a callback clears the polling receive queue. While registered,
   * received frames are delivered to the callback instead of being retained for
   * `readFrame()`.
   */
  void setFrameReceiveCallback(FrameReceiveCallback callback,
                               void *context = nullptr);

  /**
   * @brief Clear the raw-frame receive callback.
   */
  void clearFrameReceiveCallback();

  /**
   * @brief Register a callback for cached link-state changes.
   */
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);

  /**
   * @brief Clear the link-change callback.
   */
  void clearLinkChangeCallback();

  /**
   * @brief Register a carrier up/down callback for stack integration.
   */
  void setCarrierCallback(CarrierCallback callback, void *context = nullptr);

  /**
   * @brief Clear the carrier callback.
   */
  void clearCarrierCallback();

  /**
   * @brief Return whether a queued received frame is available.
   *
   * This only observes the bounded software RX queue used when no receive
   * callback is registered. It does not poll GMAC descriptors for new work.
   */
  bool frameAvailable(uint16_t *length = nullptr);

  /**
   * @brief Copy and remove the next queued received frame.
   *
   * Returns false immediately if no frame is queued or `capacity` is too small.
   * When capacity is too small, `length` receives the required frame length.
   */
  bool readFrame(uint8_t *buffer, uint16_t capacity, uint16_t *length);

  /**
   * @brief Queue one raw frame for GMAC transmission.
   *
   * Returns false immediately if Ethernet is not begun, the frame is invalid,
   * or the single TX staging buffer is already in use. TX completion is
   * reclaimed by GMAC events, not by polling from this call.
   */
  bool writeFrame(const uint8_t *buffer, uint16_t length);

  /**
   * @brief Drop the next queued received frame.
   */
  bool discardFrame();

  /**
   * @brief Initialize GMAC management and raw frame I/O.
   *
   * Requires available GMAC hardware, a valid MAC address, and a selected PHY.
   * This enables the raw frame path but does not perform blocking runtime link
   * polling.
   */
  int begin();

  /**
   * @brief Set the MAC address and initialize GMAC management/frame I/O.
   */
  int begin(const uint8_t *mac);

private:
  uint8_t _mac[6];
  bool _hasMac;
  bool _begun;
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
  volatile bool _linkRefreshRequested;
  volatile bool _phyInterruptStatusRequested;
  bool _phyInterruptStatusPending;
  bool _phyInterruptAttached;
  uint32_t _phyInterruptPin;
  uint32_t _phyInterruptMode;
  uint16_t _phyId1;
  uint16_t _phyInterruptEvents;
  uint16_t _linkAdvertisement;

  bool updateCachedLink(EthernetLinkStatus status, EthernetPhyLinkSpeed speed,
                        EthernetPhyDuplex duplex);
  bool queuePhyId1Read();
  bool queuePhyId2Read();
  bool queuePhyScan();
  bool queuePhyInterruptEnableWrite();
  bool queuePhyInterruptStatusRead();
  bool queueLinkStatusRead();
  bool queueVendorModeRead();
  bool queueLinkAdvertisementRead();
  bool queueLinkPartnerAbilityRead();
  void handleGmacEvents(gmac::EventMask events);
  void handlePhyId1Read(MiimManager::OperationHandle handle,
                        MiimManager::OperationResult result, uint16_t value);
  void handlePhyScanRead(MiimManager::OperationHandle handle,
                         MiimManager::OperationResult result, uint16_t value);
  void handlePhyId2Read(MiimManager::OperationHandle handle,
                        MiimManager::OperationResult result, uint16_t value);
  void handlePhyInterruptEnableWrite(MiimManager::OperationHandle handle,
                                     MiimManager::OperationResult result,
                                     uint16_t value);
  void handlePhyInterruptStatusRead(MiimManager::OperationHandle handle,
                                    MiimManager::OperationResult result,
                                    uint16_t value);
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
  static void handleGmacEvents(gmac::EventMask events, void *context);
  static void handlePhyId1Read(MiimManager::OperationHandle handle,
                               MiimManager::OperationResult result,
                               uint16_t value, void *context);
  static void handlePhyScanRead(MiimManager::OperationHandle handle,
                                MiimManager::OperationResult result,
                                uint16_t value, void *context);
  static void handlePhyId2Read(MiimManager::OperationHandle handle,
                               MiimManager::OperationResult result,
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
  static void handlePhyInterrupt();
  static void handlePhyInterruptCallback(void *context);
};

extern EthernetClass Ethernet;
#endif /* ETHERNET_HARDWARE_AVAILABLE */
