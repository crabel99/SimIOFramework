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
  PhySetupScanning,
  PhySetupReadingId1,
  PhySetupReadingId2,
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

  void setPhy(EthernetPhy &phy);
  EthernetPhy *phy() const;

  bool begin();
  bool updateLinkConfiguration();
  bool requestLinkRefresh();
  bool requestPhySetup();
  void requestLinkRefreshFromIsr();
  bool setPhyInterruptPin(uint32_t pin, uint32_t mode);
  void clearPhyInterruptPin();
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
  bool queuePhyScan();
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
