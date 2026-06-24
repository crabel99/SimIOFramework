#pragma once

#include <GMAC.h>
#include <utility/miim/MiimManager.h>
#include <utility/phy/Phy.h>

#include <stdint.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE

enum EthernetHardwareStatus {
  EthernetNoHardware = 0,
  EthernetGmac = 1,
};

enum EthernetLinkStatus {
  LinkOFF = 0,
  LinkON = 1,
  Unknown = 2,
};

class EthernetClass {
public:
  using FrameReceiveCallback = void (*)(const uint8_t *frame, uint16_t length,
                                        void *context);
  using LinkChangeCallback = void (*)(EthernetLinkStatus status,
                                      EthernetPhyLinkSpeed speed,
                                      EthernetPhyDuplex duplex,
                                      void *context);
  using CarrierCallback = void (*)(bool carrierUp, void *context);
  using MdioCallback = EthernetMiimManager::Callback;

  /**
   * Create an Ethernet coordinator using the default generic IEEE PHY.
   *
   * Board packages or user code can provide a vendor-specific child of
   * EthernetPhy with the overloads that accept EthernetPhy&.
   */
  EthernetClass();
  explicit EthernetClass(const uint8_t mac[6]);
  explicit EthernetClass(EthernetPhy &phy);
  EthernetClass(const uint8_t mac[6], EthernetPhy &phy);

  EthernetHardwareStatus hardwareStatus() const;
  EthernetLinkStatus linkStatus() const;
  EthernetPhyLinkSpeed linkSpeed() const;
  EthernetPhyDuplex duplex() const;
  bool carrierUp() const;
  /**
   * Select the PHY implementation used by EthernetClass.
   *
   * The argument is stored by pointer. Pass a long-lived object; stack objects
   * must outlive EthernetClass and any Ethernet operation.
   */
  void setPhy(EthernetPhy &phy);
  EthernetPhy *phy() const;
  bool setMacAddress(const uint8_t mac[6]);
  void macAddress(uint8_t mac[6]) const;
  bool updateLinkConfiguration();
  bool requestLinkRefresh();
  void requestLinkRefreshFromIsr();
  bool setPhyInterruptPin(uint32_t pin, uint32_t mode);
  void clearPhyInterruptPin();
  bool service();
  bool queueMdioRead(uint8_t registerAddress, MdioCallback callback,
                     void *context = nullptr);
  bool queueMdioWrite(uint8_t registerAddress, uint16_t value,
                      MdioCallback callback = nullptr,
                      void *context = nullptr);
  void configureReceiveOptions(const gmac::ReceiveOptions &options);
  void setPromiscuousMode(bool enabled);
  void setBroadcastReception(bool enabled);
  void setHashFilter(uint32_t bottom, uint32_t top, bool multicastEnabled,
                     bool unicastEnabled);
  void clearHashFilter();
  gmac::Status status() const;
  void clearStatus(uint32_t receiveMask, uint32_t transmitMask);
  gmac::Statistics statistics() const;
  void clearStatistics();
  void setFrameReceiveCallback(FrameReceiveCallback callback,
                               void *context = nullptr);
  void clearFrameReceiveCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();
  void setCarrierCallback(CarrierCallback callback, void *context = nullptr);
  void clearCarrierCallback();
  bool frameAvailable(uint16_t *length = nullptr);
  bool readFrame(uint8_t *buffer, uint16_t capacity, uint16_t *length);
  bool writeFrame(const uint8_t *buffer, uint16_t length);
  bool discardFrame();
  int begin();
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

  EthernetMiimManager _miim;
  bool _linkRefreshPending;
  volatile bool _linkRefreshRequested;
  bool _phyInterruptAttached;
  uint32_t _phyInterruptPin;
  uint32_t _phyInterruptMode;
  uint16_t _linkAdvertisement;

  bool updateCachedLink(EthernetLinkStatus status, EthernetPhyLinkSpeed speed,
                        EthernetPhyDuplex duplex);
  void handleGmacEvents(gmac::EventMask events);
  void handleLinkStatusRead(bool success, uint16_t value);
  void handleLinkAdvertisementRead(bool success, uint16_t value);
  void handleLinkPartnerAbilityRead(bool success, uint16_t value);
  static void handleGmacEvents(gmac::EventMask events, void *context);
  static void handleLinkStatusRead(bool success, uint16_t value,
                                   void *context);
  static void handleLinkAdvertisementRead(bool success, uint16_t value,
                                          void *context);
  static void handleLinkPartnerAbilityRead(bool success, uint16_t value,
                                           void *context);
  static void handlePhyInterrupt();
};

extern EthernetClass Ethernet;
#endif /* ETHERNET_HARDWARE_AVAILABLE */
