#pragma once

#include <GMAC.h>
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
  int begin();
  int begin(const uint8_t *mac);

private:
  uint8_t _mac[6];
  bool _hasMac;
  bool _begun;
  EthernetPhy *_phy;
};

extern EthernetClass Ethernet;
#endif /* ETHERNET_HARDWARE_AVAILABLE */
