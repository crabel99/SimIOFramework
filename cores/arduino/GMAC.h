#pragma once

#include "sam.h"

#include <stdint.h>

#if defined(GMAC_REGS)
#define ETHERNET_HARDWARE_AVAILABLE
#define GMAC_PERIPH (reinterpret_cast<uintptr_t>(GMAC_REGS))
#endif /* GMAC_REGS */

#ifdef ETHERNET_HARDWARE_AVAILABLE
class gmac {
public:
  static bool available();
  inline static uintptr_t baseAddress() { return GMAC_PERIPH; }
  static int irqNumber();
  static bool beginManagement(uint32_t mckHz = F_CPU);
  static bool isManagementIdle();
  static void setMacAddress(const uint8_t mac[6]);
  static void getMacAddress(uint8_t mac[6]);
  static bool mdioRead(uint8_t phyAddress, uint8_t registerAddress,
                       uint16_t *value);
  static bool mdioWrite(uint8_t phyAddress, uint8_t registerAddress,
                        uint16_t value);
  static bool mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                             uint16_t value);
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
