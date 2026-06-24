#pragma once

#include "PendSV.h"
#include "sam.h"

#include <stdint.h>

#if defined(GMAC_REGS)
#define ETHERNET_HARDWARE_AVAILABLE
#define GMAC_PERIPH (reinterpret_cast<uintptr_t>(GMAC_REGS))
#endif /* GMAC_REGS */

#ifdef ETHERNET_HARDWARE_AVAILABLE
class gmac {
public:
  using EventMask = uint32_t;
  using EventCallback = void (*)(EventMask events, void *context);

  enum Event : EventMask {
    EventNone = 0,
    EventRxReady = 1u << 0,
    EventTxComplete = 1u << 1,
    EventManagementComplete = 1u << 2,
    EventError = 1u << 3,
  };

  static bool available();
  inline static uintptr_t baseAddress() { return GMAC_PERIPH; }
  static int irqNumber();
  static constexpr uint8_t pendSvServiceId();
  static bool beginManagement(uint32_t mckHz = F_CPU);
  static bool isManagementIdle();
  static void setMacAddress(const uint8_t mac[6]);
  static void getMacAddress(uint8_t mac[6]);
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  static void clearEventCallback();
  static EventMask pendingEvents();
  static void scheduleEvent(EventMask events);
  static void handleInterrupt();
  static bool mdioRead(uint8_t phyAddress, uint8_t registerAddress,
                       uint16_t *value);
  static bool mdioWrite(uint8_t phyAddress, uint8_t registerAddress,
                        uint16_t value);
  static bool mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                             uint16_t value);
};

constexpr uint8_t gmac::pendSvServiceId() { return PendSVChannels::Gmac; }
#endif /* ETHERNET_HARDWARE_AVAILABLE */
