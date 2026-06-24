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

  struct Descriptor {
    volatile uint32_t word0;
    volatile uint32_t word1;
  };

  static constexpr uint32_t RxDescriptorOwnership = 1u << 0;
  static constexpr uint32_t RxDescriptorWrap = 1u << 1;
  static constexpr uint32_t RxDescriptorLengthMask = 0x00001FFFu;
  static constexpr uint32_t RxDescriptorStartOfFrame = 1u << 14;
  static constexpr uint32_t RxDescriptorEndOfFrame = 1u << 15;
  static constexpr uint32_t TxDescriptorLengthMask = 0x00003FFFu;
  static constexpr uint32_t TxDescriptorLastBuffer = 1u << 15;
  static constexpr uint32_t TxDescriptorWrap = 1u << 30;
  static constexpr uint32_t TxDescriptorUsed = 1u << 31;
  static constexpr uint16_t RxBufferSizeGranularity = 64;

  enum Event : EventMask {
    EventNone = 0,
    EventRxReady = 1u << 0,
    EventTxComplete = 1u << 1,
    EventManagementComplete = 1u << 2,
    EventError = 1u << 3,
  };

  enum LinkSpeed : uint8_t {
    LinkSpeed10M,
    LinkSpeed100M,
  };

  static bool available();
  inline static uintptr_t baseAddress() { return GMAC_PERIPH; }
  static int irqNumber();
  static constexpr uint8_t pendSvServiceId();
  static bool beginManagement(uint32_t mckHz = F_CPU);
  static bool isManagementIdle();
  static void configureLink(LinkSpeed speed, bool fullDuplex);
  static bool configureFrameBuffers(Descriptor *rxDescriptors,
                                    uint8_t rxDescriptorCount,
                                    uint8_t *rxBuffers, uint16_t rxBufferSize,
                                    Descriptor *txDescriptors,
                                    uint8_t txDescriptorCount);
  static void enableFrameIo();
  static void disableFrameIo();
  static bool queueTransmitBuffer(const uint8_t *buffer, uint16_t length);
  static uint8_t reclaimTransmitDescriptors();
  static bool peekReceivedFrame(uint8_t **buffer, uint16_t *length);
  static bool readReceivedFrame(uint8_t *buffer, uint16_t capacity,
                                uint16_t *length);
  static bool releaseReceivedFrame();
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
