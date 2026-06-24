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

  struct TransmitFragment {
    const uint8_t *buffer;
    uint16_t length;
  };

  struct Status {
    uint32_t receiveStatus;
    uint32_t transmitStatus;
  };

  struct Statistics {
    uint64_t transmitOctets;
    uint32_t transmitFrames;
    uint32_t transmitBroadcastFrames;
    uint32_t transmitMulticastFrames;
    uint32_t transmitPauseFrames;
    uint32_t transmitUnderruns;
    uint32_t transmitSingleCollisionFrames;
    uint32_t transmitMultipleCollisionFrames;
    uint32_t transmitExcessiveCollisions;
    uint32_t transmitLateCollisions;
    uint32_t transmitDeferredFrames;
    uint32_t transmitCarrierSenseErrors;
    uint64_t receiveOctets;
    uint32_t receiveFrames;
    uint32_t receiveBroadcastFrames;
    uint32_t receiveMulticastFrames;
    uint32_t receivePauseFrames;
    uint32_t receiveUndersizeFrames;
    uint32_t receiveOversizeFrames;
    uint32_t receiveJabbers;
    uint32_t receiveFcsErrors;
    uint32_t receiveLengthFieldErrors;
    uint32_t receiveSymbolErrors;
    uint32_t receiveAlignmentErrors;
    uint32_t receiveResourceErrors;
    uint32_t receiveOverruns;
    uint32_t receiveIpHeaderChecksumErrors;
    uint32_t receiveTcpChecksumErrors;
    uint32_t receiveUdpChecksumErrors;
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
  static void setPromiscuousMode(bool enabled);
  static void setBroadcastReception(bool enabled);
  static void setHashFilter(uint32_t bottom, uint32_t top,
                            bool multicastEnabled, bool unicastEnabled);
  static void clearHashFilter();
  static bool configureFrameBuffers(Descriptor *rxDescriptors,
                                    uint8_t rxDescriptorCount,
                                    uint8_t *rxBuffers, uint16_t rxBufferSize,
                                    Descriptor *txDescriptors,
                                    uint8_t txDescriptorCount);
  static void enableFrameIo();
  static void disableFrameIo();
  static Status status();
  static void clearReceiveStatus(uint32_t mask);
  static void clearTransmitStatus(uint32_t mask);
  static void clearStatus(uint32_t receiveMask, uint32_t transmitMask);
  static Statistics statistics();
  static void clearStatistics();
  static bool queueTransmitBuffer(const uint8_t *buffer, uint16_t length);
  static bool queueTransmitFrame(const TransmitFragment *fragments,
                                 uint8_t fragmentCount);
  static uint8_t reclaimTransmitDescriptors();
  static bool receivedFrameSize(uint16_t *length);
  static bool peekReceivedFrame(uint8_t **buffer, uint16_t *length);
  static bool readReceivedFrame(uint8_t *buffer, uint16_t capacity,
                                uint16_t *length);
  static bool releaseReceivedFrame();
  static bool discardReceivedFrame();
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
