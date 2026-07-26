#pragma once

/**
 * @file GMAC.h
 * @brief SAME5x GMAC peripheral driver and raw MDIO controller primitives.
 *
 * This core driver owns the SAM E5x GMAC hardware block: MAC registers,
 * descriptor rings, RX/TX DMA ownership, frame interrupts, PendSV event
 * dispatch, MAC filtering, statistics, recovery, and the MDIO controller.
 *
 * It intentionally stops at the MAC/MDIO-controller boundary. External PHY
 * policy, link negotiation, IP addressing, lwIP objects, TCP, UDP, TLS, and
 * Arduino network client/server APIs belong to the Ethernet library layers.
 */

#include "PendSV.h"
#include "sam.h"

#include <stdint.h>

#if defined(GMAC_REGS)
#define ETHERNET_HARDWARE_AVAILABLE
#define GMAC_PERIPH (reinterpret_cast<uintptr_t>(GMAC_REGS))
#endif /* GMAC_REGS */

#ifdef ETHERNET_HARDWARE_AVAILABLE
/**
 * @brief SAME5x GMAC hardware driver.
 *
 * Contract:
 * - Owns frame DMA descriptor rings and raw Ethernet frame movement.
 * - Captures interrupt status quickly, schedules bounded PendSV work, and
 *   reports coalesced events through a registered callback.
 * - Separates RX/TX recovery events from ordinary completion events so the
 *   Ethernet coordinator can clear queues or retry at the right layer.
 * - Provides blocking MDIO helpers only for explicit setup/diagnostics and
 *   non-blocking MDIO start/complete primitives for runtime management.
 * - Does not interpret PHY register meaning or own network-stack state.
 */
class gmac {
public:
  using EventMask = uint32_t;

  /**
   * @brief Deferred GMAC event callback.
   *
   * The callback runs from the PendSV service path, not directly from the GMAC
   * ISR. Implementations must remain bounded and must not wait for future
   * hardware state.
   */
  using EventCallback = void (*)(EventMask events, void *context);

  /**
   * @brief GMAC DMA descriptor storage.
   */
  struct Descriptor {
    volatile uint32_t word0;
    volatile uint32_t word1;
  };

  /**
   * @brief One immutable TX frame fragment.
   */
  struct TransmitFragment {
    const uint8_t *buffer;
    uint16_t length;
  };

  /**
   * @brief Snapshot of GMAC receive/transmit status registers.
   */
  struct Status {
    uint32_t receiveStatus;
    uint32_t transmitStatus;
  };

  /**
   * @brief Snapshot of GMAC hardware statistics counters.
   */
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

  /**
   * @brief Receive filtering and frame-acceptance options.
   */
  struct ReceiveOptions {
    bool checksumOffload = false;
    bool removeFrameCheckSequence = false;
    bool ignoreFrameCheckSequence = false;
    bool discardLengthFieldErrors = false;
    bool accept1536ByteFrames = false;
    bool jumboFrames = false;
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
    EventRxRecovered = 1u << 4,
    EventTxRecovered = 1u << 5,
  };

  enum LinkSpeed : uint8_t {
    LinkSpeed10M,
    LinkSpeed100M,
  };

  static bool available();
  inline static uintptr_t baseAddress() { return GMAC_PERIPH; }
  static int irqNumber();
  static constexpr uint8_t pendSvServiceId();
  /**
   * @brief Default maximum MDC clock rate for Clause-22 PHY management.
   */
  static constexpr uint32_t DefaultMaxMdcHz = 2500000UL;

  /**
   * @brief Configure GMAC management clocking for MDIO/MDC access.
   *
   * @param mckHz GMAC host clock frequency.
   * @param maxMdcHz Maximum MDC clock rate accepted by the attached PHY.
   *
   * This is setup policy only. Runtime MIIM reads and writes must still use the
   * non-blocking start/complete path through `MiimManager`.
   */
  static bool beginManagement(uint32_t mckHz = F_CPU,
                              uint32_t maxMdcHz = DefaultMaxMdcHz);

  /**
   * @brief Return true when the GMAC management interface is idle.
   */
  static bool isManagementIdle();

  /**
   * @brief Apply resolved link speed and duplex to the MAC.
   */
  static void configureLink(LinkSpeed speed, bool fullDuplex);
  static void configureReceiveOptions(const ReceiveOptions &options);
  static void setPromiscuousMode(bool enabled);
  static void setBroadcastReception(bool enabled);
  static bool hashIndexForAddress(const uint8_t mac[6], uint8_t *index);
  static bool multicastHashForAddress(const uint8_t mac[6], uint32_t *bottom,
                                      uint32_t *top);
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
  static bool recoverReceive();
  static bool recoverTransmit();
  static Statistics statistics();
  static void clearStatistics();
  static bool queueTransmitBuffer(const uint8_t *buffer, uint16_t length);
  static bool queueTransmitFrame(const TransmitFragment *fragments,
                                 uint8_t fragmentCount);
  static uint8_t reclaimTransmitDescriptors();
  static uint8_t lastReclaimedTransmitDescriptors();
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
#if defined(UNIT_TEST)
  static void scheduleErrorForTest(const Status &status);
  static void forceManagementBusyForTest(bool busy);
  static void forceTransmitBusyForTest(bool busy);
#endif
  static void handleInterrupt();

  /**
   * @brief Blocking Clause-22 MDIO read for setup and diagnostics only.
   *
   * Runtime link management must use `mdioReadStart()` and
   * `mdioReadComplete()` through `MiimManager` instead of this helper.
   */
  static bool mdioRead(uint8_t phyAddress, uint8_t registerAddress,
                       uint16_t *value);

  /**
   * @brief Blocking Clause-22 MDIO write for setup and diagnostics only.
   *
   * Runtime link management must use `mdioWriteStart()` through `MiimManager`
   * instead of this helper.
   */
  static bool mdioWrite(uint8_t phyAddress, uint8_t registerAddress,
                        uint16_t value);

  /**
   * @brief Start a non-blocking Clause-22 MDIO read.
   */
  static bool mdioReadStart(uint8_t phyAddress, uint8_t registerAddress);

  /**
   * @brief Complete a non-blocking Clause-22 MDIO read when management is idle.
   */
  static bool mdioReadComplete(uint16_t *value);

  /**
   * @brief Start a non-blocking Clause-22 MDIO write.
   */
  static bool mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                             uint16_t value);
};

constexpr uint8_t gmac::pendSvServiceId() { return PendSVChannels::Gmac; }
#endif /* ETHERNET_HARDWARE_AVAILABLE */
