#include "GMAC.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>
#include <PendSV.h>
#include <string.h>

/*
 * SAME5x GMAC DMA coherency policy:
 *
 * This driver currently targets SAME53/54 GMAC. These parts do not have a CPU
 * data cache covering SRAM descriptor rings or frame buffers, so descriptor and
 * frame-buffer cache clean/invalidate hooks are intentionally not present here.
 *
 * The barriers below are still required. They order CPU descriptor/status
 * writes and reads around ownership transitions with the GMAC DMA engine. If
 * this file is ever widened to a data-cache-capable target, do not just rely on
 * these barriers: add explicit CMSIS cache clean/invalidate operations for
 * descriptor rings and frame buffers before enabling that target.
 */

namespace {
constexpr uint32_t kMdioTimeoutMs = 10;
constexpr uint32_t kMdioWriteTen = 2;
constexpr uint32_t kMdioReadOperation = 2;
constexpr uint32_t kMdioWriteOperation = 1;
constexpr uintptr_t kDescriptorAlignmentMask = 0x3u;
constexpr uint32_t kFrameInterruptMask =
    GMAC_IER_RCOMP_Msk | GMAC_IER_RXUBR_Msk | GMAC_IER_TXUBR_Msk |
    GMAC_IER_TUR_Msk | GMAC_IER_RLEX_Msk | GMAC_IER_TFC_Msk |
    GMAC_IER_TCOMP_Msk | GMAC_IER_ROVR_Msk | GMAC_IER_HRESP_Msk |
    GMAC_IER_MFS_Msk;
constexpr uint32_t kReceiveErrorStatusMask =
    GMAC_RSR_BNA_Msk | GMAC_RSR_RXOVR_Msk | GMAC_RSR_HNO_Msk;
constexpr uint32_t kTransmitErrorStatusMask =
    GMAC_TSR_UBR_Msk | GMAC_TSR_RLE_Msk | GMAC_TSR_TFC_Msk |
    GMAC_TSR_HRESP_Msk;

struct GmacEventState {
  volatile gmac::EventMask pendingEvents = gmac::EventNone;
  volatile uint32_t pendingReceiveStatus = 0;
  volatile uint32_t pendingTransmitStatus = 0;
  volatile uint8_t lastReclaimedTransmitDescriptors = 0;
  gmac::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  bool serviceRegistered = false;
};

struct GmacFrameState {
  gmac::Descriptor *rxDescriptors = nullptr;
  uint8_t rxDescriptorCount = 0;
  uint8_t rxReadIndex = 0;
  uint8_t *rxBuffers = nullptr;
  uint16_t rxBufferSize = 0;
  gmac::Descriptor *txDescriptors = nullptr;
  uint8_t txDescriptorCount = 0;
  uint8_t txWriteIndex = 0;
  uint8_t txCleanIndex = 0;
  uint8_t txQueuedCount = 0;
};

struct RxFrameSpan {
  uint8_t startIndex = 0;
  uint8_t descriptorCount = 0;
  uint16_t length = 0;
};

GmacEventState eventState;
GmacFrameState frameState;
#if defined(UNIT_TEST)
bool forceManagementBusy = false;
bool forceTransmitBusy = false;
#endif

gmac_registers_t *gmacRegisters() {
  return reinterpret_cast<gmac_registers_t *>(GMAC_PERIPH);
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
}

uint64_t combineCounterWords(uint32_t low, uint32_t high) {
  return (static_cast<uint64_t>(high) << 32) | low;
}

gmac::EventMask recoverHardwareErrors(const gmac::Status &status) {
  const bool recoverRx = (status.receiveStatus & kReceiveErrorStatusMask) != 0;
  const bool recoverTx = (status.transmitStatus & kTransmitErrorStatusMask) != 0;
  gmac::EventMask recovered = gmac::EventNone;

  if ((recoverRx || (!recoverRx && !recoverTx)) && gmac::recoverReceive())
    recovered |= gmac::EventRxRecovered;

  if ((recoverTx || (!recoverRx && !recoverTx)) && gmac::recoverTransmit())
    recovered |= gmac::EventTxRecovered;

  return recovered;
}

void gmacPendSvService(uint8_t serviceId, void *) {
  if (serviceId != gmac::pendSvServiceId())
    return;

  gmac::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  gmac::EventMask events = gmac::EventNone;
  gmac::Status errorStatus = {};

  const uint32_t primask = enterCritical();
  events = eventState.pendingEvents;
  errorStatus.receiveStatus = eventState.pendingReceiveStatus;
  errorStatus.transmitStatus = eventState.pendingTransmitStatus;
  eventState.pendingEvents = gmac::EventNone;
  eventState.pendingReceiveStatus = 0;
  eventState.pendingTransmitStatus = 0;
  callback = eventState.callback;
  callbackContext = eventState.callbackContext;
  exitCritical(primask);

  if ((events & gmac::EventTxComplete) != 0) {
    const uint8_t reclaimed = gmac::reclaimTransmitDescriptors();
    const uint32_t reclaimPrimask = enterCritical();
    eventState.lastReclaimedTransmitDescriptors = reclaimed;
    exitCritical(reclaimPrimask);
  }

  if ((events & gmac::EventError) != 0)
    events |= recoverHardwareErrors(errorStatus);

  if (callback != nullptr && events != gmac::EventNone)
    callback(events, callbackContext);
}

bool ensurePendSvServiceRegistered() {
  if (eventState.serviceRegistered)
    return true;

  const bool registered = PendSV::instance().registerService(
      gmac::pendSvServiceId(), gmacPendSvService);
  if (registered)
    eventState.serviceRegistered = true;

  return registered;
}

void scheduleEventWithStatus(gmac::EventMask events,
                             const gmac::Status &errorStatus) {
  if (events == gmac::EventNone || !ensurePendSvServiceRegistered())
    return;

  const uint32_t primask = enterCritical();
  eventState.pendingEvents |= events;
  eventState.pendingReceiveStatus |= errorStatus.receiveStatus;
  eventState.pendingTransmitStatus |= errorStatus.transmitStatus;
  exitCritical(primask);

  PendSV::instance().setPending(gmac::pendSvServiceId());
}

uint32_t mdcClockBits(uint32_t mckHz, uint32_t maxMdcHz) {
  const uint64_t hostClock = mckHz;
  const uint64_t maxMdcClock = maxMdcHz;

  if (hostClock <= maxMdcClock * 8u)
    return GMAC_NCFGR_CLK_MCK8;

  if (hostClock <= maxMdcClock * 16u)
    return GMAC_NCFGR_CLK_MCK16;

  if (hostClock <= maxMdcClock * 32u)
    return GMAC_NCFGR_CLK_MCK32;

  if (hostClock <= maxMdcClock * 64u)
    return GMAC_NCFGR_CLK_MCK64;

  return GMAC_NCFGR_CLK_MCK96;
}

bool transmitBusy(gmac_registers_t *regs) {
#if defined(UNIT_TEST)
  if (forceTransmitBusy)
    return true;
#endif

  return (regs->GMAC_TSR & GMAC_TSR_TXGO_Msk) != 0;
}

bool waitManagementIdle() {
  gmac_registers_t *regs = gmacRegisters();
  const uint32_t startMs = millis();

  do {
    if ((regs->GMAC_NSR & GMAC_NSR_IDLE_Msk) != 0)
      return true;

    yield();
  } while ((millis() - startMs) < kMdioTimeoutMs);

  return false;
}

bool managementIdle() {
#if defined(UNIT_TEST)
  return !forceManagementBusy;
#endif

  return (gmacRegisters()->GMAC_NSR & GMAC_NSR_IDLE_Msk) != 0;
}

gmac::EventMask eventsFromInterruptStatus(uint32_t status) {
  gmac::EventMask events = gmac::EventNone;

  if ((status & (GMAC_ISR_RCOMP_Msk | GMAC_ISR_RXUBR_Msk)) != 0)
    events |= gmac::EventRxReady;

  if ((status & (GMAC_ISR_TCOMP_Msk | GMAC_ISR_TXUBR_Msk)) != 0)
    events |= gmac::EventTxComplete;

  if ((status & GMAC_ISR_MFS_Msk) != 0)
    events |= gmac::EventManagementComplete;

  if ((status & (GMAC_ISR_TUR_Msk | GMAC_ISR_RLEX_Msk | GMAC_ISR_TFC_Msk |
                 GMAC_ISR_ROVR_Msk | GMAC_ISR_HRESP_Msk)) != 0)
    events |= gmac::EventError;

  return events;
}

bool isWordAligned(const void *address) {
  return (reinterpret_cast<uintptr_t>(address) & kDescriptorAlignmentMask) == 0;
}

void initializeRxDescriptors(gmac::Descriptor *descriptors,
                             uint8_t descriptorCount, uint8_t *buffers,
                             uint16_t bufferSize) {
  for (uint8_t i = 0; i < descriptorCount; ++i) {
    const uintptr_t bufferAddress = reinterpret_cast<uintptr_t>(
        buffers + (static_cast<uint32_t>(i) * bufferSize));
    descriptors[i].word0 =
        static_cast<uint32_t>(bufferAddress) & GMAC_RBQB_Msk;
    descriptors[i].word1 = 0;
  }

  descriptors[descriptorCount - 1].word0 |= gmac::RxDescriptorWrap;
}

void initializeTxDescriptors(gmac::Descriptor *descriptors,
                             uint8_t descriptorCount) {
  for (uint8_t i = 0; i < descriptorCount; ++i) {
    descriptors[i].word0 = 0;
    descriptors[i].word1 = gmac::TxDescriptorUsed;
  }

  descriptors[descriptorCount - 1].word1 |= gmac::TxDescriptorWrap;
}

uint8_t nextDescriptorIndex(uint8_t index, uint8_t descriptorCount) {
  ++index;
  if (index >= descriptorCount)
    return 0;

  return index;
}

bool findReceivedFrame(RxFrameSpan *span) {
  if (span == nullptr || frameState.rxDescriptors == nullptr ||
      frameState.rxDescriptorCount == 0)
    return false;

  uint8_t index = frameState.rxReadIndex;
  gmac::Descriptor &firstDescriptor = frameState.rxDescriptors[index];
  if ((firstDescriptor.word0 & gmac::RxDescriptorOwnership) == 0)
    return false;

  __DMB();
  if ((firstDescriptor.word1 & gmac::RxDescriptorStartOfFrame) == 0)
    return false;

  for (uint8_t count = 1; count <= frameState.rxDescriptorCount; ++count) {
    gmac::Descriptor &descriptor = frameState.rxDescriptors[index];
    if ((descriptor.word0 & gmac::RxDescriptorOwnership) == 0)
      return false;

    __DMB();
    const uint32_t status = descriptor.word1;
    if ((status & gmac::RxDescriptorEndOfFrame) != 0) {
      span->startIndex = frameState.rxReadIndex;
      span->descriptorCount = count;
      span->length =
          static_cast<uint16_t>(status & gmac::RxDescriptorLengthMask);
      return true;
    }

    index = nextDescriptorIndex(index, frameState.rxDescriptorCount);
  }

  return false;
}

bool findDiscardableRxSpan(RxFrameSpan *span) {
  if (span == nullptr || frameState.rxDescriptors == nullptr ||
      frameState.rxDescriptorCount == 0)
    return false;

  uint8_t index = frameState.rxReadIndex;
  for (uint8_t count = 1; count <= frameState.rxDescriptorCount; ++count) {
    gmac::Descriptor &descriptor = frameState.rxDescriptors[index];
    if ((descriptor.word0 & gmac::RxDescriptorOwnership) == 0)
      return false;

    __DMB();
    const uint32_t status = descriptor.word1;
    if ((status & gmac::RxDescriptorEndOfFrame) != 0) {
      span->startIndex = frameState.rxReadIndex;
      span->descriptorCount = count;
      span->length =
          static_cast<uint16_t>(status & gmac::RxDescriptorLengthMask);
      return true;
    }

    index = nextDescriptorIndex(index, frameState.rxDescriptorCount);
  }

  span->startIndex = frameState.rxReadIndex;
  span->descriptorCount = frameState.rxDescriptorCount;
  span->length = 0;
  return true;
}

void releaseReceivedFrameSpan(const RxFrameSpan &span) {
  uint8_t index = span.startIndex;
  for (uint8_t i = 0; i < span.descriptorCount; ++i) {
    gmac::Descriptor &descriptor = frameState.rxDescriptors[index];
    descriptor.word1 = 0;
    __DMB();
    descriptor.word0 &= ~gmac::RxDescriptorOwnership;
    __DMB();
    index = nextDescriptorIndex(index, frameState.rxDescriptorCount);
  }

  frameState.rxReadIndex = index;
}
} // namespace

bool gmac::available() { return true; }

int gmac::irqNumber() { return static_cast<int>(GMAC_IRQn); }

bool gmac::beginManagement(uint32_t mckHz, uint32_t maxMdcHz) {
  if (maxMdcHz == 0)
    return false;

  if (static_cast<uint64_t>(mckHz) >
      (static_cast<uint64_t>(maxMdcHz) * 96u))
    return false;

  gmac_registers_t *regs = gmacRegisters();

#if defined(MCLK_AHBMASK_GMAC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_AHBMASK |= MCLK_AHBMASK_GMAC_Msk;
#elif defined(MCLK)
  MCLK->AHBMASK.reg |= MCLK_AHBMASK_GMAC_Msk;
#endif
#endif
#if defined(MCLK_APBCMASK_GMAC_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_GMAC_Msk;
#elif defined(MCLK)
  MCLK->APBCMASK.reg |= MCLK_APBCMASK_GMAC_Msk;
#endif
#endif

  regs->GMAC_NCFGR =
      (regs->GMAC_NCFGR & ~GMAC_NCFGR_CLK_Msk) |
      mdcClockBits(mckHz, maxMdcHz);
  regs->GMAC_NCR |= GMAC_NCR_MPE_Msk;

  return true;
}

bool gmac::isManagementIdle() { return managementIdle(); }

void gmac::configureLink(LinkSpeed speed, bool fullDuplex) {
  gmac_registers_t *regs = gmacRegisters();
  uint32_t config = regs->GMAC_NCFGR & ~(GMAC_NCFGR_SPD_Msk |
                                         GMAC_NCFGR_FD_Msk);

  if (speed == LinkSpeed100M)
    config |= GMAC_NCFGR_SPD_Msk;

  if (fullDuplex)
    config |= GMAC_NCFGR_FD_Msk;

  regs->GMAC_NCFGR = config;
}

void gmac::configureReceiveOptions(const ReceiveOptions &options) {
  gmac_registers_t *regs = gmacRegisters();
  uint32_t config = regs->GMAC_NCFGR &
                    ~(GMAC_NCFGR_RXCOEN_Msk | GMAC_NCFGR_RFCS_Msk |
                      GMAC_NCFGR_IRXFCS_Msk | GMAC_NCFGR_LFERD_Msk |
                      GMAC_NCFGR_MAXFS_Msk | GMAC_NCFGR_JFRAME_Msk);

  if (options.checksumOffload)
    config |= GMAC_NCFGR_RXCOEN_Msk;

  if (options.removeFrameCheckSequence)
    config |= GMAC_NCFGR_RFCS_Msk;

  if (options.ignoreFrameCheckSequence)
    config |= GMAC_NCFGR_IRXFCS_Msk;

  if (options.discardLengthFieldErrors)
    config |= GMAC_NCFGR_LFERD_Msk;

  if (options.accept1536ByteFrames)
    config |= GMAC_NCFGR_MAXFS_Msk;

  if (options.jumboFrames)
    config |= GMAC_NCFGR_JFRAME_Msk;

  regs->GMAC_NCFGR = config;
}

void gmac::setPromiscuousMode(bool enabled) {
  gmac_registers_t *regs = gmacRegisters();
  if (enabled) {
    regs->GMAC_NCFGR |= GMAC_NCFGR_CAF_Msk;
  } else {
    regs->GMAC_NCFGR &= ~GMAC_NCFGR_CAF_Msk;
  }
}

void gmac::setBroadcastReception(bool enabled) {
  gmac_registers_t *regs = gmacRegisters();
  if (enabled) {
    regs->GMAC_NCFGR &= ~GMAC_NCFGR_NBC_Msk;
  } else {
    regs->GMAC_NCFGR |= GMAC_NCFGR_NBC_Msk;
  }
}

bool gmac::hashIndexForAddress(const uint8_t mac[6], uint8_t *index) {
  if (mac == nullptr || index == nullptr)
    return false;

  uint8_t hashIndex = 0;
  for (uint8_t hashBit = 0; hashBit < 6; ++hashBit) {
    uint8_t value = 0;
    for (uint8_t addressBit = hashBit; addressBit < 48; addressBit += 6)
      value ^= (mac[addressBit / 8] >> (addressBit % 8)) & 0x01u;

    hashIndex |= value << hashBit;
  }

  *index = hashIndex;
  return true;
}

bool gmac::multicastHashForAddress(const uint8_t mac[6], uint32_t *bottom,
                                   uint32_t *top) {
  if (bottom == nullptr || top == nullptr || mac == nullptr ||
      (mac[0] & 0x01u) == 0)
    return false;

  uint8_t index = 0;
  if (!hashIndexForAddress(mac, &index))
    return false;

  *bottom = index < 32 ? (1u << index) : 0;
  *top = index >= 32 ? (1u << (index - 32)) : 0;
  return true;
}

void gmac::setHashFilter(uint32_t bottom, uint32_t top, bool multicastEnabled,
                         bool unicastEnabled) {
  gmac_registers_t *regs = gmacRegisters();
  uint32_t config =
      regs->GMAC_NCFGR & ~(GMAC_NCFGR_MTIHEN_Msk | GMAC_NCFGR_UNIHEN_Msk);

  regs->GMAC_HRB = bottom;
  regs->GMAC_HRT = top;

  if (multicastEnabled)
    config |= GMAC_NCFGR_MTIHEN_Msk;

  if (unicastEnabled)
    config |= GMAC_NCFGR_UNIHEN_Msk;

  regs->GMAC_NCFGR = config;
}

void gmac::clearHashFilter() { setHashFilter(0, 0, false, false); }

bool gmac::configureFrameBuffers(Descriptor *rxDescriptors,
                                 uint8_t rxDescriptorCount, uint8_t *rxBuffers,
                                 uint16_t rxBufferSize,
                                 Descriptor *txDescriptors,
                                 uint8_t txDescriptorCount) {
  if (rxDescriptors == nullptr || rxBuffers == nullptr ||
      txDescriptors == nullptr || rxDescriptorCount == 0 ||
      txDescriptorCount == 0 || rxBufferSize == 0 ||
      (rxBufferSize % RxBufferSizeGranularity) != 0)
    return false;

  if (!isWordAligned(rxDescriptors) || !isWordAligned(txDescriptors) ||
      !isWordAligned(rxBuffers))
    return false;

  gmac_registers_t *regs = gmacRegisters();

  disableFrameIo();
  initializeRxDescriptors(rxDescriptors, rxDescriptorCount, rxBuffers,
                          rxBufferSize);
  initializeTxDescriptors(txDescriptors, txDescriptorCount);
  __DMB();
  frameState.rxDescriptors = rxDescriptors;
  frameState.rxDescriptorCount = rxDescriptorCount;
  frameState.rxReadIndex = 0;
  frameState.rxBuffers = rxBuffers;
  frameState.rxBufferSize = rxBufferSize;
  frameState.txDescriptors = txDescriptors;
  frameState.txDescriptorCount = txDescriptorCount;
  frameState.txWriteIndex = 0;
  frameState.txCleanIndex = 0;
  frameState.txQueuedCount = 0;
  eventState.lastReclaimedTransmitDescriptors = 0;

  regs->GMAC_RBQB =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(rxDescriptors)) &
      GMAC_RBQB_Msk;
  regs->GMAC_TBQB =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(txDescriptors)) &
      GMAC_TBQB_Msk;
  regs->GMAC_DCFGR = (regs->GMAC_DCFGR & ~GMAC_DCFGR_DRBS_Msk) |
                     GMAC_DCFGR_DRBS(rxBufferSize / RxBufferSizeGranularity);
  regs->GMAC_RSR = GMAC_RSR_Msk;
  regs->GMAC_TSR = GMAC_TSR_Msk;

  return true;
}

void gmac::enableFrameIo() {
  gmac_registers_t *regs = gmacRegisters();
  regs->GMAC_RSR = GMAC_RSR_Msk;
  regs->GMAC_TSR = GMAC_TSR_Msk;
  regs->GMAC_IER = kFrameInterruptMask;
  NVIC_ClearPendingIRQ(GMAC_IRQn);
  NVIC_EnableIRQ(GMAC_IRQn);
  __DMB();
  regs->GMAC_NCR |= GMAC_NCR_RXEN_Msk | GMAC_NCR_TXEN_Msk;
}

void gmac::disableFrameIo() {
  gmac_registers_t *regs = gmacRegisters();
  regs->GMAC_NCR &= ~(GMAC_NCR_RXEN_Msk | GMAC_NCR_TXEN_Msk);
  regs->GMAC_IDR = kFrameInterruptMask;
  NVIC_DisableIRQ(GMAC_IRQn);
  NVIC_ClearPendingIRQ(GMAC_IRQn);
}

gmac::Status gmac::status() {
  gmac_registers_t *regs = gmacRegisters();
  const Status current = {regs->GMAC_RSR, regs->GMAC_TSR};
  return current;
}

void gmac::clearReceiveStatus(uint32_t mask) { gmacRegisters()->GMAC_RSR = mask; }

void gmac::clearTransmitStatus(uint32_t mask) { gmacRegisters()->GMAC_TSR = mask; }

void gmac::clearStatus(uint32_t receiveMask, uint32_t transmitMask) {
  clearReceiveStatus(receiveMask);
  clearTransmitStatus(transmitMask);
}

bool gmac::recoverReceive() {
  if (frameState.rxDescriptors == nullptr || frameState.rxDescriptorCount == 0 ||
      frameState.rxBuffers == nullptr || frameState.rxBufferSize == 0)
    return false;

  gmac_registers_t *regs = gmacRegisters();
  const bool wasEnabled = (regs->GMAC_NCR & GMAC_NCR_RXEN_Msk) != 0;
  const uint32_t descriptorBase =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
          frameState.rxDescriptors)) &
      GMAC_RBQB_Msk;

  regs->GMAC_NCR &= ~GMAC_NCR_RXEN_Msk;
  initializeRxDescriptors(frameState.rxDescriptors, frameState.rxDescriptorCount,
                          frameState.rxBuffers, frameState.rxBufferSize);
  __DMB();
  frameState.rxReadIndex = 0;
  regs->GMAC_RBQB = descriptorBase;
  regs->GMAC_RSR = GMAC_RSR_Msk;
  __DMB();

  if (wasEnabled)
    regs->GMAC_NCR |= GMAC_NCR_RXEN_Msk;

  return true;
}

bool gmac::recoverTransmit() {
  if (frameState.txDescriptors == nullptr || frameState.txDescriptorCount == 0)
    return false;

  gmac_registers_t *regs = gmacRegisters();
  const bool wasEnabled = (regs->GMAC_NCR & GMAC_NCR_TXEN_Msk) != 0;
  const uint32_t descriptorBase =
      static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
          frameState.txDescriptors)) &
      GMAC_TBQB_Msk;

  regs->GMAC_NCR |= GMAC_NCR_THALT_Msk;
  __DMB();
  if (transmitBusy(regs))
    return false;

  regs->GMAC_NCR &= ~GMAC_NCR_TXEN_Msk;
  initializeTxDescriptors(frameState.txDescriptors, frameState.txDescriptorCount);
  __DMB();
  frameState.txWriteIndex = 0;
  frameState.txCleanIndex = 0;
  frameState.txQueuedCount = 0;
  eventState.lastReclaimedTransmitDescriptors = 0;
  regs->GMAC_TBQB = descriptorBase;
  regs->GMAC_TSR = GMAC_TSR_Msk;
  regs->GMAC_NCR &= ~GMAC_NCR_THALT_Msk;
  __DMB();

  if (wasEnabled)
    regs->GMAC_NCR |= GMAC_NCR_TXEN_Msk;

  return true;
}

gmac::Statistics gmac::statistics() {
  gmac_registers_t *regs = gmacRegisters();
  Statistics current = {};

  current.transmitOctets =
      combineCounterWords(regs->GMAC_OTLO, regs->GMAC_OTHI);
  current.transmitFrames = regs->GMAC_FT;
  current.transmitBroadcastFrames = regs->GMAC_BCFT;
  current.transmitMulticastFrames = regs->GMAC_MFT;
  current.transmitPauseFrames = regs->GMAC_PFT;
  current.transmitUnderruns = regs->GMAC_TUR;
  current.transmitSingleCollisionFrames = regs->GMAC_SCF;
  current.transmitMultipleCollisionFrames = regs->GMAC_MCF;
  current.transmitExcessiveCollisions = regs->GMAC_EC;
  current.transmitLateCollisions = regs->GMAC_LC;
  current.transmitDeferredFrames = regs->GMAC_DTF;
  current.transmitCarrierSenseErrors = regs->GMAC_CSE;

  current.receiveOctets = combineCounterWords(regs->GMAC_ORLO, regs->GMAC_ORHI);
  current.receiveFrames = regs->GMAC_FR;
  current.receiveBroadcastFrames = regs->GMAC_BCFR;
  current.receiveMulticastFrames = regs->GMAC_MFR;
  current.receivePauseFrames = regs->GMAC_PFR;
  current.receiveUndersizeFrames = regs->GMAC_UFR;
  current.receiveOversizeFrames = regs->GMAC_OFR;
  current.receiveJabbers = regs->GMAC_JR;
  current.receiveFcsErrors = regs->GMAC_FCSE;
  current.receiveLengthFieldErrors = regs->GMAC_LFFE;
  current.receiveSymbolErrors = regs->GMAC_RSE;
  current.receiveAlignmentErrors = regs->GMAC_AE;
  current.receiveResourceErrors = regs->GMAC_RRE;
  current.receiveOverruns = regs->GMAC_ROE;
  current.receiveIpHeaderChecksumErrors = regs->GMAC_IHCE;
  current.receiveTcpChecksumErrors = regs->GMAC_TCE;
  current.receiveUdpChecksumErrors = regs->GMAC_UCE;

  return current;
}

void gmac::clearStatistics() { gmacRegisters()->GMAC_NCR |= GMAC_NCR_CLRSTAT_Msk; }

bool gmac::queueTransmitBuffer(const uint8_t *buffer, uint16_t length) {
  const TransmitFragment fragment = {buffer, length};
  return queueTransmitFrame(&fragment, 1);
}

bool gmac::queueTransmitFrame(const TransmitFragment *fragments,
                              uint8_t fragmentCount) {
  if (fragments == nullptr || fragmentCount == 0 ||
      frameState.txDescriptors == nullptr ||
      frameState.txDescriptorCount == 0 ||
      fragmentCount > (frameState.txDescriptorCount - frameState.txQueuedCount))
    return false;

  uint8_t index = frameState.txWriteIndex;
  for (uint8_t i = 0; i < fragmentCount; ++i) {
    const TransmitFragment &fragment = fragments[i];
    if (fragment.buffer == nullptr || fragment.length == 0 ||
        fragment.length > TxDescriptorLengthMask ||
        !isWordAligned(fragment.buffer))
      return false;

    Descriptor &descriptor = frameState.txDescriptors[index];
    if ((descriptor.word1 & TxDescriptorUsed) == 0)
      return false;

    __DMB();
    index = nextDescriptorIndex(index, frameState.txDescriptorCount);
  }

  for (uint8_t i = 0; i < fragmentCount; ++i) {
    Descriptor &descriptor = frameState.txDescriptors[frameState.txWriteIndex];
    const uint32_t wrap = descriptor.word1 & TxDescriptorWrap;
    const uint32_t lastBuffer =
        (i == (fragmentCount - 1)) ? TxDescriptorLastBuffer : 0;

    __DMB();
    descriptor.word0 =
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(fragments[i].buffer));
    __DMB();
    descriptor.word1 =
        wrap |
        (static_cast<uint32_t>(fragments[i].length) & TxDescriptorLengthMask) |
        lastBuffer;
    __DMB();

    frameState.txWriteIndex = nextDescriptorIndex(frameState.txWriteIndex,
                                                  frameState.txDescriptorCount);
    ++frameState.txQueuedCount;
  }

  __DMB();
  gmacRegisters()->GMAC_NCR |= GMAC_NCR_TSTART_Msk;
  return true;
}

uint8_t gmac::reclaimTransmitDescriptors() {
  if (frameState.txDescriptors == nullptr || frameState.txDescriptorCount == 0) {
    return 0;
  }

  uint8_t reclaimed = 0;
  while (frameState.txQueuedCount > 0) {
    uint8_t index = frameState.txCleanIndex;
    uint8_t frameDescriptorCount = 0;
    bool frameComplete = false;

    while (frameDescriptorCount < frameState.txQueuedCount) {
      Descriptor &descriptor = frameState.txDescriptors[index];
      uint32_t status = descriptor.word1;
      if ((status & TxDescriptorUsed) == 0) {
        break;
      }

      __DMB();
      status = descriptor.word1;
      ++frameDescriptorCount;
      if ((status & TxDescriptorLastBuffer) != 0) {
        frameComplete = true;
        break;
      }

      index = nextDescriptorIndex(index, frameState.txDescriptorCount);
    }

    if (!frameComplete) {
      break;
    }

    for (uint8_t i = 0; i < frameDescriptorCount; ++i) {
      Descriptor &descriptor =
          frameState.txDescriptors[frameState.txCleanIndex];
      const uint32_t wrap = descriptor.word1 & TxDescriptorWrap;
      descriptor.word0 = 0;
      descriptor.word1 = wrap | TxDescriptorUsed;
      frameState.txCleanIndex = nextDescriptorIndex(
          frameState.txCleanIndex, frameState.txDescriptorCount);
      --frameState.txQueuedCount;
      ++reclaimed;
    }
  }

  return reclaimed;
}

uint8_t gmac::lastReclaimedTransmitDescriptors() {
  const uint32_t primask = enterCritical();
  const uint8_t reclaimed = eventState.lastReclaimedTransmitDescriptors;
  eventState.lastReclaimedTransmitDescriptors = 0;
  exitCritical(primask);
  return reclaimed;
}

bool gmac::receivedFrameSize(uint16_t *length) {
  if (length == nullptr || frameState.rxBufferSize == 0)
    return false;

  RxFrameSpan span;
  if (!findReceivedFrame(&span))
    return false;

  const uint32_t readableCapacity =
      static_cast<uint32_t>(span.descriptorCount) * frameState.rxBufferSize;
  if (span.length == 0 || span.length > readableCapacity)
    return false;

  *length = span.length;
  return true;
}

bool gmac::peekReceivedFrame(uint8_t **buffer, uint16_t *length) {
  if (buffer == nullptr || length == nullptr ||
      frameState.rxDescriptors == nullptr ||
      frameState.rxDescriptorCount == 0) {
    return false;
  }

  RxFrameSpan span;
  if (!findReceivedFrame(&span) || span.descriptorCount != 1) {
    return false;
  }
  if (span.length == 0 || span.length > frameState.rxBufferSize) {
    return false;
  }

  Descriptor &descriptor = frameState.rxDescriptors[span.startIndex];

  *buffer = reinterpret_cast<uint8_t *>(descriptor.word0 & GMAC_RBQB_Msk);
  *length = span.length;
  return true;
}

bool gmac::readReceivedFrame(uint8_t *buffer, uint16_t capacity,
                             uint16_t *length) {
  if (buffer == nullptr || length == nullptr || frameState.rxBufferSize == 0) {
    return false;
  }

  RxFrameSpan span;
  if (!findReceivedFrame(&span)) {
    return false;
  }

  const uint32_t readableCapacity =
      static_cast<uint32_t>(span.descriptorCount) * frameState.rxBufferSize;
  if (span.length == 0 || span.length > readableCapacity) {
    return false;
  }

  if (capacity < span.length) {
    *length = span.length;
    return false;
  }

  uint16_t remaining = span.length;
  uint16_t offset = 0;
  uint8_t index = span.startIndex;

  for (uint8_t i = 0; i < span.descriptorCount && remaining > 0; ++i) {
    Descriptor &descriptor = frameState.rxDescriptors[index];
    const uint16_t chunkLength =
        remaining < frameState.rxBufferSize ? remaining : frameState.rxBufferSize;
    const uint8_t *source =
        reinterpret_cast<const uint8_t *>(descriptor.word0 & GMAC_RBQB_Msk);

    __DMB();
    memcpy(buffer + offset, source, chunkLength);
    offset += chunkLength;
    remaining -= chunkLength;
    index = nextDescriptorIndex(index, frameState.rxDescriptorCount);
  }

  *length = span.length;
  releaseReceivedFrameSpan(span);
  return remaining == 0;
}

bool gmac::releaseReceivedFrame() {
  if (frameState.rxDescriptors == nullptr ||
      frameState.rxDescriptorCount == 0) {
    return false;
  }

  RxFrameSpan span;
  if (!findReceivedFrame(&span)) {
    return false;
  }

  releaseReceivedFrameSpan(span);
  return true;
}

bool gmac::discardReceivedFrame() {
  if (frameState.rxDescriptors == nullptr || frameState.rxDescriptorCount == 0)
    return false;

  RxFrameSpan span;
  if (!findDiscardableRxSpan(&span))
    return false;

  releaseReceivedFrameSpan(span);
  return true;
}

bool gmac::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr)
    return false;

  if (!ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  eventState.callback = callback;
  eventState.callbackContext = context;
  exitCritical(primask);

  return true;
}

void gmac::clearEventCallback() {
  const uint32_t primask = enterCritical();
  eventState.pendingEvents = EventNone;
  eventState.pendingReceiveStatus = 0;
  eventState.pendingTransmitStatus = 0;
  eventState.callback = nullptr;
  eventState.callbackContext = nullptr;
  eventState.serviceRegistered = false;
  exitCritical(primask);

  PendSV::instance().clearService(pendSvServiceId());
}

gmac::EventMask gmac::pendingEvents() {
  const uint32_t primask = enterCritical();
  const EventMask events = eventState.pendingEvents;
  exitCritical(primask);
  return events;
}

void gmac::scheduleEvent(EventMask events) {
  Status errorStatus = {};
  if ((events & EventError) != 0)
    errorStatus = status();

  scheduleEventWithStatus(events, errorStatus);
}

#if defined(UNIT_TEST)
void gmac::scheduleErrorForTest(const Status &status) {
  scheduleEventWithStatus(EventError, status);
}

void gmac::forceManagementBusyForTest(bool busy) { forceManagementBusy = busy; }

void gmac::forceTransmitBusyForTest(bool busy) { forceTransmitBusy = busy; }
#endif

void gmac::handleInterrupt() {
  gmac_registers_t *regs = gmacRegisters();
  const uint32_t status = regs->GMAC_ISR & ~regs->GMAC_IMR;
  scheduleEvent(eventsFromInterruptStatus(status));
}

void gmac::setMacAddress(const uint8_t mac[6]) {
  if (mac == nullptr)
    return;

  gmac_registers_t *regs = gmacRegisters();

  regs->SA[0].GMAC_SAB = static_cast<uint32_t>(mac[0]) |
                         (static_cast<uint32_t>(mac[1]) << 8) |
                         (static_cast<uint32_t>(mac[2]) << 16) |
                         (static_cast<uint32_t>(mac[3]) << 24);
  regs->SA[0].GMAC_SAT =
      static_cast<uint32_t>(mac[4]) | (static_cast<uint32_t>(mac[5]) << 8);
}

void gmac::getMacAddress(uint8_t mac[6]) {
  if (mac == nullptr)
    return;

  gmac_registers_t *regs = gmacRegisters();
  const uint32_t bottom = regs->SA[0].GMAC_SAB;
  const uint32_t top = regs->SA[0].GMAC_SAT;

  mac[0] = static_cast<uint8_t>(bottom & 0xFFu);
  mac[1] = static_cast<uint8_t>((bottom >> 8) & 0xFFu);
  mac[2] = static_cast<uint8_t>((bottom >> 16) & 0xFFu);
  mac[3] = static_cast<uint8_t>((bottom >> 24) & 0xFFu);
  mac[4] = static_cast<uint8_t>(top & 0xFFu);
  mac[5] = static_cast<uint8_t>((top >> 8) & 0xFFu);
}

bool gmac::mdioRead(uint8_t phyAddress, uint8_t registerAddress,
                    uint16_t *value) {
  if (value == nullptr || phyAddress > 31 || registerAddress > 31)
    return false;

  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle())
    return false;

  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioReadOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen);

  if (!waitManagementIdle())
    return false;
  
  *value = static_cast<uint16_t>(regs->GMAC_MAN & GMAC_MAN_DATA_Msk);
  return true;
}

bool gmac::mdioWrite(uint8_t phyAddress, uint8_t registerAddress,
                     uint16_t value) {
  if (phyAddress > 31 || registerAddress > 31)
    return false;

  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle()) 
    return false;

  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioWriteOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen) | GMAC_MAN_DATA(value);

  return waitManagementIdle();
}

bool gmac::mdioReadStart(uint8_t phyAddress, uint8_t registerAddress) {
  if (phyAddress > 31 || registerAddress > 31 || !managementIdle())
    return false;

  gmac_registers_t *regs = gmacRegisters();
  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioReadOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen);
  return true;
}

bool gmac::mdioReadComplete(uint16_t *value) {
  if (value == nullptr || !managementIdle())
    return false;

  *value = static_cast<uint16_t>(gmacRegisters()->GMAC_MAN & GMAC_MAN_DATA_Msk);
  return true;
}

bool gmac::mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                          uint16_t value) {
  if (phyAddress > 31 || registerAddress > 31)
    return false;
  
  gmac_registers_t *regs = gmacRegisters();

  if (!managementIdle())
    return false;
  
  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioWriteOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen) | GMAC_MAN_DATA(value);

  return true;
}

extern "C" void GMAC_Handler(void) {
  gmac::handleInterrupt();
}

#endif /* ETHERNET_HARDWARE_AVAILABLE */
