#include "GMAC.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>
#include <PendSV.h>
#include <string.h>

namespace {
constexpr uint32_t kMdioTimeoutMs = 10;
constexpr uint32_t kMdioWriteTen = 2;
constexpr uint32_t kMdioReadOperation = 2;
constexpr uint32_t kMdioWriteOperation = 1;
constexpr uintptr_t kDescriptorAlignmentMask = 0x3u;
constexpr uint32_t kFrameInterruptMask =
    GMAC_IER_RCOMP_Msk | GMAC_IER_RXUBR_Msk | GMAC_IER_TXUBR_Msk |
    GMAC_IER_TUR_Msk | GMAC_IER_RLEX_Msk | GMAC_IER_TFC_Msk |
    GMAC_IER_TCOMP_Msk | GMAC_IER_ROVR_Msk | GMAC_IER_HRESP_Msk;

struct GmacEventState {
  volatile gmac::EventMask pendingEvents = gmac::EventNone;
  gmac::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  bool serviceRegistered = false;
};

struct GmacFrameState {
  gmac::Descriptor *rxDescriptors = nullptr;
  uint8_t rxDescriptorCount = 0;
  uint8_t rxReadIndex = 0;
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

void gmacPendSvService(uint8_t serviceId, void *) {
  if (serviceId != gmac::pendSvServiceId()) {
    return;
  }

  gmac::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  gmac::EventMask events = gmac::EventNone;

  const uint32_t primask = enterCritical();
  events = eventState.pendingEvents;
  eventState.pendingEvents = gmac::EventNone;
  callback = eventState.callback;
  callbackContext = eventState.callbackContext;
  exitCritical(primask);

  if ((events & gmac::EventTxComplete) != 0) {
    gmac::reclaimTransmitDescriptors();
  }

  if (callback != nullptr && events != gmac::EventNone) {
    callback(events, callbackContext);
  }
}

bool ensurePendSvServiceRegistered() {
  if (eventState.serviceRegistered) {
    return true;
  }

  const bool registered = PendSV::instance().registerService(
      gmac::pendSvServiceId(), gmacPendSvService);
  if (registered) {
    eventState.serviceRegistered = true;
  }
  return registered;
}

uint32_t mdcClockBits(uint32_t mckHz) {
  if (mckHz <= 20000000UL) {
    return GMAC_NCFGR_CLK_MCK8;
  }
  if (mckHz <= 40000000UL) {
    return GMAC_NCFGR_CLK_MCK16;
  }
  if (mckHz <= 80000000UL) {
    return GMAC_NCFGR_CLK_MCK32;
  }
  if (mckHz <= 120000000UL) {
    return GMAC_NCFGR_CLK_MCK64;
  }
  return GMAC_NCFGR_CLK_MCK96;
}

bool waitManagementIdle() {
  gmac_registers_t *regs = gmacRegisters();
  const uint32_t startMs = millis();

  do {
    if ((regs->GMAC_NSR & GMAC_NSR_IDLE_Msk) != 0) {
      return true;
    }
    yield();
  } while ((millis() - startMs) < kMdioTimeoutMs);

  return false;
}

gmac::EventMask eventsFromInterruptStatus(uint32_t status) {
  gmac::EventMask events = gmac::EventNone;

  if ((status & (GMAC_ISR_RCOMP_Msk | GMAC_ISR_RXUBR_Msk)) != 0) {
    events |= gmac::EventRxReady;
  }
  if ((status & (GMAC_ISR_TCOMP_Msk | GMAC_ISR_TXUBR_Msk)) != 0) {
    events |= gmac::EventTxComplete;
  }
  if ((status & GMAC_ISR_MFS_Msk) != 0) {
    events |= gmac::EventManagementComplete;
  }
  if ((status & (GMAC_ISR_TUR_Msk | GMAC_ISR_RLEX_Msk | GMAC_ISR_TFC_Msk |
                 GMAC_ISR_ROVR_Msk | GMAC_ISR_HRESP_Msk)) != 0) {
    events |= gmac::EventError;
  }

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
  if (index >= descriptorCount) {
    return 0;
  }
  return index;
}

bool findReceivedFrame(RxFrameSpan *span) {
  if (span == nullptr || frameState.rxDescriptors == nullptr ||
      frameState.rxDescriptorCount == 0) {
    return false;
  }

  uint8_t index = frameState.rxReadIndex;
  gmac::Descriptor &firstDescriptor = frameState.rxDescriptors[index];
  if ((firstDescriptor.word0 & gmac::RxDescriptorOwnership) == 0 ||
      (firstDescriptor.word1 & gmac::RxDescriptorStartOfFrame) == 0) {
    return false;
  }

  for (uint8_t count = 1; count <= frameState.rxDescriptorCount; ++count) {
    gmac::Descriptor &descriptor = frameState.rxDescriptors[index];
    if ((descriptor.word0 & gmac::RxDescriptorOwnership) == 0) {
      return false;
    }

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

void releaseReceivedFrameSpan(const RxFrameSpan &span) {
  uint8_t index = span.startIndex;
  for (uint8_t i = 0; i < span.descriptorCount; ++i) {
    gmac::Descriptor &descriptor = frameState.rxDescriptors[index];
    descriptor.word0 &= ~gmac::RxDescriptorOwnership;
    descriptor.word1 = 0;
    index = nextDescriptorIndex(index, frameState.rxDescriptorCount);
  }

  frameState.rxReadIndex = index;
}
} // namespace

bool gmac::available() { return true; }

int gmac::irqNumber() { return static_cast<int>(GMAC_IRQn); }

bool gmac::beginManagement(uint32_t mckHz) {
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
      (regs->GMAC_NCFGR & ~GMAC_NCFGR_CLK_Msk) | mdcClockBits(mckHz);
  regs->GMAC_NCR |= GMAC_NCR_MPE_Msk;

  return waitManagementIdle();
}

bool gmac::isManagementIdle() { return waitManagementIdle(); }

void gmac::configureLink(LinkSpeed speed, bool fullDuplex) {
  gmac_registers_t *regs = gmacRegisters();
  uint32_t config = regs->GMAC_NCFGR & ~(GMAC_NCFGR_SPD_Msk |
                                         GMAC_NCFGR_FD_Msk);

  if (speed == LinkSpeed100M) {
    config |= GMAC_NCFGR_SPD_Msk;
  }
  if (fullDuplex) {
    config |= GMAC_NCFGR_FD_Msk;
  }

  regs->GMAC_NCFGR = config;
}

bool gmac::configureFrameBuffers(Descriptor *rxDescriptors,
                                 uint8_t rxDescriptorCount, uint8_t *rxBuffers,
                                 uint16_t rxBufferSize,
                                 Descriptor *txDescriptors,
                                 uint8_t txDescriptorCount) {
  if (rxDescriptors == nullptr || rxBuffers == nullptr ||
      txDescriptors == nullptr || rxDescriptorCount == 0 ||
      txDescriptorCount == 0 || rxBufferSize == 0 ||
      (rxBufferSize % RxBufferSizeGranularity) != 0) {
    return false;
  }

  if (!isWordAligned(rxDescriptors) || !isWordAligned(txDescriptors) ||
      !isWordAligned(rxBuffers)) {
    return false;
  }

  gmac_registers_t *regs = gmacRegisters();

  disableFrameIo();
  initializeRxDescriptors(rxDescriptors, rxDescriptorCount, rxBuffers,
                          rxBufferSize);
  initializeTxDescriptors(txDescriptors, txDescriptorCount);
  frameState.rxDescriptors = rxDescriptors;
  frameState.rxDescriptorCount = rxDescriptorCount;
  frameState.rxReadIndex = 0;
  frameState.rxBufferSize = rxBufferSize;
  frameState.txDescriptors = txDescriptors;
  frameState.txDescriptorCount = txDescriptorCount;
  frameState.txWriteIndex = 0;
  frameState.txCleanIndex = 0;
  frameState.txQueuedCount = 0;

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
  regs->GMAC_NCR |= GMAC_NCR_RXEN_Msk | GMAC_NCR_TXEN_Msk;
}

void gmac::disableFrameIo() {
  gmac_registers_t *regs = gmacRegisters();
  regs->GMAC_NCR &= ~(GMAC_NCR_RXEN_Msk | GMAC_NCR_TXEN_Msk);
  regs->GMAC_IDR = kFrameInterruptMask;
}

bool gmac::queueTransmitBuffer(const uint8_t *buffer, uint16_t length) {
  if (buffer == nullptr || length == 0 || length > TxDescriptorLengthMask ||
      !isWordAligned(buffer) || frameState.txDescriptors == nullptr ||
      frameState.txDescriptorCount == 0 ||
      frameState.txQueuedCount >= frameState.txDescriptorCount) {
    return false;
  }

  Descriptor &descriptor =
      frameState.txDescriptors[frameState.txWriteIndex];
  if ((descriptor.word1 & TxDescriptorUsed) == 0) {
    return false;
  }

  const uint32_t wrap = descriptor.word1 & TxDescriptorWrap;
  descriptor.word0 = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(buffer));
  descriptor.word1 = wrap | (static_cast<uint32_t>(length) &
                             TxDescriptorLengthMask) |
                     TxDescriptorLastBuffer;
  frameState.txWriteIndex =
      nextDescriptorIndex(frameState.txWriteIndex, frameState.txDescriptorCount);
  ++frameState.txQueuedCount;

  gmacRegisters()->GMAC_NCR |= GMAC_NCR_TSTART_Msk;
  return true;
}

uint8_t gmac::reclaimTransmitDescriptors() {
  if (frameState.txDescriptors == nullptr || frameState.txDescriptorCount == 0) {
    return 0;
  }

  uint8_t reclaimed = 0;
  while (frameState.txQueuedCount > 0) {
    Descriptor &descriptor =
        frameState.txDescriptors[frameState.txCleanIndex];
    if ((descriptor.word1 & TxDescriptorUsed) == 0) {
      break;
    }

    const uint32_t wrap = descriptor.word1 & TxDescriptorWrap;
    descriptor.word0 = 0;
    descriptor.word1 = wrap | TxDescriptorUsed;
    frameState.txCleanIndex = nextDescriptorIndex(frameState.txCleanIndex,
                                                  frameState.txDescriptorCount);
    --frameState.txQueuedCount;
    ++reclaimed;
  }

  return reclaimed;
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

bool gmac::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr) {
    return false;
  }
  if (!ensurePendSvServiceRegistered()) {
    return false;
  }

  const uint32_t primask = enterCritical();
  eventState.callback = callback;
  eventState.callbackContext = context;
  exitCritical(primask);

  return true;
}

void gmac::clearEventCallback() {
  const uint32_t primask = enterCritical();
  eventState.pendingEvents = EventNone;
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
  if (events == EventNone || !ensurePendSvServiceRegistered()) {
    return;
  }

  const uint32_t primask = enterCritical();
  eventState.pendingEvents |= events;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
}

void gmac::handleInterrupt() {
  gmac_registers_t *regs = gmacRegisters();
  const uint32_t status = regs->GMAC_ISR & ~regs->GMAC_IMR;
  scheduleEvent(eventsFromInterruptStatus(status));
}

void gmac::setMacAddress(const uint8_t mac[6]) {
  if (mac == nullptr) {
    return;
  }

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
  if (phyAddress > 31 || registerAddress > 31) {
    return false;
  }

  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle()) 
    return false;

  regs->GMAC_MAN = GMAC_MAN_CLTTO_Msk | GMAC_MAN_OP(kMdioWriteOperation) |
                   GMAC_MAN_PHYA(phyAddress) | GMAC_MAN_REGA(registerAddress) |
                   GMAC_MAN_WTN(kMdioWriteTen) | GMAC_MAN_DATA(value);

  return waitManagementIdle();
}

bool gmac::mdioWriteStart(uint8_t phyAddress, uint8_t registerAddress,
                          uint16_t value) {
  if (phyAddress > 31 || registerAddress > 31)
    return false;
  
  gmac_registers_t *regs = gmacRegisters();

  if (!waitManagementIdle()) 
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
