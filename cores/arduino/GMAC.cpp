#include "GMAC.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <Arduino.h>
#include <PendSV.h>

namespace {
constexpr uint32_t kMdioTimeoutMs = 10;
constexpr uint32_t kMdioWriteTen = 2;
constexpr uint32_t kMdioReadOperation = 2;
constexpr uint32_t kMdioWriteOperation = 1;

struct GmacEventState {
  volatile gmac::EventMask pendingEvents = gmac::EventNone;
  gmac::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  bool serviceRegistered = false;
};

GmacEventState eventState;

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
  const uint32_t status = regs->GMAC_ISR & regs->GMAC_IMR;
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
