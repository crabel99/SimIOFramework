#include "TRNG.h"

#if TRNG_AVAILABLE

namespace {
inline trng_registers_t *regs() {
  return reinterpret_cast<trng_registers_t *>(TRNG_PERIPH);
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
}

struct AsyncState {
  trng::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint8_t pendingFlags = 0;
  uint32_t pendingValue = 0;
  bool serviceRegistered = false;
  bool busy = false;
  bool stopAfterWord = true;
};

AsyncState asyncState;

void scrubWord(uint32_t &value) {
  volatile uint32_t *word = &value;
  *word = 0;
}

void trngPendSvService(uint8_t serviceId, void *context) {
  (void)serviceId;
  (void)context;

  trng::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint8_t flags = 0;
  uint32_t value = 0;
  bool stopAfterWord = true;

  const uint32_t primask = enterCritical();
  flags = asyncState.pendingFlags;
  value = asyncState.pendingValue;
  asyncState.pendingFlags = 0;
  asyncState.pendingValue = 0;
  callback = asyncState.callback;
  callbackContext = asyncState.callbackContext;
  asyncState.busy = false;
  stopAfterWord = asyncState.stopAfterWord;
  asyncState.stopAfterWord = true;
  exitCritical(primask);

  if (stopAfterWord)
    trng::end();

  trng::EventMask events = trng::EventNone;
  if ((flags & trng::DataReadyInterrupt) != 0u)
    events |= trng::EventDataReady;

  if (callback != nullptr && events != trng::EventNone)
    callback(events, value, callbackContext);

  scrubWord(value);
}

bool ensurePendSvServiceRegistered() {
  if (asyncState.serviceRegistered)
    return true;

  const bool registered = PendSV::instance().registerService(
      trng::pendSvServiceId(), trngPendSvService);
  if (registered)
    asyncState.serviceRegistered = true;
  return registered;
}
} // namespace

int trng::irqNumber() {
  return static_cast<int>(TRNG_IRQn);
}

void trng::enableClock() {
#if defined(MCLK_APBCMASK_TRNG_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_TRNG_Msk;
#else
  MCLK->APBCMASK.reg |= MCLK_APBCMASK_TRNG_Msk;
#endif
#endif
}

void trng::disableClock() {
#if defined(MCLK_APBCMASK_TRNG_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK &= ~MCLK_APBCMASK_TRNG_Msk;
#else
  MCLK->APBCMASK.reg &= ~MCLK_APBCMASK_TRNG_Msk;
#endif
#endif
}

void trng::begin(bool runStandby) {
  enableClock();
  regs()->TRNG_INTENCLR = TRNG_INTENCLR_Msk;
  regs()->TRNG_INTFLAG = TRNG_INTFLAG_Msk;
  regs()->TRNG_CTRLA =
      TRNG_CTRLA_ENABLE_Msk | (runStandby ? TRNG_CTRLA_RUNSTDBY_Msk : 0u);
}

void trng::end() {
  regs()->TRNG_INTENCLR = TRNG_INTENCLR_Msk;
  regs()->TRNG_CTRLA = 0;
}

bool trng::enabled() {
  return (regs()->TRNG_CTRLA & TRNG_CTRLA_ENABLE_Msk) != 0;
}

bool trng::dataReady() {
  return (regs()->TRNG_INTFLAG & TRNG_INTFLAG_DATARDY_Msk) != 0;
}

bool trng::read(uint32_t &value) {
  if (!dataReady())
    return false;

  value = regs()->TRNG_DATA;
  return true;
}

uint8_t trng::interruptFlags() {
  return regs()->TRNG_INTFLAG & TRNG_INTFLAG_Msk;
}

void trng::clearInterruptFlags(uint8_t flags) {
  regs()->TRNG_INTFLAG = flags & TRNG_INTFLAG_Msk;
}

void trng::enableInterrupts(uint8_t mask) {
  regs()->TRNG_INTENSET = mask & TRNG_INTENSET_Msk;
}

void trng::disableInterrupts(uint8_t mask) {
  regs()->TRNG_INTENCLR = mask & TRNG_INTENCLR_Msk;
}

bool trng::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  asyncState.callback = callback;
  asyncState.callbackContext = context;
  asyncState.pendingFlags = 0;
  asyncState.pendingValue = 0;
  exitCritical(primask);
  return true;
}

void trng::clearEventCallback() {
  const uint32_t primask = enterCritical();
  asyncState.callback = nullptr;
  asyncState.callbackContext = nullptr;
  asyncState.pendingFlags = 0;
  asyncState.pendingValue = 0;
  asyncState.busy = false;
  asyncState.stopAfterWord = true;
  exitCritical(primask);
  PendSV::instance().clearService(pendSvServiceId());
  asyncState.serviceRegistered = false;
}

bool trng::requestWordAsync(bool runStandby, bool stopAfterWord) {
  if (!ensurePendSvServiceRegistered())
    return false;

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.stopAfterWord = stopAfterWord;
  asyncState.pendingFlags = 0;
  asyncState.pendingValue = 0;
  exitCritical(primask);

  enableClock();
  const bool alreadyEnabled = enabled();
  if (!alreadyEnabled)
    begin(runStandby);
  enableInterrupts(DataReadyInterrupt);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  return true;
}

bool trng::asyncBusy() {
  const uint32_t primask = enterCritical();
  const bool busy = asyncState.busy;
  exitCritical(primask);
  return busy;
}

void trng::handleInterrupt() {
  const uint8_t flags = interruptFlags();
  const uint8_t handled = flags & DataReadyInterrupt;
  if (handled == 0u)
    return;

  uint32_t value = 0;
  if (!read(value))
    return;

  disableInterrupts(handled);
  clearInterruptFlags(handled);

  const uint32_t primask = enterCritical();
  asyncState.pendingFlags |= handled;
  asyncState.pendingValue = value;
  exitCritical(primask);
  scrubWord(value);

  PendSV::instance().setPending(pendSvServiceId());
}

extern "C" void TRNG_Handler(void) {
  trng::handleInterrupt();
}

#endif /* TRNG_AVAILABLE */
