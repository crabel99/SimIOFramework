#include "TRNG.h"

#if TRNG_AVAILABLE

namespace {
#if defined(__SAMD51__) || defined(__SAME51__)
constexpr uint8_t kDataReadyInterrupt = TRNG_INTFLAG_DATARDY;
constexpr uint8_t kControlEnable = TRNG_CTRLA_ENABLE;
constexpr uint8_t kControlRunStandby = TRNG_CTRLA_RUNSTDBY;

uint8_t controlA() { return TRNG->CTRLA.reg; }
void writeControlA(uint8_t value) { TRNG->CTRLA.reg = value; }
uint8_t rawInterruptFlags() { return TRNG->INTFLAG.reg; }
void writeInterruptFlags(uint8_t value) { TRNG->INTFLAG.reg = value; }
void writeInterruptEnableSet(uint8_t value) { TRNG->INTENSET.reg = value; }
void writeInterruptEnableClear(uint8_t value) { TRNG->INTENCLR.reg = value; }
uint32_t data() { return TRNG->DATA.reg; }
void enableBusClock() { MCLK->APBCMASK.reg |= MCLK_APBCMASK_TRNG; }
void disableBusClock() { MCLK->APBCMASK.reg &= ~MCLK_APBCMASK_TRNG; }
#else
constexpr uint8_t kDataReadyInterrupt = TRNG_INTFLAG_DATARDY_Msk;
constexpr uint8_t kControlEnable = TRNG_CTRLA_ENABLE_Msk;
constexpr uint8_t kControlRunStandby = TRNG_CTRLA_RUNSTDBY_Msk;

uint8_t controlA() { return TRNG_REGS->TRNG_CTRLA; }
void writeControlA(uint8_t value) { TRNG_REGS->TRNG_CTRLA = value; }
uint8_t rawInterruptFlags() { return TRNG_REGS->TRNG_INTFLAG; }
void writeInterruptFlags(uint8_t value) { TRNG_REGS->TRNG_INTFLAG = value; }
void writeInterruptEnableSet(uint8_t value) {
  TRNG_REGS->TRNG_INTENSET = value;
}
void writeInterruptEnableClear(uint8_t value) {
  TRNG_REGS->TRNG_INTENCLR = value;
}
uint32_t data() { return TRNG_REGS->TRNG_DATA; }
void enableBusClock() { MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_TRNG_Msk; }
void disableBusClock() { MCLK_REGS->MCLK_APBCMASK &= ~MCLK_APBCMASK_TRNG_Msk; }
#endif

constexpr uint8_t kInterruptMask = kDataReadyInterrupt;

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
  if ((flags & kDataReadyInterrupt) != 0u)
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

uintptr_t trng::baseAddress() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return reinterpret_cast<uintptr_t>(TRNG);
#else
  return reinterpret_cast<uintptr_t>(TRNG_REGS);
#endif
}

void trng::enableClock() { enableBusClock(); }

void trng::disableClock() { disableBusClock(); }

void trng::begin(bool runStandby) {
  enableClock();
  writeInterruptEnableClear(kInterruptMask);
  writeInterruptFlags(kInterruptMask);
  writeControlA(kControlEnable | (runStandby ? kControlRunStandby : 0u));
}

void trng::end() {
  writeInterruptEnableClear(kInterruptMask);
  writeControlA(0);
}

bool trng::enabled() { return (controlA() & kControlEnable) != 0; }

bool trng::dataReady() {
  return (rawInterruptFlags() & kDataReadyInterrupt) != 0;
}

bool trng::read(uint32_t &value) {
  if (!dataReady())
    return false;

  value = data();
  return true;
}

uint8_t trng::interruptFlags() { return rawInterruptFlags() & kInterruptMask; }

void trng::clearInterruptFlags(uint8_t flags) {
  writeInterruptFlags(flags & kInterruptMask);
}

void trng::enableInterrupts(uint8_t mask) {
  writeInterruptEnableSet(mask & kInterruptMask);
}

void trng::disableInterrupts(uint8_t mask) {
  writeInterruptEnableClear(mask & kInterruptMask);
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
  enableInterrupts(kDataReadyInterrupt);
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
  const uint8_t handled = flags & kDataReadyInterrupt;
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
