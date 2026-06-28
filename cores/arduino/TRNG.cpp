#include "TRNG.h"

#if TRNG_AVAILABLE

namespace {
inline trng_registers_t *regs() {
  return reinterpret_cast<trng_registers_t *>(TRNG_PERIPH);
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

#endif /* TRNG_AVAILABLE */
