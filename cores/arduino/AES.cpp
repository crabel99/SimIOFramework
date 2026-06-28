#include "AES.h"

#if AES_AVAILABLE

namespace {
inline aes_registers_t *regs() {
  return reinterpret_cast<aes_registers_t *>(AES_PERIPH);
}

uint8_t expectedKeyWords(aes::KeySize keySize) {
  switch (keySize) {
  case aes::KeySize::Bits128:
    return 4;
  case aes::KeySize::Bits192:
    return 6;
  case aes::KeySize::Bits256:
    return 8;
  }
  return 0;
}
} // namespace

int aes::irqNumber() { return static_cast<int>(AES_IRQn); }

void aes::enableClock() {
#if defined(MCLK_APBCMASK_AES_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_AES_Msk;
#else
  MCLK->APBCMASK.reg |= MCLK_APBCMASK_AES_Msk;
#endif
#endif
}

void aes::disableClock() {
#if defined(MCLK_APBCMASK_AES_Msk)
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK &= ~MCLK_APBCMASK_AES_Msk;
#else
  MCLK->APBCMASK.reg &= ~MCLK_APBCMASK_AES_Msk;
#endif
#endif
}

void aes::reset() {
  regs()->AES_CTRLA = AES_CTRLA_SWRST_Msk;
  while ((regs()->AES_CTRLA & AES_CTRLA_SWRST_Msk) != 0) {
  }
}

void aes::begin() {
  enableClock();
  reset();
  regs()->AES_INTENCLR = AES_INTENCLR_Msk;
  regs()->AES_INTFLAG = AES_INTFLAG_Msk;
  regs()->AES_CTRLA = AES_CTRLA_ENABLE_Msk;
}

void aes::end() {
  regs()->AES_INTENCLR = AES_INTENCLR_Msk;
  regs()->AES_CTRLA = 0;
}

bool aes::enabled() {
  return (regs()->AES_CTRLA & AES_CTRLA_ENABLE_Msk) != 0;
}

void aes::configure(Mode mode, KeySize keySize, Direction direction,
                    bool autoStart) {
  regs()->AES_CTRLA = 0;
  uint32_t control = AES_CTRLA_ENABLE_Msk;
  control |= AES_CTRLA_AESMODE(static_cast<uint32_t>(mode));
  control |= AES_CTRLA_KEYSIZE(static_cast<uint32_t>(keySize));
  control |= AES_CTRLA_CIPHER(static_cast<uint32_t>(direction));
  if (autoStart)
    control |= AES_CTRLA_STARTMODE_AUTO;
  regs()->AES_CTRLA = control;
}

bool aes::writeKey(const uint32_t *words, uint8_t wordCount) {
  if (words == nullptr)
    return false;
  if (wordCount != expectedKeyWords(KeySize::Bits128) &&
      wordCount != expectedKeyWords(KeySize::Bits192) &&
      wordCount != expectedKeyWords(KeySize::Bits256)) {
    return false;
  }

  for (uint8_t i = 0; i < wordCount; ++i)
    regs()->AES_KEYWORD[i] = words[i];
  return true;
}

void aes::writeInputBlock(const uint32_t words[4]) {
  regs()->AES_DATABUFPTR = 0;
  for (uint8_t i = 0; i < 4; ++i)
    regs()->AES_INDATA = words[i];
}

void aes::readOutputBlock(uint32_t words[4]) {
  regs()->AES_DATABUFPTR = 0;
  for (uint8_t i = 0; i < 4; ++i)
    words[i] = regs()->AES_INDATA;
}

void aes::writeInitializationVector(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    regs()->AES_INTVECTV[i] = words[i];
}

void aes::beginMessage() {
  regs()->AES_CTRLB = AES_CTRLB_NEWMSG_Msk;
}

void aes::start() {
  regs()->AES_CTRLB = AES_CTRLB_START_Msk;
}

bool aes::operationComplete() {
  return (regs()->AES_INTFLAG & AES_INTFLAG_ENCCMP_Msk) != 0;
}

uint8_t aes::interruptFlags() {
  return regs()->AES_INTFLAG & AES_INTFLAG_Msk;
}

void aes::clearInterruptFlags(uint8_t flags) {
  regs()->AES_INTFLAG = flags & AES_INTFLAG_Msk;
}

void aes::enableInterrupts(uint8_t mask) {
  regs()->AES_INTENSET = mask & AES_INTENSET_Msk;
}

void aes::disableInterrupts(uint8_t mask) {
  regs()->AES_INTENCLR = mask & AES_INTENCLR_Msk;
}

#endif /* AES_AVAILABLE */
