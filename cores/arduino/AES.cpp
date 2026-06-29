#include "AES.h"

#if AES_AVAILABLE

namespace {
inline aes_registers_t *regs() {
  return reinterpret_cast<aes_registers_t *>(AES_PERIPH);
}

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
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

struct AsyncState {
  enum class OutputKind : uint8_t {
    None,
    DataBlock,
    GhashBlock,
  };

  aes::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint32_t *output = nullptr;
  OutputKind outputKind = OutputKind::None;
  uint8_t pendingFlags = 0;
  bool serviceRegistered = false;
  bool busy = false;
};

AsyncState asyncState;

void aesPendSvService(uint8_t serviceId, void *context) {
  (void)serviceId;
  (void)context;

  aes::EventCallback callback = nullptr;
  void *callbackContext = nullptr;
  uint32_t *output = nullptr;
  AsyncState::OutputKind outputKind = AsyncState::OutputKind::None;
  uint8_t flags = 0;

  const uint32_t primask = enterCritical();
  flags = asyncState.pendingFlags;
  asyncState.pendingFlags = 0;
  output = asyncState.output;
  outputKind = asyncState.outputKind;
  callback = asyncState.callback;
  callbackContext = asyncState.callbackContext;
  exitCritical(primask);

  aes::EventMask events = aes::EventNone;
  if ((flags & aes::EncryptionCompleteInterrupt) != 0u) {
    if (output != nullptr && outputKind == AsyncState::OutputKind::DataBlock)
      aes::readOutputBlock(output);
    events |= aes::EventComplete;
  }
  if ((flags & aes::GaloisMultiplyCompleteInterrupt) != 0u) {
    if (output != nullptr && outputKind == AsyncState::OutputKind::GhashBlock)
      aes::readGhash(output);
    events |= aes::EventGaloisComplete;
  }

  aes::end();

  const uint32_t completePrimask = enterCritical();
  asyncState.output = nullptr;
  asyncState.outputKind = AsyncState::OutputKind::None;
  asyncState.busy = false;
  exitCritical(completePrimask);

  if (callback != nullptr && events != aes::EventNone)
    callback(events, callbackContext);
}

bool ensurePendSvServiceRegistered() {
  if (asyncState.serviceRegistered)
    return true;

  const bool registered = PendSV::instance().registerService(
      aes::pendSvServiceId(), aesPendSvService);
  if (registered)
    asyncState.serviceRegistered = true;
  return registered;
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

void aes::writeHashKey(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    regs()->AES_HASHKEY[i] = words[i];
}

void aes::writeGhash(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    regs()->AES_GHASH[i] = words[i];
}

void aes::readGhash(uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    words[i] = regs()->AES_GHASH[i];
}

void aes::beginMessage() {
  regs()->AES_CTRLB = AES_CTRLB_NEWMSG_Msk;
}

void aes::start() {
  regs()->AES_CTRLB = AES_CTRLB_START_Msk;
}

void aes::startGaloisMultiply() { regs()->AES_CTRLB = AES_CTRLB_GFMUL_Msk; }

static void startGaloisMultiplyBlock(const uint32_t words[4]) {
  regs()->AES_CTRLB = AES_CTRLB_GFMUL_Msk;
  aes::writeInputBlock(words);
  regs()->AES_CTRLB = AES_CTRLB_GFMUL_Msk | AES_CTRLB_START_Msk;
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

bool aes::registerEventCallback(EventCallback callback, void *context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered())
    return false;

  const uint32_t primask = enterCritical();
  asyncState.callback = callback;
  asyncState.callbackContext = context;
  asyncState.pendingFlags = 0;
  asyncState.outputKind = AsyncState::OutputKind::None;
  exitCritical(primask);
  return true;
}

void aes::clearEventCallback() {
  const uint32_t primask = enterCritical();
  asyncState.callback = nullptr;
  asyncState.callbackContext = nullptr;
  asyncState.pendingFlags = 0;
  asyncState.output = nullptr;
  asyncState.outputKind = AsyncState::OutputKind::None;
  asyncState.busy = false;
  exitCritical(primask);
  disableInterrupts(EncryptionCompleteInterrupt |
                    GaloisMultiplyCompleteInterrupt);
  PendSV::instance().clearService(pendSvServiceId());
  asyncState.serviceRegistered = false;
}

bool aes::startEcb128Async(Direction direction, const uint32_t key[4],
                           const uint32_t input[4], uint32_t output[4]) {
  if (key == nullptr || input == nullptr || output == nullptr)
    return false;
  if (!ensurePendSvServiceRegistered())
    return false;

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = output;
  asyncState.outputKind = AsyncState::OutputKind::DataBlock;
  asyncState.pendingFlags = 0;
  exitCritical(primask);

  begin();
  configure(Mode::Ecb, KeySize::Bits128, direction);
  if (!writeKey(key, 4)) {
    end();
    primask = enterCritical();
    asyncState.busy = false;
    asyncState.output = nullptr;
    asyncState.outputKind = AsyncState::OutputKind::None;
    exitCritical(primask);
    return false;
  }

  clearInterruptFlags(EncryptionCompleteInterrupt |
                      GaloisMultiplyCompleteInterrupt);
  beginMessage();
  writeInputBlock(input);
  enableInterrupts(EncryptionCompleteInterrupt);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  start();
  return true;
}

bool aes::startGaloisMultiplyAsync(const uint32_t hashKey[4],
                                   const uint32_t input[4],
                                   uint32_t output[4]) {
  if (hashKey == nullptr || input == nullptr || output == nullptr)
    return false;
  if (!ensurePendSvServiceRegistered())
    return false;

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = output;
  asyncState.outputKind = AsyncState::OutputKind::GhashBlock;
  asyncState.pendingFlags = 0;
  exitCritical(primask);

  begin();
  configure(Mode::Gcm, KeySize::Bits128, Direction::Encrypt);
  writeHashKey(hashKey);
  clearInterruptFlags(EncryptionCompleteInterrupt |
                      GaloisMultiplyCompleteInterrupt);
  enableInterrupts(GaloisMultiplyCompleteInterrupt);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  startGaloisMultiplyBlock(input);
  return true;
}

bool aes::asyncBusy() {
  const uint32_t primask = enterCritical();
  const bool busy = asyncState.busy;
  exitCritical(primask);
  return busy;
}

void aes::handleInterrupt() {
  const uint8_t flags = interruptFlags();
  const uint8_t handled =
      flags & (EncryptionCompleteInterrupt | GaloisMultiplyCompleteInterrupt);
  if (handled == 0u)
    return;

  disableInterrupts(handled);
  clearInterruptFlags(handled);

  const uint32_t primask = enterCritical();
  asyncState.pendingFlags |= handled;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
}

extern "C" void AES_Handler(void) {
  aes::handleInterrupt();
}

#endif /* AES_AVAILABLE */
