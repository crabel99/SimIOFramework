#include "AES.h"

#if AES_AVAILABLE

namespace {
constexpr uint8_t kEncryptionCompleteInterrupt =
    aes::EncryptionCompleteInterrupt;
constexpr uint8_t kGaloisMultiplyCompleteInterrupt =
    aes::GaloisMultiplyCompleteInterrupt;
constexpr uint8_t kInterruptMask =
    kEncryptionCompleteInterrupt | kGaloisMultiplyCompleteInterrupt;

#if defined(__SAMD51__) || defined(__SAME51__)
constexpr uint32_t kControlSoftwareReset = AES_CTRLA_SWRST;
constexpr uint32_t kControlEnable = AES_CTRLA_ENABLE;
constexpr uint8_t kControlNewMessage = AES_CTRLB_NEWMSG;
constexpr uint8_t kControlStart = AES_CTRLB_START;
constexpr uint8_t kControlGaloisMultiply = AES_CTRLB_GFMUL;

uint32_t controlA() { return AES->CTRLA.reg; }
void writeControlA(uint32_t value) { AES->CTRLA.reg = value; }
void writeControlB(uint8_t value) { AES->CTRLB.reg = value; }
uint8_t rawInterruptFlags() { return AES->INTFLAG.reg; }
void writeInterruptFlags(uint8_t value) { AES->INTFLAG.reg = value; }
void writeInterruptEnableSet(uint8_t value) { AES->INTENSET.reg = value; }
void writeInterruptEnableClear(uint8_t value) { AES->INTENCLR.reg = value; }
void writeDataBufferPointer(uint8_t value) { AES->DATABUFPTR.reg = value; }
void writeKeyword(uint8_t index, uint32_t value) {
  AES->KEYWORD[index].reg = value;
}
void writeInputData(uint32_t value) { AES->INDATA.reg = value; }
uint32_t inputData() { return AES->INDATA.reg; }
void writeInitializationVectorWord(uint8_t index, uint32_t value) {
  AES->INTVECTV[index].reg = value;
}
void writeHashKeyWord(uint8_t index, uint32_t value) {
  AES->HASHKEY[index].reg = value;
}
void writeGhashWord(uint8_t index, uint32_t value) {
  AES->GHASH[index].reg = value;
}
uint32_t ghashWord(uint8_t index) { return AES->GHASH[index].reg; }
void enableBusClock() { MCLK->APBCMASK.reg |= MCLK_APBCMASK_AES; }
void disableBusClock() { MCLK->APBCMASK.reg &= ~MCLK_APBCMASK_AES; }
#else
constexpr uint32_t kControlSoftwareReset = AES_CTRLA_SWRST_Msk;
constexpr uint32_t kControlEnable = AES_CTRLA_ENABLE_Msk;
constexpr uint8_t kControlNewMessage = AES_CTRLB_NEWMSG_Msk;
constexpr uint8_t kControlStart = AES_CTRLB_START_Msk;
constexpr uint8_t kControlGaloisMultiply = AES_CTRLB_GFMUL_Msk;

uint32_t controlA() { return AES_REGS->AES_CTRLA; }
void writeControlA(uint32_t value) { AES_REGS->AES_CTRLA = value; }
void writeControlB(uint8_t value) { AES_REGS->AES_CTRLB = value; }
uint8_t rawInterruptFlags() { return AES_REGS->AES_INTFLAG; }
void writeInterruptFlags(uint8_t value) { AES_REGS->AES_INTFLAG = value; }
void writeInterruptEnableSet(uint8_t value) {
  AES_REGS->AES_INTENSET = value;
}
void writeInterruptEnableClear(uint8_t value) {
  AES_REGS->AES_INTENCLR = value;
}
void writeDataBufferPointer(uint8_t value) {
  AES_REGS->AES_DATABUFPTR = value;
}
void writeKeyword(uint8_t index, uint32_t value) {
  AES_REGS->AES_KEYWORD[index] = value;
}
void writeInputData(uint32_t value) { AES_REGS->AES_INDATA = value; }
uint32_t inputData() { return AES_REGS->AES_INDATA; }
void writeInitializationVectorWord(uint8_t index, uint32_t value) {
  AES_REGS->AES_INTVECTV[index] = value;
}
void writeHashKeyWord(uint8_t index, uint32_t value) {
  AES_REGS->AES_HASHKEY[index] = value;
}
void writeGhashWord(uint8_t index, uint32_t value) {
  AES_REGS->AES_GHASH[index] = value;
}
uint32_t ghashWord(uint8_t index) { return AES_REGS->AES_GHASH[index]; }
void enableBusClock() { MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_AES_Msk; }
void disableBusClock() { MCLK_REGS->MCLK_APBCMASK &= ~MCLK_APBCMASK_AES_Msk; }
#endif

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
  if ((flags & kEncryptionCompleteInterrupt) != 0u) {
    if (output != nullptr && outputKind == AsyncState::OutputKind::DataBlock)
      aes::readOutputBlock(output);
    events |= aes::EventComplete;
  }
  if ((flags & kGaloisMultiplyCompleteInterrupt) != 0u) {
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

uintptr_t aes::baseAddress() {
#if defined(__SAMD51__) || defined(__SAME51__)
  return reinterpret_cast<uintptr_t>(AES);
#else
  return reinterpret_cast<uintptr_t>(AES_REGS);
#endif
}

void aes::enableClock() { enableBusClock(); }

void aes::disableClock() { disableBusClock(); }

void aes::reset() {
  writeControlA(kControlSoftwareReset);
  while ((controlA() & kControlSoftwareReset) != 0) {
  }
}

void aes::begin() {
  enableClock();
  reset();
  writeInterruptEnableClear(kInterruptMask);
  writeInterruptFlags(kInterruptMask);
  writeControlA(kControlEnable);
}

void aes::end() {
  writeInterruptEnableClear(kInterruptMask);
  writeControlA(0);
}

bool aes::enabled() {
  return (controlA() & kControlEnable) != 0;
}

void aes::configure(Mode mode, KeySize keySize, Direction direction,
                    bool autoStart) {
  writeControlA(0);
  uint32_t control = kControlEnable;
  control |= AES_CTRLA_AESMODE(static_cast<uint32_t>(mode));
  control |= AES_CTRLA_KEYSIZE(static_cast<uint32_t>(keySize));
  control |= static_cast<uint32_t>(direction) << AES_CTRLA_CIPHER_Pos;
  if (autoStart)
    control |= AES_CTRLA_STARTMODE_AUTO;
  writeControlA(control);
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
    writeKeyword(i, words[i]);
  return true;
}

void aes::writeInputBlock(const uint32_t words[4]) {
  writeDataBufferPointer(0);
  for (uint8_t i = 0; i < 4; ++i)
    writeInputData(words[i]);
}

void aes::readOutputBlock(uint32_t words[4]) {
  writeDataBufferPointer(0);
  for (uint8_t i = 0; i < 4; ++i)
    words[i] = inputData();
}

void aes::writeInitializationVector(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    writeInitializationVectorWord(i, words[i]);
}

void aes::writeHashKey(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    writeHashKeyWord(i, words[i]);
}

void aes::writeGhash(const uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    writeGhashWord(i, words[i]);
}

void aes::readGhash(uint32_t words[4]) {
  for (uint8_t i = 0; i < 4; ++i)
    words[i] = ghashWord(i);
}

void aes::beginMessage() {
  writeControlB(kControlNewMessage);
}

void aes::start() { writeControlB(kControlStart); }

void aes::startGaloisMultiply() {
  writeControlB(kControlGaloisMultiply);
}

static void startGaloisMultiplyBlock(const uint32_t words[4]) {
  writeControlB(kControlGaloisMultiply);
  aes::writeInputBlock(words);
  writeControlB(kControlGaloisMultiply | kControlStart);
}

bool aes::operationComplete() {
  return (rawInterruptFlags() & kEncryptionCompleteInterrupt) != 0;
}

uint8_t aes::interruptFlags() {
  return rawInterruptFlags() & kInterruptMask;
}

void aes::clearInterruptFlags(uint8_t flags) {
  writeInterruptFlags(flags & kInterruptMask);
}

void aes::enableInterrupts(uint8_t mask) {
  writeInterruptEnableSet(mask & kInterruptMask);
}

void aes::disableInterrupts(uint8_t mask) {
  writeInterruptEnableClear(mask & kInterruptMask);
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
  disableInterrupts(kInterruptMask);
  PendSV::instance().clearService(pendSvServiceId());
  asyncState.serviceRegistered = false;
}

bool aes::startEcbAsync(Direction direction, KeySize keySize,
                        const uint32_t *key, const uint32_t input[4],
                        uint32_t output[4]) {
  if (key == nullptr || input == nullptr || output == nullptr)
    return false;
  const uint8_t wordCount = expectedKeyWords(keySize);
  if (wordCount == 0)
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
  configure(Mode::Ecb, keySize, direction);
  if (!writeKey(key, wordCount)) {
    end();
    primask = enterCritical();
    asyncState.busy = false;
    asyncState.output = nullptr;
    asyncState.outputKind = AsyncState::OutputKind::None;
    exitCritical(primask);
    return false;
  }

  clearInterruptFlags(kInterruptMask);
  beginMessage();
  writeInputBlock(input);
  enableInterrupts(kEncryptionCompleteInterrupt);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  start();
  return true;
}

bool aes::startEcb128Async(Direction direction, const uint32_t key[4],
                           const uint32_t input[4], uint32_t output[4]) {
  return startEcbAsync(direction, KeySize::Bits128, key, input, output);
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
  clearInterruptFlags(kInterruptMask);
  enableInterrupts(kGaloisMultiplyCompleteInterrupt);
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
  const uint8_t handled = flags & kInterruptMask;
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
