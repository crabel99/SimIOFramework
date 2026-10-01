// Ported from AsyncCortex ICM at 1b073eb4e693515d26252b91462b80ac8fb03e54.
#include "ICM.h"

#if ICM_AVAILABLE

#include <string.h>

#if defined(ICM_REGS)
#define SIMIO_ICM_REG(name) (ICM_REGS->ICM_##name)
#define SIMIO_ICM_UIHVAL(index) (ICM_REGS->ICM_UIHVAL[index])
#else
#define SIMIO_ICM_REG(name) (ICM->name.reg)
#define SIMIO_ICM_UIHVAL(index) (ICM->UIHVAL[index].reg)
#define ICM_IER_URAD_Msk ICM_IER_URAD
#define ICM_SR_ENABLE_Msk ICM_SR_ENABLE
#define ICM_CFG_UIHASH_Msk ICM_CFG_UIHASH
#define ICM_CTRL_ENABLE_Msk ICM_CTRL_ENABLE
#define ICM_CTRL_DISABLE_Msk ICM_CTRL_DISABLE
#define ICM_CTRL_SWRST_Msk ICM_CTRL_SWRST
#endif

namespace {
constexpr uint32_t kRegion0 = 1u;
constexpr uint32_t kRegion0RawDisabledStatus = ICM_SR_RAWRMDIS(kRegion0);
constexpr uint32_t kCompleteInterrupt = ICM_IER_RHC(kRegion0) | ICM_IER_REC(kRegion0);
constexpr uint32_t kMismatchInterrupt = ICM_IER_RDM(kRegion0);
constexpr uint32_t kErrorInterrupt = ICM_IER_RBE(kRegion0) | ICM_IER_URAD_Msk;
constexpr uint32_t kInterruptMask = kCompleteInterrupt | kErrorInterrupt;
constexpr uint32_t kMonitorInterruptMask = kMismatchInterrupt | kErrorInterrupt;
constexpr uint32_t kAllAsyncInterrupts = kInterruptMask | kMonitorInterruptMask;
constexpr size_t kBlockSize = 64u;
constexpr size_t kMaxHashDescriptorCount = 8u;
constexpr size_t kMaxDataDescriptorCount = kMaxHashDescriptorCount - 1u;
constexpr size_t kMaxDescriptorBlocks = 65536u;
constexpr size_t kMaxDescriptorBytes = kMaxDescriptorBlocks * kBlockSize;
static_assert(icm::MaxInputLength ==
                  (kMaxDataDescriptorCount * kMaxDescriptorBytes) + (kBlockSize - 1u),
              "ICM hash input limit must match the fixed descriptor list");

struct alignas(64) IcmDescriptor {
  uint32_t raddr;
  uint32_t rcfg;
  uint32_t rctrl;
  uint32_t rnext;
};

struct AsyncState {
  icm::EventCallback callback = nullptr;
  void* callbackContext = nullptr;
  uint8_t* output = nullptr;
  size_t outputLength = 0;
  uint32_t pendingFlags = 0;
  uint32_t lastFlags = 0;
  bool serviceRegistered = false;
  bool busy = false;
  bool keepSession = false;
  bool regionDisabledForSession = false;
};

alignas(64) IcmDescriptor descriptors[kMaxHashDescriptorCount];
alignas(64) uint8_t hashPadding[2u * kBlockSize];
alignas(128) volatile uint8_t hashArea[128];
AsyncState asyncState;
icm::TimingCounters icmTimingCounters;

uint32_t enterCritical() {
  const uint32_t primask = __get_PRIMASK();
  __disable_irq();
  return primask;
}

void exitCritical(uint32_t primask) {
  __set_PRIMASK(primask);
}

uint32_t cyclesNow() {
  return DWT->CYCCNT;
}

void writeBe64(uint64_t value, uint8_t* output) {
  for (size_t index = 0; index < sizeof(uint64_t); ++index) {
    output[7u - index] = static_cast<uint8_t>(value & 0xFFu);
    value >>= 8u;
  }
}

uint32_t algorithmValue(icm::Algorithm algorithm);

bool addHashDataDescriptor(size_t& descriptorCount, const uint8_t* address, size_t bytes,
                           icm::Algorithm algorithm) {
  if (bytes == 0u) {
    return true;
  }
  if (address == nullptr || (bytes % kBlockSize) != 0u) {
    return false;
  }

  while (bytes != 0u) {
    if (descriptorCount >= kMaxHashDescriptorCount) {
      return false;
    }
    const size_t chunk = bytes > kMaxDescriptorBytes ? kMaxDescriptorBytes : bytes;
    descriptors[descriptorCount].raddr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(address));
    descriptors[descriptorCount].rcfg = ICM_RCFG_RHIEN_EN | ICM_RCFG_ECIEN_EN | ICM_RCFG_BEIEN_EN |
                                        ICM_RCFG_ALGO(algorithmValue(algorithm));
    descriptors[descriptorCount].rctrl = ICM_RCTRL_TRSIZE((chunk / kBlockSize) - 1u);
    descriptors[descriptorCount].rnext = 0u;
    ++descriptorCount;
    address += chunk;
    bytes -= chunk;
  }
  return true;
}

bool prepareHashBlockStateDescriptors(icm::Algorithm algorithm, const uint8_t* input,
                                      size_t inputLength) {
  if (input == nullptr || inputLength == 0u || (inputLength % kBlockSize) != 0u ||
      inputLength > icm::MaxInputLength) {
    return false;
  }

  size_t descriptorCount = 0;
  if (!addHashDataDescriptor(descriptorCount, input, inputLength, algorithm) ||
      descriptorCount == 0u) {
    return false;
  }

  descriptors[descriptorCount - 1u].rcfg |= ICM_RCFG_EOM_YES;
  for (size_t index = 0; index + 1u < descriptorCount; ++index) {
    descriptors[index].rnext = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&descriptors[index + 1u]));
  }
  return true;
}

bool addHashPaddingDescriptor(size_t& descriptorCount, const uint8_t* tail, size_t tailLength,
                              size_t totalLength, icm::Algorithm algorithm) {
  if (descriptorCount >= kMaxHashDescriptorCount || tailLength >= kBlockSize ||
      (tail == nullptr && tailLength != 0u)) {
    return false;
  }

  const size_t paddedLength = ((tailLength + 9u + kBlockSize - 1u) / kBlockSize) * kBlockSize;
  memset(hashPadding, 0, paddedLength);
  if (tailLength != 0u) {
    memcpy(hashPadding, tail, tailLength);
  }
  hashPadding[tailLength] = 0x80u;
  writeBe64(static_cast<uint64_t>(totalLength) * 8u, hashPadding + paddedLength - 8u);

  descriptors[descriptorCount].raddr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hashPadding));
  descriptors[descriptorCount].rcfg = ICM_RCFG_EOM_YES | ICM_RCFG_RHIEN_EN | ICM_RCFG_ECIEN_EN |
                                      ICM_RCFG_BEIEN_EN | ICM_RCFG_ALGO(algorithmValue(algorithm));
  descriptors[descriptorCount].rctrl = ICM_RCTRL_TRSIZE((paddedLength / kBlockSize) - 1u);
  descriptors[descriptorCount].rnext = 0u;
  ++descriptorCount;
  return true;
}

bool prepareHashDescriptors(icm::Algorithm algorithm, const icm::HashSegment* segments,
                            size_t segmentCount, size_t initialLength) {
  if (segments == nullptr || segmentCount == 0u || segmentCount > kMaxDataDescriptorCount ||
      (initialLength % kBlockSize) != 0u || initialLength > icm::MaxInputLength) {
    return false;
  }

  size_t totalLength = initialLength;
  for (size_t index = 0; index < segmentCount; ++index) {
    if (segments[index].data == nullptr && segments[index].length != 0u) {
      return false;
    }
    if (index + 1u < segmentCount && (segments[index].length % kBlockSize) != 0u) {
      return false;
    }
    if (segments[index].length > icm::MaxInputLength - totalLength) {
      return false;
    }
    totalLength += segments[index].length;
  }

  size_t descriptorCount = 0;
  for (size_t index = 0; index < segmentCount; ++index) {
    const bool finalSegment = index + 1u == segmentCount;
    const size_t tailLength = finalSegment ? (segments[index].length % kBlockSize) : 0u;
    const size_t fullBytes = segments[index].length - tailLength;
    if (!addHashDataDescriptor(descriptorCount, segments[index].data, fullBytes, algorithm)) {
      return false;
    }
  }

  const icm::HashSegment& last = segments[segmentCount - 1u];
  const size_t tailLength = last.length % kBlockSize;
  const uint8_t* tail = tailLength == 0u ? nullptr : last.data + (last.length - tailLength);
  if (!addHashPaddingDescriptor(descriptorCount, tail, tailLength, totalLength, algorithm)) {
    return false;
  }

  for (size_t index = 0; index + 1u < descriptorCount; ++index) {
    descriptors[index].rnext = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&descriptors[index + 1u]));
  }
  return descriptorCount != 0u;
}

uint32_t algorithmValue(icm::Algorithm algorithm) {
  switch (algorithm) {
  case icm::Algorithm::Sha1:
    return ICM_CFG_UALGO_SHA1_Val;
  case icm::Algorithm::Sha224:
    return ICM_CFG_UALGO_SHA224_Val;
  case icm::Algorithm::Sha256:
    return ICM_CFG_UALGO_SHA256_Val;
  }
  return ICM_CFG_UALGO_SHA1_Val;
}

void writeControl(uint32_t value) {
  SIMIO_ICM_REG(CTRL) = value;
}
uint32_t status() {
  return SIMIO_ICM_REG(SR);
}
bool waitUntilDisabled() {
  for (uint32_t attempts = 0; attempts < 10000u; ++attempts) {
    if ((status() & ICM_SR_ENABLE_Msk) == 0u) {
      return true;
    }
  }
  return false;
}
bool waitUntilEnabledOrDone() {
  for (uint32_t attempts = 0; attempts < 10000u; ++attempts) {
    if ((status() & ICM_SR_ENABLE_Msk) != 0u || (SIMIO_ICM_REG(ISR) & kInterruptMask) != 0u) {
      return true;
    }
  }
  return false;
}
bool waitUntilRegionDisableAccepted() {
  for (uint32_t attempts = 0; attempts < 10000u; ++attempts) {
    if ((status() & kRegion0RawDisabledStatus) == kRegion0RawDisabledStatus) {
      return true;
    }
  }
  return false;
}
void writeInterruptEnable(uint32_t value) {
  SIMIO_ICM_REG(IER) = value;
}
void writeInterruptDisable(uint32_t value) {
  SIMIO_ICM_REG(IDR) = value;
}
void writeDescriptorAddress(uintptr_t address) {
  SIMIO_ICM_REG(DSCR) = static_cast<uint32_t>(address);
}
void writeHashAddress(uintptr_t address) {
  SIMIO_ICM_REG(HASH) = static_cast<uint32_t>(address);
}

void applyNvmCacheHostWorkaround();

void disableRegion0() {
  const uint32_t startCycles = cyclesNow();
  ++icmTimingCounters.regionDisableCalls;
  writeInterruptDisable(kAllAsyncInterrupts);
  writeControl(ICM_CTRL_RMDIS(kRegion0));
  (void)waitUntilRegionDisableAccepted();
  icmTimingCounters.regionDisableCycles += cyclesNow() - startCycles;
}

uint32_t loadStateWord(const uint8_t* data) {
  return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8u) |
         (static_cast<uint32_t>(data[2]) << 16u) | (static_cast<uint32_t>(data[3]) << 24u);
}

bool configureUserInitialHash(icm::Algorithm algorithm, const uint8_t* initialState,
                              size_t initialStateLength) {
  const size_t expectedLength = icm::stateLength(algorithm);
  if (initialState == nullptr || initialStateLength != expectedLength ||
      (initialStateLength % sizeof(uint32_t)) != 0u) {
    return false;
  }

  const size_t wordCount = initialStateLength / sizeof(uint32_t);
  for (size_t index = 0; index < 8u; ++index) {
    const uint32_t value =
        index < wordCount ? loadStateWord(initialState + (index * sizeof(uint32_t))) : 0u;
    SIMIO_ICM_UIHVAL(index) = value;
  }
  SIMIO_ICM_REG(CFG) = ICM_CFG_UIHASH_Msk | ICM_CFG_UALGO(algorithmValue(algorithm));
  return true;
}

bool startPreparedHash(bool keepSession, icm::Algorithm algorithm, const uint8_t* initialState,
                       size_t initialStateLength) {
  const uint32_t startCycles = cyclesNow();
  ++icmTimingCounters.hashStartCalls;
  applyNvmCacheHostWorkaround();

  if (icm::enabled()) {
    bool regionDisabled = false;
    uint32_t primask = enterCritical();
    regionDisabled = asyncState.regionDisabledForSession;
    asyncState.regionDisabledForSession = false;
    exitCritical(primask);
    if (!regionDisabled) {
      disableRegion0();
    } else {
      ++icmTimingCounters.sessionContinuations;
    }
  } else {
    icm::begin();
    applyNvmCacheHostWorkaround();
  }

  if (initialState != nullptr) {
    if (!configureUserInitialHash(algorithm, initialState, initialStateLength)) {
      icmTimingCounters.hashStartCycles += cyclesNow() - startCycles;
      return false;
    }
  } else {
    SIMIO_ICM_REG(CFG) = 0u;
  }
  writeDescriptorAddress(reinterpret_cast<uintptr_t>(&descriptors[0]));
  writeHashAddress(reinterpret_cast<uintptr_t>(hashArea));
  __DSB();
  writeInterruptEnable(kInterruptMask);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(icm::irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(icm::irqNumber()));

  const uint32_t primask = enterCritical();
  asyncState.keepSession = keepSession;
  asyncState.regionDisabledForSession = false;
  exitCritical(primask);

  writeControl(ICM_CTRL_ENABLE_Msk | ICM_CTRL_RMEN(kRegion0));
  __DSB();
  const uint32_t waitStartCycles = cyclesNow();
  const bool started = waitUntilEnabledOrDone();
  icmTimingCounters.hashStartWaitCycles += cyclesNow() - waitStartCycles;
  icmTimingCounters.hashStartCycles += cyclesNow() - startCycles;
  return started;
}

void copyHashArea(uint8_t* output, size_t outputLength) {
  const uint32_t startCycles = cyclesNow();
  ++icmTimingCounters.hashCopyCalls;
  __DSB();
  applyNvmCacheHostWorkaround();
  __DSB();
  for (size_t index = 0; index < outputLength; ++index) {
    output[index] = hashArea[index];
  }
  icmTimingCounters.hashCopyCycles += cyclesNow() - startCycles;
}

void applyNvmCacheHostWorkaround() {
#if defined(NVMCTRL_REGS) && defined(NVMCTRL_CTRLA_CACHEDIS1_Msk)
  // DS80000748 2.6.10 requires AHB1 cache cleanup before ICM host access.
  NVMCTRL_REGS->NVMCTRL_CTRLA |= NVMCTRL_CTRLA_CACHEDIS1_Msk;
  __DSB();
  NVMCTRL_REGS->NVMCTRL_CTRLA &= ~NVMCTRL_CTRLA_CACHEDIS1_Msk;
  __DSB();
#elif defined(NVMCTRL) && defined(NVMCTRL_CTRLA_CACHEDIS1)
  NVMCTRL->CTRLA.reg |= NVMCTRL_CTRLA_CACHEDIS1;
  __DSB();
  NVMCTRL->CTRLA.reg &= ~NVMCTRL_CTRLA_CACHEDIS1;
  __DSB();
#endif
}

bool ensurePendSvServiceRegistered() {
  if (asyncState.serviceRegistered) {
    return true;
  }

  const bool registered = PendSV::instance().registerService(
      icm::pendSvServiceId(), [](uint8_t serviceId, void* context) {
        (void)serviceId;
        (void)context;

        icm::EventCallback callback = nullptr;
        void* callbackContext = nullptr;
        uint8_t* output = nullptr;
        size_t outputLength = 0;
        uint32_t flags = 0;
        bool keepSession = false;

        const uint32_t primask = enterCritical();
        flags = asyncState.pendingFlags;
        asyncState.pendingFlags = 0;
        output = asyncState.output;
        outputLength = asyncState.outputLength;
        callback = asyncState.callback;
        callbackContext = asyncState.callbackContext;
        keepSession = asyncState.keepSession;
        exitCritical(primask);

        icm::EventMask events = icm::EventNone;
        if ((flags & kErrorInterrupt) != 0u) {
          events |= icm::EventError;
        }
        if ((flags & kMismatchInterrupt) != 0u) {
          events |= icm::EventMismatch;
        }
        if ((flags & kCompleteInterrupt) != 0u) {
          if (output != nullptr && outputLength != 0u) {
            copyHashArea(output, outputLength);
          }
          events |= icm::EventComplete;
        }

        if (!keepSession) {
          icm::end();
        } else {
          disableRegion0();
          ++icmTimingCounters.sessionKeptCompletions;
          const uint32_t sessionPrimask = enterCritical();
          asyncState.regionDisabledForSession = true;
          exitCritical(sessionPrimask);
        }

        const uint32_t completePrimask = enterCritical();
        asyncState.output = nullptr;
        asyncState.outputLength = 0;
        asyncState.busy = false;
        asyncState.keepSession = false;
        exitCritical(completePrimask);

        if (callback != nullptr && events != icm::EventNone) {
          callback(events, callbackContext);
        }
      });
  if (registered) {
    asyncState.serviceRegistered = true;
  }
  return registered;
}
} // namespace

uintptr_t icm::baseAddress() {
#if defined(ICM_REGS)
  return reinterpret_cast<uintptr_t>(ICM_REGS);
#else
  return reinterpret_cast<uintptr_t>(ICM);
#endif
}

int icm::irqNumber() {
  return static_cast<int>(ICM_IRQn);
}

void icm::enableClock() {
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_AHBMASK |= MCLK_AHBMASK_ICM_Msk;
  MCLK_REGS->MCLK_APBCMASK |= MCLK_APBCMASK_ICM_Msk;
#else
  MCLK->AHBMASK.reg |= MCLK_AHBMASK_ICM;
  MCLK->APBCMASK.reg |= MCLK_APBCMASK_ICM;
#endif
}

void icm::disableClock() {
#if defined(MCLK_REGS)
  MCLK_REGS->MCLK_APBCMASK &= ~MCLK_APBCMASK_ICM_Msk;
  MCLK_REGS->MCLK_AHBMASK &= ~MCLK_AHBMASK_ICM_Msk;
#else
  MCLK->APBCMASK.reg &= ~MCLK_APBCMASK_ICM;
  MCLK->AHBMASK.reg &= ~MCLK_AHBMASK_ICM;
#endif
}

void icm::reset() {
  writeControl(ICM_CTRL_SWRST_Msk);
  (void)waitUntilDisabled();
  __DSB();
  __ISB();
}

void icm::begin() {
  const uint32_t startCycles = cyclesNow();
  ++icmTimingCounters.beginCalls;
  enableClock();
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  reset();
  SIMIO_ICM_REG(CFG) = 0u;
  SIMIO_ICM_REG(IDR) = kAllAsyncInterrupts;
  SIMIO_ICM_REG(DSCR) = 0u;
  SIMIO_ICM_REG(HASH) = 0u;
  icmTimingCounters.beginCycles += cyclesNow() - startCycles;
}

void icm::end() {
  const uint32_t startCycles = cyclesNow();
  ++icmTimingCounters.endCalls;
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
  writeInterruptDisable(kAllAsyncInterrupts);
  writeControl(ICM_CTRL_RMDIS(kRegion0));
  (void)waitUntilRegionDisableAccepted();
  writeControl(ICM_CTRL_DISABLE_Msk);
  (void)waitUntilDisabled();
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  __DSB();
  __ISB();
  icmTimingCounters.endCycles += cyclesNow() - startCycles;
}

bool icm::enabled() {
  return (status() & ICM_SR_ENABLE_Msk) != 0u;
}

size_t icm::digestLength(Algorithm algorithm) {
  switch (algorithm) {
  case Algorithm::Sha1:
    return Sha1DigestLength;
  case Algorithm::Sha224:
    return Sha224DigestLength;
  case Algorithm::Sha256:
    return Sha256DigestLength;
  }
  return 0u;
}

size_t icm::stateLength(Algorithm algorithm) {
  switch (algorithm) {
  case Algorithm::Sha1:
    return Sha1DigestLength;
  case Algorithm::Sha224:
  case Algorithm::Sha256:
    return Sha256DigestLength;
  }
  return 0u;
}

bool icm::registerEventCallback(EventCallback callback, void* context) {
  if (callback == nullptr || !ensurePendSvServiceRegistered()) {
    return false;
  }

  const uint32_t primask = enterCritical();
  asyncState.callback = callback;
  asyncState.callbackContext = context;
  asyncState.pendingFlags = 0;
  asyncState.lastFlags = 0;
  exitCritical(primask);
  return true;
}

void icm::clearEventCallback() {
  const uint32_t primask = enterCritical();
  asyncState.callback = nullptr;
  asyncState.callbackContext = nullptr;
  asyncState.pendingFlags = 0;
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.keepSession = false;
  asyncState.regionDisabledForSession = false;
  asyncState.busy = false;
  exitCritical(primask);
  writeInterruptDisable(kAllAsyncInterrupts);
  NVIC_DisableIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  if (enabled()) {
    end();
  }
  PendSV::instance().clearService(pendSvServiceId());
  asyncState.serviceRegistered = false;
}

bool icm::startHashAsync(Algorithm algorithm, const uint8_t* input, size_t inputLength,
                         uint8_t* output, size_t outputLength) {
  const HashSegment segment = {input, inputLength};
  return startHashSegmentsAsync(algorithm, &segment, 1u, output, outputLength);
}

bool icm::startHashSegmentsAsync(Algorithm algorithm, const HashSegment* segments,
                                 size_t segmentCount, uint8_t* output, size_t outputLength) {
  return startHashSegmentsSessionAsync(algorithm, segments, segmentCount, output, outputLength,
                                       false);
}

bool icm::startHashSegmentsSessionAsync(Algorithm algorithm, const HashSegment* segments,
                                        size_t segmentCount, uint8_t* output, size_t outputLength,
                                        bool keepSession) {
  const size_t expectedDigestLength = digestLength(algorithm);
  if (expectedDigestLength == 0u || output == nullptr || outputLength != expectedDigestLength ||
      !ensurePendSvServiceRegistered()) {
    return false;
  }

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = output;
  asyncState.outputLength = outputLength;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = keepSession;
  exitCritical(primask);

  if (!prepareHashDescriptors(algorithm, segments, segmentCount, 0u)) {
    primask = enterCritical();
    asyncState.output = nullptr;
    asyncState.outputLength = 0;
    asyncState.pendingFlags = 0;
    asyncState.keepSession = false;
    asyncState.regionDisabledForSession = false;
    asyncState.busy = false;
    exitCritical(primask);
    return false;
  }

  for (uint8_t attempt = 0; attempt < 2u; ++attempt) {
    if (startPreparedHash(keepSession, algorithm, nullptr, 0u)) {
      return true;
    }
    end();
  }

  primask = enterCritical();
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = false;
  asyncState.regionDisabledForSession = false;
  asyncState.busy = false;
  exitCritical(primask);
  return false;
}

bool icm::startHashContinuationAsync(Algorithm algorithm, const uint8_t* initialState,
                                     size_t initialStateLength, size_t processedLength,
                                     const HashSegment* segments, size_t segmentCount,
                                     uint8_t* output, size_t outputLength, bool keepSession) {
  const size_t expectedDigestLength = digestLength(algorithm);
  const size_t expectedStateLength = stateLength(algorithm);
  if (expectedDigestLength == 0u || output == nullptr || outputLength != expectedDigestLength || initialState == nullptr ||
      initialStateLength != expectedStateLength || (processedLength % kBlockSize) != 0u ||
      !ensurePendSvServiceRegistered()) {
    return false;
  }

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = output;
  asyncState.outputLength = outputLength;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = keepSession;
  exitCritical(primask);

  if (!prepareHashDescriptors(algorithm, segments, segmentCount, processedLength)) {
    primask = enterCritical();
    asyncState.output = nullptr;
    asyncState.outputLength = 0;
    asyncState.pendingFlags = 0;
    asyncState.keepSession = false;
    asyncState.regionDisabledForSession = false;
    asyncState.busy = false;
    exitCritical(primask);
    return false;
  }

  for (uint8_t attempt = 0; attempt < 2u; ++attempt) {
    if (startPreparedHash(keepSession, algorithm, initialState, initialStateLength)) {
      return true;
    }
    end();
  }

  primask = enterCritical();
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = false;
  asyncState.regionDisabledForSession = false;
  asyncState.busy = false;
  exitCritical(primask);
  return false;
}

bool icm::startHashBlockStateAsync(Algorithm algorithm, const uint8_t* input, size_t inputLength,
                                   uint8_t* output, size_t outputLength, bool keepSession) {
  const size_t expectedStateLength = stateLength(algorithm);
  if (expectedStateLength == 0u || output == nullptr || outputLength != expectedStateLength ||
      !ensurePendSvServiceRegistered()) {
    return false;
  }

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = output;
  asyncState.outputLength = outputLength;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = keepSession;
  exitCritical(primask);

  if (!prepareHashBlockStateDescriptors(algorithm, input, inputLength)) {
    primask = enterCritical();
    asyncState.output = nullptr;
    asyncState.outputLength = 0;
    asyncState.pendingFlags = 0;
    asyncState.keepSession = false;
    asyncState.regionDisabledForSession = false;
    asyncState.busy = false;
    exitCritical(primask);
    return false;
  }

  for (uint8_t attempt = 0; attempt < 2u; ++attempt) {
    if (startPreparedHash(keepSession, algorithm, nullptr, 0u)) {
      return true;
    }
    end();
  }

  primask = enterCritical();
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.pendingFlags = 0;
  asyncState.keepSession = false;
  asyncState.regionDisabledForSession = false;
  asyncState.busy = false;
  exitCritical(primask);
  return false;
}

bool icm::startRegionDigestWritebackAsync(Algorithm algorithm, const void* address, size_t bytes,
                                          volatile uint8_t* digest, size_t digestLength) {
  const size_t expectedDigestLength =
      digestLength == icm::digestLength(algorithm) ? digestLength : 0u;
  if (address == nullptr || digest == nullptr || expectedDigestLength == 0u || bytes == 0u ||
      (bytes % kBlockSize) != 0u || !ensurePendSvServiceRegistered()) {
    return false;
  }

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.pendingFlags = 0;
  exitCritical(primask);

  begin();
  applyNvmCacheHostWorkaround();
  SIMIO_ICM_REG(CFG) = 0u;
  descriptors[0].raddr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(address));
  descriptors[0].rcfg = ICM_RCFG_CDWBN_WRBA | ICM_RCFG_EOM_YES | ICM_RCFG_RHIEN_EN |
                        ICM_RCFG_ECIEN_EN | ICM_RCFG_BEIEN_EN |
                        ICM_RCFG_ALGO(algorithmValue(algorithm));
  descriptors[0].rctrl = ICM_RCTRL_TRSIZE((bytes / kBlockSize) - 1u);
  descriptors[0].rnext = 0u;

  writeDescriptorAddress(reinterpret_cast<uintptr_t>(&descriptors[0]));
  writeHashAddress(reinterpret_cast<uintptr_t>(digest));
  __DSB();
  writeInterruptEnable(kCompleteInterrupt | kErrorInterrupt);
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  writeControl(ICM_CTRL_ENABLE_Msk | ICM_CTRL_RMEN(kRegion0));
  __DSB();
  if (waitUntilEnabledOrDone()) {
    return true;
  }
  clearEventCallback();
  end();
  return false;
}

bool icm::startRegionCompareAsync(Algorithm algorithm, const void* address, size_t bytes,
                                  volatile uint8_t* digest, size_t digestLength, bool continuous) {
  const size_t expectedDigestLength =
      digestLength == icm::digestLength(algorithm) ? digestLength : 0u;
  if (address == nullptr || digest == nullptr || expectedDigestLength == 0u || bytes == 0u ||
      (bytes % kBlockSize) != 0u || !ensurePendSvServiceRegistered()) {
    return false;
  }

  uint32_t primask = enterCritical();
  if (asyncState.busy || asyncState.callback == nullptr) {
    exitCritical(primask);
    return false;
  }
  asyncState.busy = true;
  asyncState.output = nullptr;
  asyncState.outputLength = 0;
  asyncState.pendingFlags = 0;
  exitCritical(primask);

  begin();
  applyNvmCacheHostWorkaround();
  SIMIO_ICM_REG(CFG) = 0u;
  descriptors[0].raddr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(address));
  descriptors[0].rcfg = ICM_RCFG_CDWBN_COMP | ICM_RCFG_DMIEN_EN | ICM_RCFG_BEIEN_EN |
                        ICM_RCFG_ALGO(algorithmValue(algorithm));
  if (continuous) {
    descriptors[0].rcfg |= ICM_RCFG_WRAP_YES | ICM_RCFG_EOM_NO;
  } else {
    descriptors[0].rcfg |= ICM_RCFG_EOM_YES | ICM_RCFG_RHIEN_EN | ICM_RCFG_ECIEN_EN;
  }
  descriptors[0].rctrl = ICM_RCTRL_TRSIZE((bytes / kBlockSize) - 1u);
  descriptors[0].rnext = 0u;

  writeDescriptorAddress(reinterpret_cast<uintptr_t>(&descriptors[0]));
  writeHashAddress(reinterpret_cast<uintptr_t>(digest));
  __DSB();
  writeInterruptEnable(continuous ? kMonitorInterruptMask
                                  : (kCompleteInterrupt | kMismatchInterrupt | kErrorInterrupt));
  NVIC_ClearPendingIRQ(static_cast<IRQn_Type>(irqNumber()));
  NVIC_EnableIRQ(static_cast<IRQn_Type>(irqNumber()));
  writeControl(ICM_CTRL_ENABLE_Msk | ICM_CTRL_RMEN(kRegion0));
  __DSB();
  if (waitUntilEnabledOrDone()) {
    return true;
  }
  clearEventCallback();
  end();
  return false;
}

bool icm::asyncBusy() {
  const uint32_t primask = enterCritical();
  const bool busy = asyncState.busy;
  exitCritical(primask);
  return busy;
}

uint32_t icm::interruptFlags() {
  return SIMIO_ICM_REG(ISR) & kAllAsyncInterrupts;
}

uint32_t icm::lastInterruptFlags() {
  return asyncState.lastFlags;
}

void icm::resetTimingCounters() {
  const uint32_t primask = enterCritical();
  icmTimingCounters = TimingCounters{};
  exitCritical(primask);
}

icm::TimingCounters icm::timingCounters() {
  const uint32_t primask = enterCritical();
  const TimingCounters snapshot = icmTimingCounters;
  exitCritical(primask);
  return snapshot;
}

void icm::handleInterrupt() {
  const uint32_t flags = interruptFlags();
  const uint32_t handled = flags & kAllAsyncInterrupts;
  if (handled == 0u) {
    return;
  }

  writeInterruptDisable(handled);

  const uint32_t primask = enterCritical();
  asyncState.pendingFlags |= handled;
  asyncState.lastFlags = handled;
  exitCritical(primask);

  PendSV::instance().setPending(pendSvServiceId());
}

extern "C" void ICM_Handler(void) {
  icm::handleInterrupt();
}

#endif
