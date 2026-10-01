// Ported from AsyncCortex ICM at 1b073eb4e693515d26252b91462b80ac8fb03e54.
#pragma once

#include "PendSV.h"
#include "sam.h"

#include <stddef.h>
#include <stdint.h>

#if defined(ICM) || defined(ICM_REGS)
#define ICM_AVAILABLE 1
#else
#define ICM_AVAILABLE 0
#endif

#if ICM_AVAILABLE

class icm {
public:
  using EventMask = uint8_t;
  // A valid digest requires EventComplete with no EventError.
  using EventCallback = void (*)(EventMask events, void* context);

  static constexpr EventMask EventNone = 0;
  static constexpr EventMask EventComplete = 1u << 0;
  static constexpr EventMask EventError = 1u << 1;
  static constexpr EventMask EventMismatch = 1u << 2;

  enum class Algorithm : uint8_t {
    Sha1,
    Sha224,
    Sha256,
  };

  struct HashSegment {
    const uint8_t* data;
    size_t length;
  };

  struct TimingCounters {
    uint32_t beginCalls;
    uint32_t beginCycles;
    uint32_t endCalls;
    uint32_t endCycles;
    uint32_t regionDisableCalls;
    uint32_t regionDisableCycles;
    uint32_t hashStartCalls;
    uint32_t hashStartCycles;
    uint32_t hashStartWaitCycles;
    uint32_t hashCopyCalls;
    uint32_t hashCopyCycles;
    uint32_t sessionKeptCompletions;
    uint32_t sessionContinuations;
  };

  static constexpr size_t MaxInputLength = (7u * 65536u * 64u) + 63u;
  static constexpr size_t Sha1DigestLength = 20u;
  static constexpr size_t Sha224DigestLength = 28u;
  static constexpr size_t Sha256DigestLength = 32u;

  static uintptr_t baseAddress();
  inline static uint8_t pendSvServiceId() {
    return PendSVChannels::Icm;
  }

  static int irqNumber();
  static void enableClock();
  static void disableClock();
  static void reset();
  static void begin();
  static void end();
  static bool enabled();
  static size_t stateLength(Algorithm algorithm);
  static size_t digestLength(Algorithm algorithm);
  static bool registerEventCallback(EventCallback callback, void* context = nullptr);
  static void clearEventCallback();
  // Input/output storage must remain valid until the completion callback.
  // All segments except the last must contain complete 64-byte blocks.
  static bool startHashAsync(Algorithm algorithm, const uint8_t* input, size_t inputLength,
                             uint8_t* output, size_t outputLength);
  static bool startHashSegmentsAsync(Algorithm algorithm, const HashSegment* segments,
                                     size_t segmentCount, uint8_t* output, size_t outputLength);
  static bool startHashSegmentsSessionAsync(Algorithm algorithm, const HashSegment* segments,
                                            size_t segmentCount, uint8_t* output,
                                            size_t outputLength, bool keepSession);
  static bool startHashBlockStateAsync(Algorithm algorithm, const uint8_t* input,
                                       size_t inputLength, uint8_t* output, size_t outputLength,
                                       bool keepSession);
  /**
   * @brief Continue a SHA operation from a caller-supplied compression state.
   *
   * The initial state must be the SHA state after processing `processedLength`
   * bytes, `processedLength` must be a full 64-byte block multiple, and the
   * remaining segments are padded as the final message suffix. This is a
   * backend-driver primitive for validated continuation paths; common provider
   * contracts should keep using hash/HMAC requests.
   */
  static bool startHashContinuationAsync(Algorithm algorithm, const uint8_t* initialState,
                                         size_t initialStateLength, size_t processedLength,
                                         const HashSegment* segments, size_t segmentCount,
                                         uint8_t* output, size_t outputLength,
                                         bool keepSession = false);
  static bool startRegionDigestWritebackAsync(Algorithm algorithm, const void* address,
                                              size_t bytes, volatile uint8_t* digest,
                                              size_t digestLength);
  static bool startRegionCompareAsync(Algorithm algorithm, const void* address, size_t bytes,
                                      volatile uint8_t* digest, size_t digestLength,
                                      bool continuous);
  static bool asyncBusy();
  static uint32_t interruptFlags();
  static uint32_t lastInterruptFlags();
  static void resetTimingCounters();
  static TimingCounters timingCounters();
  static void handleInterrupt();
};

#endif
