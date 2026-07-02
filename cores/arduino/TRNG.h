#pragma once

#include "sam.h"
#include "PendSV.h"

#include <stdint.h>

#if defined(__SAMD51__) || defined(__SAME51__) || defined(__SAME53__) ||       \
    defined(__SAME54__)
#define TRNG_AVAILABLE 1
#else
#define TRNG_AVAILABLE 0
#endif /* SAMD5x/E5x TRNG target */

#if TRNG_AVAILABLE

#define CRYPTO_HARDWARE_AVAILABLE

/**
 * @brief SAME5x true-random generator hardware interface.
 *
 * `trng` owns the MCU TRNG register path: APB clock gating, peripheral
 * enable/disable, DATARDY status, interrupt masks, and non-blocking random-word
 * reads. It does not own entropy policy, TLS state, provisioning state, or any
 * consumer-side buffering; higher layers must call `begin()` before requesting
 * data and must handle `read()` returning false when the hardware has not
 * produced a word yet.
 *
 * Per the SAME5x datasheet, TRNG has no enable synchronization step. Once
 * enabled, it produces a 32-bit word every 84 CLK_TRNG_APB cycles and sets
 * INTFLAG.DATARDY when DATA is valid. DATA reset contents are undefined, so
 * callers must treat DATARDY as the validity contract. Reading DATA clears
 * DATARDY; there is no software entropy conditioning, startup discard, or DRBG
 * policy in this peripheral wrapper.
 */
class trng {
public:
  using EventMask = uint8_t;
  using EventCallback = void (*)(EventMask events, uint32_t value,
                                 void *context);

  static constexpr EventMask EventNone = 0;
  static constexpr EventMask EventDataReady = 1u << 0;
  static constexpr EventMask EventError = 1u << 1;

  static uintptr_t baseAddress();
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Trng; }

  /** @brief Return the CMSIS IRQ number for the TRNG peripheral. */
  static int irqNumber();
  /** @brief Enable the peripheral bus clock needed before touching registers. */
  static void enableClock();
  /** @brief Disable the peripheral bus clock when no TRNG access is required. */
  static void disableClock();
  /** @brief Enable the TRNG and clear stale interrupt state. */
  static void begin(bool runStandby = false);
  /** @brief Disable TRNG generation and DATARDY interrupts. */
  static void end();
  /** @brief Report whether the peripheral enable bit is currently set. */
  static bool enabled();
  /** @brief Report whether a random word can be read without waiting. */
  static bool dataReady();
  /** @brief Read one random word if available; returns false without blocking. */
  static bool read(uint32_t &value);
  /** @brief Return currently latched TRNG interrupt flags. */
  static uint8_t interruptFlags();
  /** @brief Clear selected TRNG interrupt flags. */
  static void clearInterruptFlags(uint8_t flags);
  /** @brief Enable selected TRNG interrupt sources. */
  static void enableInterrupts(uint8_t mask);
  /** @brief Disable selected TRNG interrupt sources. */
  static void disableInterrupts(uint8_t mask);
  /**
   * @brief Register callback for async TRNG words.
   *
   * The callback runs from the TRNG PendSV service. Register before
   * `requestWordAsync()`.
   */
  static bool registerEventCallback(EventCallback callback,
                                    void *context = nullptr);
  /** @brief Clear the callback and cancel queued TRNG PendSV work. */
  static void clearEventCallback();
  /**
   * @brief Request one random word without blocking.
   *
   * Starts TRNG generation and enables DATARDY interrupt. The callback receives
   * the word from PendSV context. By default the peripheral is stopped before
   * callback dispatch; callers collecting multiple consecutive entropy words
   * may pass `stopAfterWord = false` and then either submit the next request
   * from the callback or explicitly stop the peripheral when collection is done.
   * Returns false when no callback is registered or a request is already active.
   */
  static bool requestWordAsync(bool runStandby = false,
                               bool stopAfterWord = true);
  /** @brief Return true while one async TRNG request is outstanding. */
  static bool asyncBusy();
  /** @brief Capture DATARDY IRQ state and schedule PendSV callback dispatch. */
  static void handleInterrupt();
};
#endif /*TRNG_AVAILABLE*/
