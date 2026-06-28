#pragma once

#include "sam.h"
#include "PendSV.h"

#include <stdint.h>

#if defined(AES_REGS)
#define AES_AVAILABLE 1
#define AES_PERIPH (reinterpret_cast<uintptr_t>(AES_REGS))
#elif defined(AES)
#define AES_AVAILABLE 1
#define AES_PERIPH (reinterpret_cast<uintptr_t>(AES))
#else
#define AES_AVAILABLE 0
#endif /* AES_REGS || AES */

#if AES_AVAILABLE

#define CRYPTO_HARDWARE_AVAILABLE

/**
 * @brief SAME5x AES peripheral register interface.
 *
 * `aes` owns the low-level AES hardware boundary: APB clock gating,
 * reset/enable, mode/key-size/direction register packing, key and block
 * register loading, start control, and AES interrupt flag masks. It is not a
 * TLS/session API and does not allocate buffers, manage certificates, or choose
 * cryptographic policy. Higher layers are responsible for choosing safe modes,
 * padding rules, IV policy, and authenticated-encryption usage.
 */
class aes {
public:
  enum class Mode : uint32_t {
    Ecb = AES_CTRLA_AESMODE_ECB_Val,
    Cbc = AES_CTRLA_AESMODE_CBC_Val,
    Ofb = AES_CTRLA_AESMODE_OFB_Val,
    Cfb = AES_CTRLA_AESMODE_CFB_Val,
    Counter = AES_CTRLA_AESMODE_COUNTER_Val,
    Ccm = AES_CTRLA_AESMODE_CCM_Val,
    Gcm = AES_CTRLA_AESMODE_GCM_Val,
  };

  enum class KeySize : uint32_t {
    Bits128 = AES_CTRLA_KEYSIZE_128BIT_Val,
    Bits192 = AES_CTRLA_KEYSIZE_192BIT_Val,
    Bits256 = AES_CTRLA_KEYSIZE_256BIT_Val,
  };

  enum class Direction : uint32_t {
    Decrypt = AES_CTRLA_CIPHER_DEC_Val,
    Encrypt = AES_CTRLA_CIPHER_ENC_Val,
  };

  static constexpr uint8_t EncryptionCompleteInterrupt = AES_INTFLAG_ENCCMP_Msk;
  static constexpr uint8_t GaloisMultiplyCompleteInterrupt =
      AES_INTFLAG_GFMCMP_Msk;

  inline static uintptr_t baseAddress() { return AES_PERIPH; }
  inline static uint8_t pendSvServiceId() { return PendSVChannels::Aes; }

  /** @brief Return the CMSIS IRQ number for the AES peripheral. */
  static int irqNumber();
  /** @brief Enable the peripheral bus clock needed before touching registers. */
  static void enableClock();
  /** @brief Disable the peripheral bus clock when AES is idle. */
  static void disableClock();
  /** @brief Issue a hardware software-reset and wait for reset completion. */
  static void reset();
  /** @brief Enable the peripheral after clocking and clear stale interrupts. */
  static void begin();
  /** @brief Disable AES interrupts and the peripheral enable bit. */
  static void end();
  /** @brief Report whether the AES enable bit is currently set. */
  static bool enabled();
  /** @brief Program mode, key size, direction, and manual/auto start behavior. */
  static void configure(Mode mode, KeySize keySize, Direction direction,
                        bool autoStart = false);
  /** @brief Load a 128/192/256-bit key as 4/6/8 32-bit words. */
  static bool writeKey(const uint32_t *words, uint8_t wordCount);
  /** @brief Load one 128-bit input block. */
  static void writeInputBlock(const uint32_t words[4]);
  /** @brief Read one 128-bit output block from the data register window. */
  static void readOutputBlock(uint32_t words[4]);
  /** @brief Load one 128-bit initialization vector. */
  static void writeInitializationVector(const uint32_t words[4]);
  /** @brief Mark the next block as the beginning of a new AES message. */
  static void beginMessage();
  /** @brief Start a manual AES operation. */
  static void start();
  /** @brief Report whether the current AES block operation has completed. */
  static bool operationComplete();
  /** @brief Return currently latched AES interrupt flags. */
  static uint8_t interruptFlags();
  /** @brief Clear selected AES interrupt flags. */
  static void clearInterruptFlags(uint8_t flags);
  /** @brief Enable selected AES interrupt sources. */
  static void enableInterrupts(uint8_t mask);
  /** @brief Disable selected AES interrupt sources. */
  static void disableInterrupts(uint8_t mask);
};
#endif /* AES_AVAILABLE */
