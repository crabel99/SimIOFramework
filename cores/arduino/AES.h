#pragma once

#include "sam.h"

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

class aes {
public:
  inline static uintptr_t baseAddress() { return AES_PERIPH; }
  static int irqNumber();
};
#endif /* AES_AVAILABLE */
