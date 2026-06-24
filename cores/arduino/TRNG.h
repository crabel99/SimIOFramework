#pragma once

#include "sam.h"

#include <stdint.h>

#ifdef TRNG_REGS
#define TRNG_AVAILABLE 1
#define TRNG_PERIPH (reinterpret_cast<uintptr_t>(TRNG_REGS))
#elif defined(TRNG)
#define TRNG_AVAILABLE 1
#define TRNG_PERIPH (reinterpret_cast<uintptr_t>(TRNG))
#else
#define TRNG_AVAILABLE 0
#endif /*TRNG_REGS || TRNG */

#if TRNG_AVAILABLE

#define CRYPTO_HARDWARE_AVAILABLE

class trng {
public:
  inline static uintptr_t baseAddress() { return TRNG_PERIPH; }
  static int irqNumber();
};
#endif /*TRNG_AVAILABLE*/
