#include "TRNG.h"

#if TRNG_AVAILABLE

int trng::irqNumber() {
  return static_cast<int>(TRNG_IRQn);
}

#endif /* TRNG_AVAILABLE */
