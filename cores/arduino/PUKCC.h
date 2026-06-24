#pragma once

#include "sam.h"

#include <stdint.h>

#if defined(PUKCC) || defined(ID_PUKCC) || defined(PUKCC_INSTANCE_ID)
#define PUKCC_AVAILABLE 1
#else
#define PUKCC_AVAILABLE 0
#endif /* PUKCC || ID_PUKCC || PUKCC_INSTANCE_ID */

#if defined(PUKCC)
#define PUKCC_PERIPH_APB (reinterpret_cast<uintptr_t>(PUKCC))
#else
#define PUKCC_PERIPH_APB (static_cast<uintptr_t>(0))
#endif /* PUKCC */

#if defined(PUKCC_AHB)
#define PUKCC_PERIPH_AHB (reinterpret_cast<uintptr_t>(PUKCC_AHB))
#else
#define PUKCC_PERIPH_AHB (static_cast<uintptr_t>(0))
#endif /* PUKCC_AHB */

#if PUKCC_AVAILABLE

#define CRYPTO_HARDWARE_AVAILABLE

class pukcc {
public:
  inline static uintptr_t apbBaseAddress() { return PUKCC_PERIPH_APB; }
  inline static uintptr_t ahbBaseAddress() { return PUKCC_PERIPH_AHB; }
  static int irqNumber();
  inline static int instanceId() {
#if defined(PUKCC_INSTANCE_ID)
    return static_cast<int>(PUKCC_INSTANCE_ID);
#elif defined(ID_PUKCC)
    return static_cast<int>(ID_PUKCC);
#else
    return -1;
#endif
  }
};
#endif /* PUKCC_AVAILABLE */
