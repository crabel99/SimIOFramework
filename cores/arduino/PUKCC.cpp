#include "PUKCC.h"

#if PUKCC_AVAILABLE

int pukcc::irqNumber() { return static_cast<int>(PUKCC_IRQn); }

#endif /* PUKCC_AVAILABLE */
