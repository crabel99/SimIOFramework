#include "AES.h"

#if AES_AVAILABLE

int aes::irqNumber() { return static_cast<int>(AES_IRQn); }

#endif /* AES_AVAILABLE */
