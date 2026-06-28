#include <stddef.h>
#include <stdint.h>

extern "C" void mbedtls_platform_zeroize(void *buffer, size_t length) {
  if (buffer == nullptr)
    return;

  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(buffer);
  while (length-- > 0u) {
    *bytes++ = 0u;
  }
}

