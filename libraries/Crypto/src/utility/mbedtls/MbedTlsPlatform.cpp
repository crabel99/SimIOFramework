#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <mbedtls/platform_time.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <utility/tls/TlsClientSession.h>

#if defined(ARDUINO)
#include <Arduino.h>
#else
#include <chrono>
#endif

namespace Crypto::MbedTlsPort {
namespace {
Crypto::TlsCryptoProvider *externalRandomProvider = nullptr;
} // namespace

bool setExternalRandomProvider(Crypto::TlsCryptoProvider *provider) {
  if (provider == nullptr || !provider->ready())
    return false;

  externalRandomProvider = provider;
  return true;
}

void clearExternalRandomProvider(Crypto::TlsCryptoProvider *provider) {
  if (externalRandomProvider == provider)
    externalRandomProvider = nullptr;
}

bool generateExternalRandom(uint8_t *buffer, size_t length) {
  if (externalRandomProvider == nullptr)
    return false;

  return externalRandomProvider->generateRandom(buffer, length);
}
} // namespace Crypto::MbedTlsPort

extern "C" void mbedtls_platform_zeroize(void *buffer, size_t length) {
  if (buffer == nullptr)
    return;

  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(buffer);
  while (length-- > 0u) {
    *bytes++ = 0u;
  }
}

extern "C" void mbedtls_zeroize_and_free(void *buffer, size_t length) {
  if (buffer == nullptr)
    return;

  mbedtls_platform_zeroize(buffer, length);
  free(buffer);
}

extern "C" struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *time,
                                                struct tm *timeBuffer) {
  if (time == nullptr || timeBuffer == nullptr)
    return nullptr;

#if defined(_WIN32)
  return gmtime_s(timeBuffer, time) == 0 ? timeBuffer : nullptr;
#elif defined(ARDUINO)
  (void)time;
  (void)timeBuffer;
  return nullptr;
#else
  return gmtime_r(time, timeBuffer);
#endif
}

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void) {
#if defined(ARDUINO)
  return static_cast<mbedtls_ms_time_t>(millis());
#else
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<mbedtls_ms_time_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
#endif
}

extern "C" psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context, uint8_t *output,
    size_t outputSize, size_t *outputLength) {
  (void)context;

  if (outputLength != nullptr)
    *outputLength = 0;
  if (output == nullptr || outputLength == nullptr || outputSize == 0)
    return PSA_ERROR_INVALID_ARGUMENT;

  if (!Crypto::MbedTlsPort::generateExternalRandom(output, outputSize))
    return PSA_ERROR_INSUFFICIENT_ENTROPY;

  *outputLength = outputSize;
  return PSA_SUCCESS;
}
