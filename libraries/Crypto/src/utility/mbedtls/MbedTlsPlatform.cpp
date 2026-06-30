#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
bool trustedTimeConfigured = false;
mbedtls_time_t trustedTime = 0;
} // namespace

bool setExternalRandomProvider(Crypto::TlsCryptoProvider *provider) {
  if (provider == nullptr || !provider->ready())
    return false;
  if (externalRandomProvider != nullptr)
    return false;

  externalRandomProvider = provider;
  return true;
}

void clearExternalRandomProvider(Crypto::TlsCryptoProvider *provider) {
  if (externalRandomProvider == provider)
    externalRandomProvider = nullptr;
}

bool setTrustedTime(uint64_t unixTime) {
  trustedTime = static_cast<mbedtls_time_t>(unixTime);
  trustedTimeConfigured = true;
  return true;
}

void clearTrustedTime() {
  trustedTimeConfigured = false;
  trustedTime = 0;
}

bool hasTrustedTime() { return trustedTimeConfigured; }

mbedtls_time_t currentTrustedTime() {
  return trustedTimeConfigured ? trustedTime : 0;
}

#if defined(SIMIO_MBEDTLS_TEST_SYNC_COMPAT)
bool generateExternalRandom(uint8_t *buffer, size_t length) {
  if (externalRandomProvider == nullptr || buffer == nullptr || length == 0)
    return false;

  return externalRandomProvider->generateRandom(buffer, length);
}
#endif
} // namespace Crypto::MbedTlsPort

extern "C" {
typedef void (*simio_mbedtls_async_callback_t)(int success, void *context);

time_t simio_mbedtls_time(time_t *time) {
  const mbedtls_time_t now = Crypto::MbedTlsPort::currentTrustedTime();
  if (time != nullptr)
    *time = static_cast<time_t>(now);
  return static_cast<time_t>(now);
}

static void simio_mbedtls_zeroize(void *buffer, size_t length) {
  if (buffer == nullptr)
    return;

  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(buffer);
  while (length-- > 0u)
    *bytes++ = 0u;
}

int simio_mbedtls_random_start(uint8_t *buffer, size_t length,
                               simio_mbedtls_async_callback_t callback,
                               void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      buffer == nullptr || length == 0 || callback == nullptr) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->randomBytesAsync(
          buffer, length,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_ecdh_p256_start(const uint8_t privateScalar[32],
                                  const uint8_t peerPublicKey[65],
                                  uint8_t sharedSecret[32],
                                  simio_mbedtls_async_callback_t callback,
                                  void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      privateScalar == nullptr || peerPublicKey == nullptr ||
      sharedSecret == nullptr || callback == nullptr) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->keyExchangeSharedSecretAsync(
          Crypto::TlsKeyExchangeAlgorithm::EcdhP256, privateScalar, 32,
          peerPublicKey, 65, sharedSecret, 32,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_ecdh_p256_public_key_start(
    const uint8_t privateScalar[32], uint8_t publicKey[65],
    simio_mbedtls_async_callback_t callback, void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      privateScalar == nullptr || publicKey == nullptr || callback == nullptr) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->keyExchangePublicKeyAsync(
          Crypto::TlsKeyExchangeAlgorithm::EcdhP256, privateScalar, 32,
          publicKey, 65,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_ecdsa_p256_verify_start(
    const uint8_t publicKey[65], const uint8_t hash[32],
    const uint8_t signature[64], simio_mbedtls_async_callback_t callback,
    void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      publicKey == nullptr || hash == nullptr || signature == nullptr ||
      callback == nullptr) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->signatureVerifyAsync(
          Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256, publicKey, 65, hash,
          32, signature, 64,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_ecdsa_p256_sign_start(const uint8_t privateKey[32],
                                        const uint8_t hash[32],
                                        uint8_t signature[64],
                                        simio_mbedtls_async_callback_t callback,
                                        void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      privateKey == nullptr || hash == nullptr || signature == nullptr ||
      callback == nullptr) {
    return 0;
  }

  struct CallbackContext {
    uint8_t nonceScalar[32];
    const uint8_t *privateKey;
    const uint8_t *hash;
    uint8_t *signature;
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext = {};
  callbackContext.privateKey = privateKey;
  callbackContext.hash = hash;
  callbackContext.signature = signature;
  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submittedRandom =
      Crypto::MbedTlsPort::externalRandomProvider->randomBytesAsync(
          callbackContext.nonceScalar, sizeof(callbackContext.nonceScalar),
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            if (!success ||
                Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
                !Crypto::MbedTlsPort::externalRandomProvider
                     ->signatureSignAsync(
                         Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256,
                         callbackContext->privateKey, 32,
                         callbackContext->nonceScalar, 32,
                         callbackContext->hash, 32, callbackContext->signature,
                         64,
                         [](bool signSuccess, void *signUser) {
                           auto *callbackContext =
                               static_cast<CallbackContext *>(signUser);
                           simio_mbedtls_async_callback_t completed =
                               callbackContext->callback;
                           void *completedContext = callbackContext->context;
                           simio_mbedtls_zeroize(
                               callbackContext->nonceScalar,
                               sizeof(callbackContext->nonceScalar));
                           callbackContext->privateKey = nullptr;
                           callbackContext->hash = nullptr;
                           callbackContext->signature = nullptr;
                           callbackContext->callback = nullptr;
                           callbackContext->context = nullptr;
                           if (completed != nullptr)
                             completed(signSuccess ? 1 : 0, completedContext);
                         },
                         callbackContext)) {
              simio_mbedtls_async_callback_t completed =
                  callbackContext->callback;
              void *completedContext = callbackContext->context;
              simio_mbedtls_zeroize(callbackContext->nonceScalar,
                                    sizeof(callbackContext->nonceScalar));
              callbackContext->privateKey = nullptr;
              callbackContext->hash = nullptr;
              callbackContext->signature = nullptr;
              callbackContext->callback = nullptr;
              callbackContext->context = nullptr;
              if (completed != nullptr)
                completed(0, completedContext);
            }
          },
          &callbackContext);

  if (!submittedRandom) {
    simio_mbedtls_zeroize(callbackContext.nonceScalar,
                          sizeof(callbackContext.nonceScalar));
    callbackContext = {};
    return 0;
  }

  return 1;
}

int simio_mbedtls_aes_gcm128_encrypt_start(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *plaintext, uint8_t *ciphertext,
    size_t length, uint8_t tag[16], simio_mbedtls_async_callback_t callback,
    void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->aesGcm128EncryptAsync(
          key, nonce, aad, aadLength, plaintext, ciphertext, length, tag,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_aead_encrypt_start(
    int algorithm, const uint8_t *key, size_t keyLength,
    const uint8_t *nonce, size_t nonceLength, const uint8_t *aad,
    size_t aadLength, const uint8_t *plaintext, uint8_t *ciphertext,
    size_t length, uint8_t *tag, size_t tagLength,
    simio_mbedtls_async_callback_t callback, void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      key == nullptr || keyLength == 0 || nonce == nullptr ||
      nonceLength == 0 || tag == nullptr || tagLength == 0 ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (plaintext == nullptr && length != 0) ||
      (ciphertext == nullptr && length != 0)) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->aeadEncryptAsync(
          static_cast<Crypto::TlsAeadAlgorithm>(algorithm), key, keyLength,
          nonce, nonceLength, aad, aadLength, plaintext, ciphertext, length,
          tag, tagLength,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_aes_gcm128_decrypt_start(
    const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
    size_t aadLength, const uint8_t *ciphertext, uint8_t *plaintext,
    size_t length, const uint8_t tag[16],
    simio_mbedtls_async_callback_t callback, void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      key == nullptr || nonce == nullptr || tag == nullptr ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->aesGcm128DecryptAsync(
          key, nonce, aad, aadLength, ciphertext, plaintext, length, tag,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}

int simio_mbedtls_aead_decrypt_start(
    int algorithm, const uint8_t *key, size_t keyLength,
    const uint8_t *nonce, size_t nonceLength, const uint8_t *aad,
    size_t aadLength, const uint8_t *ciphertext, uint8_t *plaintext,
    size_t length, const uint8_t *tag, size_t tagLength,
    simio_mbedtls_async_callback_t callback, void *context) {
  if (Crypto::MbedTlsPort::externalRandomProvider == nullptr ||
      key == nullptr || keyLength == 0 || nonce == nullptr ||
      nonceLength == 0 || tag == nullptr || tagLength == 0 ||
      callback == nullptr || (aad == nullptr && aadLength != 0) ||
      (ciphertext == nullptr && length != 0) ||
      (plaintext == nullptr && length != 0)) {
    return 0;
  }

  struct CallbackContext {
    simio_mbedtls_async_callback_t callback;
    void *context;
  };

  static CallbackContext callbackContext;
  if (callbackContext.callback != nullptr)
    return 0;

  callbackContext.callback = callback;
  callbackContext.context = context;

  const bool submitted =
      Crypto::MbedTlsPort::externalRandomProvider->aeadDecryptAsync(
          static_cast<Crypto::TlsAeadAlgorithm>(algorithm), key, keyLength,
          nonce, nonceLength, aad, aadLength, ciphertext, plaintext, length,
          tag, tagLength,
          [](bool success, void *user) {
            auto *callbackContext = static_cast<CallbackContext *>(user);
            simio_mbedtls_async_callback_t completed =
                callbackContext->callback;
            void *completedContext = callbackContext->context;
            callbackContext->callback = nullptr;
            callbackContext->context = nullptr;
            if (completed != nullptr)
              completed(success ? 1 : 0, completedContext);
          },
          &callbackContext);

  if (!submitted) {
    callbackContext.callback = nullptr;
    callbackContext.context = nullptr;
    return 0;
  }

  return 1;
}
}

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
#else
#if defined(ARDUINO)
  int64_t seconds = static_cast<int64_t>(*time);
  int64_t days = seconds / 86400;
  int64_t remaining = seconds % 86400;
  if (remaining < 0) {
    remaining += 86400;
    --days;
  }

  const int hour = static_cast<int>(remaining / 3600);
  remaining %= 3600;
  const int minute = static_cast<int>(remaining / 60);
  const int second = static_cast<int>(remaining % 60);

  const int weekday = static_cast<int>((days + 4) % 7);
  const int normalizedWeekday = weekday < 0 ? weekday + 7 : weekday;

  int64_t z = days + 719468;
  const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe =
      (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int year = static_cast<int>(yoe) + static_cast<int>(era) * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  const unsigned day = doy - (153 * mp + 2) / 5 + 1;
  const int month = static_cast<int>(mp) + (mp < 10 ? 3 : -9);
  year += month <= 2 ? 1 : 0;

  const bool leap =
      (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0));
  static constexpr unsigned monthDaysBefore[] = {
      0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
  unsigned yearDay =
      monthDaysBefore[static_cast<unsigned>(month - 1)] + day - 1;
  if (leap && month > 2)
    ++yearDay;

  memset(timeBuffer, 0, sizeof(*timeBuffer));
  timeBuffer->tm_sec = second;
  timeBuffer->tm_min = minute;
  timeBuffer->tm_hour = hour;
  timeBuffer->tm_mday = static_cast<int>(day);
  timeBuffer->tm_mon = static_cast<int>(month) - 1;
  timeBuffer->tm_year = year - 1900;
  timeBuffer->tm_wday = normalizedWeekday;
  timeBuffer->tm_yday = static_cast<int>(yearDay);
  timeBuffer->tm_isdst = 0;
  return timeBuffer;
#else
  return gmtime_r(time, timeBuffer);
#endif
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

#if defined(SIMIO_MBEDTLS_TEST_SYNC_COMPAT)
  if (!Crypto::MbedTlsPort::generateExternalRandom(output, outputSize))
    return PSA_ERROR_INSUFFICIENT_ENTROPY;

  *outputLength = outputSize;
  return PSA_SUCCESS;
#else
  (void)output;
  (void)outputSize;
  return PSA_ERROR_INSUFFICIENT_ENTROPY;
#endif
}
