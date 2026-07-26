/**
 * @file TlsConfig.h
 * @brief SAMD Mbed TLS configuration entry point.
 *
 * This file is the local configuration boundary for the Mbed TLS dependency.
 * It intentionally starts narrow: production TLS/crypto behavior must come
 * from Mbed TLS, while SAME5x hardware acceleration and entropy are exposed
 * through small SAMD adapter hooks. Do not put protocol policy or crypto
 * primitive implementations in this file.
 */

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif
extern time_t mbedtls_platform_time(time_t *time);
#ifdef __cplusplus
}
#endif

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_MACRO mbedtls_platform_time

#define MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 256

/* Client TLS profile for SecureClient. No Mbed TLS networking, timing, or
 * blocking entropy modules are enabled here; Arduino supplies transport and RNG
 * readiness through async adapters.
 */
#define MBEDTLS_SSL_CLI_C
#if defined(MBEDTLS_NATIVE_TLS_TEST_SERVER)
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CACHE_C
#endif
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_ECP_RESTARTABLE
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_SSL_IN_CONTENT_LEN 1024
#define MBEDTLS_SSL_OUT_CONTENT_LEN 1024
#define MBEDTLS_SSL_CIPHERSUITES                                             \
  MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,                           \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                         \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,                       \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                         \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,                              \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,                            \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,                              \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,                            \
      MBEDTLS_TLS1_3_AES_128_GCM_SHA256,                                     \
      MBEDTLS_TLS1_3_AES_256_GCM_SHA384,                                     \
      MBEDTLS_TLS1_3_AES_128_CCM_SHA256,                                     \
      MBEDTLS_TLS1_3_AES_128_CCM_8_SHA256

/* RSA signature support is limited to async hardware-backed RSA-PSS and
 * RSA-PKCS1-v1.5 sign/verify. RSA key exchange and RSA decryption are
 * intentionally not part of this TLS client profile.
 */

/* Mbed TLS 4.x delegates cryptographic feature selection to PSA. Keep the
 * initial SecureClient profile narrow. Built-in software PSA modules are
 * bring-up scaffolding only for primitives that the SAME5x can perform in async
 * hardware; final supported paths must be routed through exact SAMD hardware
 * adapters instead of blocking or software fallback helpers.
 */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CLIENT
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#if defined(__SAMD51__) || defined(__SAME51__) || defined(__SAME53__) ||      \
    defined(__SAME54__) || defined(TARGET_SAME54)
#define MBEDTLS_ASYNC_HARDWARE_ECDH
#define MBEDTLS_ASYNC_HARDWARE_ECDSA
#define MBEDTLS_ASYNC_HARDWARE_RSA
#define MBEDTLS_ASYNC_HARDWARE_AEAD
#define MBEDTLS_ASYNC_HARDWARE_RANDOM
#endif
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define PSA_WANT_ALG_ECDH 1
#define PSA_WANT_ALG_ECDSA 1
#define PSA_WANT_ALG_CCM 1
#define PSA_WANT_ALG_GCM 1
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_ALG_HKDF 1
#define PSA_WANT_ALG_HKDF_EXTRACT 1
#define PSA_WANT_ALG_HKDF_EXPAND 1
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_384 1
#define PSA_WANT_ALG_SHA_512 1
#define PSA_WANT_ALG_TLS12_PRF 1
#define PSA_WANT_ECC_SECP_R1_256 1
#define PSA_WANT_ECC_SECP_R1_384 1
#define PSA_WANT_ECC_SECP_R1_521 1
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1

#if defined(MBEDTLS_ASYNC_HARDWARE_RSA) || defined(MBEDTLS_NATIVE_TLS_TEST_SERVER)
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN 1
#define PSA_WANT_ALG_RSA_PSS 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
#endif
