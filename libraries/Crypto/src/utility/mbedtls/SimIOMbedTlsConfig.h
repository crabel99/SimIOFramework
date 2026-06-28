#pragma once

/**
 * @file SimIOMbedTlsConfig.h
 * @brief SimIO Mbed TLS configuration entry point.
 *
 * This file is the local configuration boundary for the Mbed TLS dependency.
 * It intentionally starts narrow: production TLS/crypto behavior must come
 * from Mbed TLS, while SAME5x hardware acceleration and entropy are exposed
 * through small SimIO adapter hooks. Do not put protocol policy or crypto
 * primitive implementations in this file.
 */

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_AES_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_PSA_CRYPTO_RNG_STRENGTH 256
