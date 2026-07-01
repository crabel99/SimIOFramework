/**
 * @file TlsClientSession.h
 * @brief Async TLS client session contract for secure transports.
 *
 * `TlsClientSession` is the boundary between transport-specific secure clients
 * and the Mbed TLS implementation. It owns TLS session state, hostname/trust
 * policy, non-blocking transport binding, and callback-driven operation
 * progress. It must not block inside handshake, read, write, close-notify,
 * entropy, or crypto paths.
 */
#pragma once

#include <utility/tls/TlsTransport.h>

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/TlsConfig.h"
#endif

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <stddef.h>
#include <stdint.h>

namespace Crypto {

using TlsCryptoReadyCallback = void (*)(bool success, void *context);
using TlsRandomCallback = void (*)(bool success, void *context);
using TlsEcdhP256Callback = void (*)(bool success, void *context);
using TlsEcdsaP256SignCallback = void (*)(bool success, void *context);
using TlsEcdsaP256VerifyCallback = void (*)(bool success, void *context);
using TlsAesGcm128Callback = void (*)(bool success, void *context);
using TlsKeyExchangeCallback = void (*)(bool success, void *context);
using TlsSignatureCallback = void (*)(bool success, void *context);
using TlsAeadCallback = void (*)(bool success, void *context);

/**
 * @brief TLS key exchange groups that may be serviced by async providers.
 *
 * P-256 is currently implemented through PUKCC. Other groups are represented
 * so TLS 1.3 KeyShare support can be added without using implicit PSA/software
 * fallback paths.
 */
enum class TlsKeyExchangeAlgorithm : uint8_t {
  EcdhP256 = 1,
  EcdhP384 = 2,
  X25519 = 3,
  EcdhP521 = 4,
};

/**
 * @brief TLS signature algorithms that may be serviced by async providers.
 *
 * ECDSA P-256 with SHA-256 is currently implemented through PUKCC. Unsupported
 * algorithms fail closed until a provider implements the exact signature shape.
 */
enum class TlsSignatureAlgorithm : uint8_t {
  EcdsaP256Sha256 = 1,
  EcdsaP384Sha384 = 2,
  EcdsaP521Sha512 = 3,
  Ed25519 = 4,
  RsaPssRsaeSha256 = 5,
  RsaPssRsaeSha384 = 6,
};

/**
 * @brief TLS AEAD algorithms that may be serviced by async Crypto providers.
 *
 * The numeric values are part of the C shim contract used by the local Mbed TLS
 * hooks. Unsupported algorithms must fail closed until the provider implements
 * an async hardware-backed path for that exact shape.
 */
enum class TlsAeadAlgorithm : uint8_t {
  Aes128Gcm = 1,
  Aes256Gcm = 2,
  Aes128Ccm = 3,
  Aes256Ccm = 4,
  Aes128Ccm8 = 5,
  Aes256Ccm8 = 6,
  ChaCha20Poly1305 = 7,
};

/**
 * @brief TLS hash/MAC/KDF algorithms retained as explicit software exceptions.
 *
 * @todo Promote individual algorithms to async hardware-backed provider
 * operations if future targets expose exact SHA/HMAC/HKDF/TLS-PRF hardware
 * support. Until then, these are documented protocol/key-schedule exceptions,
 * not claimed hardware-backed primitives.
 */
enum class TlsSoftwareKdfAlgorithm : uint8_t {
  Sha256 = 1,
  Sha384 = 2,
  HmacSha256 = 3,
  HmacSha384 = 4,
  HkdfSha256 = 5,
  HkdfSha384 = 6,
  Tls12PrfSha256 = 7,
};

/**
 * @brief Async crypto readiness provider for TLS sessions.
 *
 * Implementations own the Mbed TLS RNG/crypto setup required before handshake
 * progress can run. They must return immediately from `beginHandshakeCrypto()`
 * and later report completion through the callback. The callback only marks
 * readiness; TLS protocol progress still happens from `TlsClientSession::poll()`.
 * New operation code must request randomness with `randomBytesAsync()` so the
 * hardware TRNG writes directly into operation-owned sensitive buffers. The
 * synchronous `generateRandom()` compatibility hook exists only in
 * `SIMIO_MBEDTLS_TEST_SYNC_COMPAT` builds for legacy Mbed TLS callback tests;
 * production builds do not expose that fallback path.
 */
class TlsCryptoProvider {
public:
  virtual ~TlsCryptoProvider() = default;

  virtual bool beginHandshakeCrypto(TlsCryptoReadyCallback callback,
                                    void *context) = 0;
  virtual void reset() = 0;
  virtual bool ready() const = 0;
#if defined(SIMIO_MBEDTLS_TEST_SYNC_COMPAT)
  virtual bool generateRandom(uint8_t *buffer, size_t length) = 0;
#endif

  /**
   * @brief Fill an operation-owned sensitive buffer from async hardware random.
   *
   * The provider must write TRNG-backed bytes directly into `buffer`; it must
   * not stage them in a reusable provider pool. The callback reports only that
   * the buffer is ready for the owning operation to consume. Callers own
   * zeroizing `buffer` after use. The default implementation fails closed for
   * test providers that have not implemented an async hardware random path.
   */
  virtual bool randomBytesAsync(uint8_t *buffer, size_t length,
                                TlsRandomCallback callback, void *context) {
    (void)buffer;
    (void)length;
    (void)callback;
    (void)context;
    return false;
  }
  /**
   * @brief Start async P-256 ECDH shared-secret computation.
   *
   * `privateScalar` is the local 32-byte big-endian scalar. `peerPublicKey`
   * must be the TLS uncompressed form: 0x04 || X || Y. `sharedSecret` receives
   * the 32-byte big-endian X coordinate only after the callback reports
   * success. The default implementation fails closed for test providers and
   * platforms without a hardware ECDH backend.
   */
  virtual bool ecdhP256SharedSecretAsync(const uint8_t privateScalar[32],
                                         const uint8_t peerPublicKey[65],
                                         uint8_t sharedSecret[32],
                                         TlsEcdhP256Callback callback,
                                         void *context) {
    (void)privateScalar;
    (void)peerPublicKey;
    (void)sharedSecret;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async P-256 public-key derivation.
   *
   * `privateScalar` is the local 32-byte big-endian scalar. `publicKey`
   * receives the TLS uncompressed form: 0x04 || X || Y. The default
   * implementation fails closed for providers without a hardware scalar
   * multiply backend.
   */
  virtual bool ecdhP256PublicKeyAsync(const uint8_t privateScalar[32],
                                      uint8_t publicKey[65],
                                      TlsEcdhP256Callback callback,
                                      void *context) {
    (void)privateScalar;
    (void)publicKey;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS key exchange public-key derivation.
   *
   * `privateScalar` and `publicKey` use the wire shape for `algorithm`. P-256
   * expects a 32-byte big-endian scalar and writes a 65-byte uncompressed
   * point.
   *
   * @todo Add async provider implementations for P-384, X25519, and P-521 when
   * those groups are enabled for TLS 1.3 KeyShare or expanded TLS profiles.
   */
  virtual bool keyExchangePublicKeyAsync(
      TlsKeyExchangeAlgorithm algorithm, const uint8_t *privateScalar,
      size_t privateScalarLength, uint8_t *publicKey, size_t publicKeyLength,
      TlsKeyExchangeCallback callback, void *context) {
    if (algorithm == TlsKeyExchangeAlgorithm::EcdhP256 &&
        privateScalarLength == 32 && publicKeyLength == 65) {
      return ecdhP256PublicKeyAsync(privateScalar, publicKey, callback,
                                    context);
    }

    (void)privateScalar;
    (void)publicKey;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS key exchange shared-secret computation.
   *
   * P-256 expects a 32-byte big-endian scalar, a 65-byte uncompressed peer
   * point, and writes the 32-byte X-coordinate shared secret.
   *
   * @todo Add async provider implementations for P-384, X25519, and P-521 when
   * those groups are enabled. Unsupported groups fail closed.
   */
  virtual bool keyExchangeSharedSecretAsync(
      TlsKeyExchangeAlgorithm algorithm, const uint8_t *privateScalar,
      size_t privateScalarLength, const uint8_t *peerPublicKey,
      size_t peerPublicKeyLength, uint8_t *sharedSecret,
      size_t sharedSecretLength, TlsKeyExchangeCallback callback,
      void *context) {
    if (algorithm == TlsKeyExchangeAlgorithm::EcdhP256 &&
        privateScalarLength == 32 && peerPublicKeyLength == 65 &&
        sharedSecretLength == 32) {
      return ecdhP256SharedSecretAsync(privateScalar, peerPublicKey,
                                       sharedSecret, callback, context);
    }

    (void)privateScalar;
    (void)peerPublicKey;
    (void)sharedSecret;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async P-256 ECDSA signature generation.
   *
   * `privateKey` and `nonceScalar` are 32-byte big-endian scalars. The nonce
   * scalar must come from the async hardware random path in production; tests
   * may supply a fixed scalar only to prove deterministic hardware behavior.
   * `hash` is a 32-byte big-endian digest and `signature` receives the raw
   * P1363 encoding R || S after the callback reports success. The default
   * implementation fails closed for test providers and platforms without a
   * hardware ECDSA signing backend.
   */
  virtual bool ecdsaP256SignAsync(const uint8_t privateKey[32],
                                  const uint8_t nonceScalar[32],
                                  const uint8_t hash[32],
                                  uint8_t signature[64],
                                  TlsEcdsaP256SignCallback callback,
                                  void *context) {
    (void)privateKey;
    (void)nonceScalar;
    (void)hash;
    (void)signature;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async P-256 ECDSA signature verification.
   *
   * `publicKey` must be the TLS uncompressed form: 0x04 || X || Y. `hash` is a
   * 32-byte big-endian digest and `signature` is the 64-byte raw P1363
   * encoding R || S. The default implementation fails closed for test
   * providers and platforms without a hardware ECDSA backend.
   */
  virtual bool ecdsaP256VerifyAsync(const uint8_t publicKey[65],
                                    const uint8_t hash[32],
                                    const uint8_t signature[64],
                                    TlsEcdsaP256VerifyCallback callback,
                                    void *context) {
    (void)publicKey;
    (void)hash;
    (void)signature;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS signature generation for a supported algorithm.
   *
   * ECDSA P-256/SHA-256 is currently implemented and requires a caller-owned
   * nonce scalar already filled from async hardware random.
   *
   * @todo Add provider implementations for P-384/P-521 ECDSA, Ed25519, and
   * RSA-PSS only when those signature schemes become supported TLS policy.
   */
  virtual bool
  signatureSignAsync(TlsSignatureAlgorithm algorithm, const uint8_t *privateKey,
                     size_t privateKeyLength, const uint8_t *nonceScalar,
                     size_t nonceScalarLength, const uint8_t *hash,
                     size_t hashLength, uint8_t *signature,
                     size_t signatureLength, TlsSignatureCallback callback,
                     void *context) {
    if (algorithm == TlsSignatureAlgorithm::EcdsaP256Sha256 &&
        privateKeyLength == 32 && nonceScalarLength == 32 && hashLength == 32 &&
        signatureLength == 64) {
      return ecdsaP256SignAsync(privateKey, nonceScalar, hash, signature,
                                callback, context);
    }

    (void)privateKey;
    (void)nonceScalar;
    (void)hash;
    (void)signature;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS signature verification for a supported algorithm.
   *
   * ECDSA P-256/SHA-256 is currently implemented. Unsupported signature
   * algorithms fail closed instead of falling back to PSA/software.
   */
  virtual bool signatureVerifyAsync(TlsSignatureAlgorithm algorithm,
                                    const uint8_t *publicKey,
                                    size_t publicKeyLength, const uint8_t *hash,
                                    size_t hashLength, const uint8_t *signature,
                                    size_t signatureLength,
                                    TlsSignatureCallback callback,
                                    void *context) {
    if (algorithm == TlsSignatureAlgorithm::EcdsaP256Sha256 &&
        publicKeyLength == 65 && hashLength == 32 && signatureLength == 64) {
      return ecdsaP256VerifyAsync(publicKey, hash, signature, callback,
                                  context);
    }

    (void)publicKey;
    (void)hash;
    (void)signature;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async AES-128-GCM encryption.
   *
   * This is the TLS record-protection primitive for the supported
   * ECDHE-ECDSA-AES128-GCM-SHA256 profile. `nonce` is the 12-byte TLS GCM
   * nonce, `aad` is authenticated but not encrypted, and `tag` receives the
   * 16-byte authentication tag only after the callback reports success.
   * Implementations must fail closed rather than falling back to blocking
   * software when the hardware-backed path is unavailable.
   */
  virtual bool
  aesGcm128EncryptAsync(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aadLength,
                        const uint8_t *plaintext, uint8_t *ciphertext,
                        size_t length, uint8_t tag[16],
                        TlsAesGcm128Callback callback, void *context) {
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aadLength;
    (void)plaintext;
    (void)ciphertext;
    (void)length;
    (void)tag;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async AES-128-GCM decryption and authentication.
   *
   * The plaintext output is valid only when the callback reports success. A tag
   * mismatch must fail closed and leave callers responsible for discarding any
   * partially written plaintext buffer.
   */
  virtual bool
  aesGcm128DecryptAsync(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aadLength,
                        const uint8_t *ciphertext, uint8_t *plaintext,
                        size_t length, const uint8_t tag[16],
                        TlsAesGcm128Callback callback, void *context) {
    (void)key;
    (void)nonce;
    (void)aad;
    (void)aadLength;
    (void)ciphertext;
    (void)plaintext;
    (void)length;
    (void)tag;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS AEAD encryption for a supported provider algorithm.
   *
   * AES-128-GCM is the first implemented hardware path and is dispatched to
   * `aesGcm128EncryptAsync()`. Other TLS AEAD algorithms are represented here
   * so callers can fail closed through one generic Crypto boundary instead of
   * falling back to software implicitly.
   *
   * @todo Add async hardware implementations for AES-256-GCM, AES-CCM,
   * AES-CCM-8, and ChaCha20-Poly1305 when those algorithms are required by
   * non-Ethernet peripherals or expanded TLS profiles.
   */
  virtual bool aeadEncryptAsync(TlsAeadAlgorithm algorithm,
                                const uint8_t *key, size_t keyLength,
                                const uint8_t *nonce, size_t nonceLength,
                                const uint8_t *aad, size_t aadLength,
                                const uint8_t *plaintext,
                                uint8_t *ciphertext, size_t length,
                                uint8_t *tag, size_t tagLength,
                                TlsAeadCallback callback, void *context) {
    if (algorithm == TlsAeadAlgorithm::Aes128Gcm && keyLength == 16 &&
        nonceLength == 12 && tagLength == 16) {
      return aesGcm128EncryptAsync(key, nonce, aad, aadLength, plaintext,
                                   ciphertext, length, tag, callback,
                                   context);
    }

    (void)key;
    (void)nonce;
    (void)aad;
    (void)aadLength;
    (void)plaintext;
    (void)ciphertext;
    (void)length;
    (void)tag;
    (void)callback;
    (void)context;
    return false;
  }

  /**
   * @brief Start async TLS AEAD decryption for a supported provider algorithm.
   *
   * Unsupported algorithms fail closed by default. This keeps Crypto generic
   * while making each production AEAD shape an explicit provider capability.
   *
   * @todo Add async hardware implementations for AES-256-GCM, AES-CCM,
   * AES-CCM-8, and ChaCha20-Poly1305 when those algorithms are promoted from
   * stubs to supported Crypto provider capabilities.
   */
  virtual bool aeadDecryptAsync(TlsAeadAlgorithm algorithm,
                                const uint8_t *key, size_t keyLength,
                                const uint8_t *nonce, size_t nonceLength,
                                const uint8_t *aad, size_t aadLength,
                                const uint8_t *ciphertext,
                                uint8_t *plaintext, size_t length,
                                const uint8_t *tag, size_t tagLength,
                                TlsAeadCallback callback, void *context) {
    if (algorithm == TlsAeadAlgorithm::Aes128Gcm && keyLength == 16 &&
        nonceLength == 12 && tagLength == 16) {
      return aesGcm128DecryptAsync(key, nonce, aad, aadLength, ciphertext,
                                   plaintext, length, tag, callback, context);
    }

    (void)key;
    (void)nonce;
    (void)aad;
    (void)aadLength;
    (void)ciphertext;
    (void)plaintext;
    (void)length;
    (void)tag;
    (void)callback;
    (void)context;
    return false;
  }
};

enum class TlsAsyncStatus : uint8_t {
  Idle,
  Busy,
  WantRead,
  WantWrite,
  WaitingCrypto,
  Complete,
  Error,
};

enum class TlsOperation : uint8_t {
  None,
  Handshake,
  Read,
  Write,
  CloseNotify,
};

enum class TlsRecordDirection : uint8_t {
  ClientWrite,
  ServerWrite,
};

enum class TlsRecordContentType : uint8_t {
  ChangeCipherSpec = 20,
  Alert = 21,
  Handshake = 22,
  ApplicationData = 23,
};

/**
 * @brief TLS 1.2 AES-128-GCM traffic keys for one client session.
 *
 * These values are produced by the TLS key schedule. `clientWrite*` protects
 * outbound client records and `serverWrite*` authenticates inbound server
 * records. Static IVs are the four-byte TLS 1.2 GCM salt; the explicit eight
 * bytes come from the record sequence number.
 */
struct TlsAesGcmRecordKeys {
  uint8_t clientWriteKey[16] = {};
  uint8_t serverWriteKey[16] = {};
  uint8_t clientWriteIv[4] = {};
  uint8_t serverWriteIv[4] = {};
};

enum class TlsVerificationPolicy : uint8_t {
  Required,
};

enum class TlsProtocolVersion : uint8_t {
  Tls12,
};

enum class TlsCipherSuite : uint8_t {
  EcdheEcdsaWithAes128GcmSha256,
};

/**
 * @brief Strict TLS policy supported by the current SecureClient profile.
 *
 * The policy is intentionally narrow and fail-closed. Runtime configuration
 * exists so callers and tests can state the contract explicitly; unsupported
 * values are rejected rather than silently widening the protocol surface.
 */
struct TlsClientPolicy {
  TlsVerificationPolicy verification = TlsVerificationPolicy::Required;
  TlsProtocolVersion minVersion = TlsProtocolVersion::Tls12;
  TlsProtocolVersion maxVersion = TlsProtocolVersion::Tls12;
  TlsCipherSuite cipherSuite = TlsCipherSuite::EcdheEcdsaWithAes128GcmSha256;
};

constexpr uint16_t DefaultTlsOperationPollLimit = 20000;
constexpr size_t TlsSha256DigestLength = 32;
#ifndef SIMIO_TLS_ECC_OPERATION_BUDGET
#define SIMIO_TLS_ECC_OPERATION_BUDGET 32
#endif
constexpr uint32_t DefaultTlsEccOperationBudget =
    SIMIO_TLS_ECC_OPERATION_BUDGET;

class TlsClientSession {
public:
  using Callback = void (*)(TlsAsyncStatus status, void *context);

  TlsClientSession();
  ~TlsClientSession();

  /**
   * @brief Store trust-anchor material lifetime supplied by the caller.
   *
   * Certificate parsing belongs to Mbed TLS and runs through PSA key import.
   * The caller must keep the memory valid for the session lifetime because the
   * session records the original trust material boundary as well as the parsed
   * Mbed TLS chain. This call must fail closed while an operation is active.
   */
  bool configureTrustAnchors(const uint8_t *data, size_t length);

  /**
   * @brief Set the hostname used for SNI and certificate verification.
   */
  bool setHostname(const char *hostname);

  /**
   * @brief Configure the optional client certificate and private key.
   *
   * The caller must keep both buffers valid for the session lifetime. Parsing
   * is delegated to Mbed TLS at configuration time so malformed identity
   * material fails before any handshake begins. This call fails closed while an
   * operation is active and clears any previously configured client identity on
   * parse failure.
   */
  bool configureClientIdentity(const uint8_t *certificate,
                               size_t certificateLength,
                               const uint8_t *privateKey,
                               size_t privateKeyLength);

  /**
   * @brief Configure optional ALPN protocols for future handshakes.
   *
   * `protocols` may be `nullptr` to disable ALPN. Otherwise it must point to a
   * null-terminated list of non-empty protocol strings that remains valid for
   * the session lifetime. The list is bounded by this wrapper before Mbed TLS
   * sees it so missing terminators and oversized names fail closed.
   */
  bool configureAlpnProtocols(const char *const *protocols);
  const char *negotiatedAlpnProtocol() const;

  /**
   * @brief Hash the current peer leaf certificate DER with SHA-256.
   *
   * This succeeds only after a completed TLS handshake. It is intended for
   * caller-owned pin checks on constrained bootstrap endpoints such as trusted
   * time sources. It hashes the complete leaf certificate DER; future SPKI
   * pinning can use the parsed peer certificate public-key field without
   * widening the TLS policy surface.
   */
  bool peerCertificateSha256(uint8_t digest[TlsSha256DigestLength]) const;

  /**
   * @brief Configure trusted UTC Unix time for certificate validity checks.
   *
   * TLS handshakes fail closed until a caller provides a trusted timestamp.
   * This is intentionally separate from transport setup because Ethernet and
   * other peripherals may obtain time from different authenticated sources.
   * The value is passed to the local Mbed TLS platform hook before certificate
   * verification so not-before/not-after checks are enabled in production.
   */
  bool configureTrustedTime(uint64_t unixTime);
  void clearTrustedTime();
  bool trustedTimeConfigured() const { return _trustedTimeConfigured; }
  uint64_t trustedUnixTime() const { return _trustedUnixTime; }

  /**
   * @brief Configure the strict TLS policy used for future handshakes.
   *
   * This call fails while an operation is active. The current implementation
   * supports only TLS 1.2 with required certificate verification and
   * ECDHE-ECDSA-AES128-GCM-SHA256. Unsupported enum values fail closed so
   * adding broader policy later requires explicit implementation and tests.
   */
  bool configurePolicy(const TlsClientPolicy &policy);
  const TlsClientPolicy &policy() const { return _policy; }

  /**
   * @brief Configure the bounded progress deadline for each TLS operation.
   *
   * Each active handshake/read/write/close-notify operation may consume at most
   * `pollLimit` calls to `poll()`. The limit must be nonzero and can only be
   * changed while idle. Expired operations, including a handshake stalled while
   * waiting for async crypto readiness, fail closed and invoke the pending
   * operation callback with `TlsAsyncStatus::Error`.
   */
  bool configureOperationPollLimit(uint16_t pollLimit);
  uint16_t operationPollLimit() const { return _operationPollLimit; }

  /**
   * @brief Enable or disable the in-memory TLS session reuse cache.
   *
   * When enabled, a completed handshake captures Mbed TLS session state for a
   * future handshake on the same `TlsClientSession` instance. The cached session
   * never leaves this object and can only be changed while no TLS operation is
   * active. Disabling reuse clears any cached session material.
   */
  bool enableSessionReuse(bool enabled);
  bool sessionReuseEnabled() const { return _sessionReuseEnabled; }
  bool sessionCached() const { return _sessionCached; }

  /**
   * @brief Clear any cached TLS session material.
   *
   * This is an idle-only operation because Mbed TLS owns session state while a
   * handshake/read/write/close-notify operation is active.
   */
  bool clearSessionCache();

  /**
   * @brief Bind the TLS BIO to an already-created non-blocking transport.
   */
  bool bindTransport(TlsTransport &transport);

  /**
   * @brief Bind the async crypto provider used before TLS handshake progress.
   *
   * A production provider owns TLS crypto readiness and direct async primitive
   * dispatch. Tests may inject a mock provider to verify state-machine behavior
   * without hardware.
   */
  bool bindCryptoProvider(TlsCryptoProvider &provider);

  /**
   * @brief Configure TLS 1.2 AES-128-GCM record-protection keys.
   *
   * This is the record-layer boundary between TLS protocol state and the async
   * hardware AES-GCM provider. It stores only traffic keys and fixed IVs;
   * record sequence numbers remain explicit arguments so callers can enforce
   * monotonic sequencing at the TLS state-machine layer.
   */
  bool configureAesGcmRecordKeys(const TlsAesGcmRecordKeys &keys);

  /**
   * @brief Protect one TLS 1.2 AES-128-GCM record fragment asynchronously.
   *
   * `output` receives explicit_nonce || ciphertext || tag. AAD is constructed
   * as seq_num || content_type || TLS 1.2 version || plaintext_length, and the
   * 12-byte GCM nonce is fixed_iv || explicit_nonce. Completion reports through
   * `callback`; `outputLength` is written only on success.
   */
  bool protectAesGcmRecordAsync(
      TlsRecordDirection direction, TlsRecordContentType type,
      uint64_t sequenceNumber, const uint8_t *plaintext, size_t length,
      uint8_t *output, size_t outputCapacity, size_t &outputLength,
      TlsAesGcm128Callback callback, void *context = nullptr);

  /**
   * @brief Authenticate and decrypt one TLS 1.2 AES-128-GCM record fragment.
   *
   * `input` must contain explicit_nonce || ciphertext || tag. The plaintext
   * output is valid only when the callback reports success.
   */
  bool unprotectAesGcmRecordAsync(
      TlsRecordDirection direction, TlsRecordContentType type,
      uint64_t sequenceNumber, const uint8_t *input, size_t inputLength,
      uint8_t *plaintext, size_t plaintextCapacity, size_t &plaintextLength,
      TlsAesGcm128Callback callback, void *context = nullptr);

  /**
   * @brief Start async TLS handshake progress.
   *
   * The call validates configuration and stores callback state only. `poll()`
   * reports `WaitingCrypto` until the bound `TlsCryptoProvider` has completed
   * readiness, then advances one bounded Mbed TLS handshake step per call and
   * reports `WantRead`/`WantWrite` when the transport cannot progress.
   */
  TlsAsyncStatus handshakeAsync(Callback callback, void *context = nullptr);

  /**
   * @brief Start an async TLS read operation.
   */
  TlsAsyncStatus readAsync(uint8_t *buffer, size_t length, Callback callback,
                           void *context = nullptr);

  /**
   * @brief Start an async TLS write operation.
   */
  TlsAsyncStatus writeAsync(const uint8_t *buffer, size_t length,
                            Callback callback, void *context = nullptr);

  /**
   * @brief Start an async TLS close-notify operation.
   */
  TlsAsyncStatus closeNotifyAsync(Callback callback, void *context = nullptr);

  /**
   * @brief Advance one bounded unit of TLS work.
   *
   * ECC-heavy handshake phases are bounded with Mbed TLS/PSA interruptable
   * crypto. When certificate verification, ECDSA verification/signing, or
   * restartable PSA ECC reaches `DefaultTlsEccOperationBudget`, `poll()`
   * returns `TlsAsyncStatus::Busy` with `lastMbedTlsResult()` set to
   * `MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS`. Callers must run the surrounding
   * network/peripheral service loop and call `poll()` again to resume the same
   * Mbed TLS operation. This is the TLS-level contract that prevents
   * ECDHE/ECDSA work from monopolizing the cooperative runtime. Boards may
   * raise `SIMIO_TLS_ECC_OPERATION_BUDGET` to trade longer bounded poll slices
   * for fewer resumes while keeping TLS progress cooperative.
   *
   * This budget is a temporary containment mechanism for Mbed TLS/PSA software
   * ECC during bring-up. Final SAME5x builds must route exact ECDH/ECDSA
   * mappings through async PUKCC adapters instead of relying on software ECC
   * resumes for normal secure-client operation.
   */
  TlsAsyncStatus poll();

  /**
   * @brief Abort session state without attempting close-notify.
   */
  void abort();

  TlsAsyncStatus status() const { return _status; }
  TlsOperation operation() const { return _operation; }
  int lastError() const { return _lastError; }
  int lastMbedTlsResult() const { return _lastMbedTlsResult; }
  uint32_t verificationResult() const { return _verificationResult; }
  bool configured() const;
  bool handshakeComplete() const { return _handshakeComplete; }
  /**
   * @brief Return true after a read observes TLS close-notify from the peer.
   */
  bool peerCloseNotified() const { return _peerCloseNotified; }
  size_t bytesTransferred() const { return _bytesTransferred; }
  int handshakeState() const { return _ssl.MBEDTLS_PRIVATE(state); }
  uint32_t bioSendCalls() const { return _bioSendCalls; }
  uint32_t bioRecvCalls() const { return _bioRecvCalls; }
  uint32_t bioRecvWantReadCount() const { return _bioRecvWantReadCount; }
  size_t bioBytesSent() const { return _bioBytesSent; }
  size_t bioBytesReceived() const { return _bioBytesReceived; }
  size_t bioLastSendLength() const { return _bioLastSendLength; }
  size_t bioLastSendAccepted() const { return _bioLastSendAccepted; }
  size_t bioLastRecvLength() const { return _bioLastRecvLength; }
  int bioLastRecvAvailable() const { return _bioLastRecvAvailable; }

private:
  bool operationActive() const;
  bool startOperation(TlsOperation operation, Callback callback, void *context);
  bool startHandshakeCrypto();
  bool prepareMbedTlsSession();
  void resetMbedTlsSession();
  TlsAsyncStatus pollHandshake();
  TlsAsyncStatus pollRead();
  TlsAsyncStatus pollWrite();
  TlsAsyncStatus pollCloseNotify();
  TlsAsyncStatus handleMbedTlsResult(int result);
  TlsAsyncStatus finish(TlsAsyncStatus status);
  TlsAsyncStatus fail(int error);
  TlsAsyncStatus reject(int error);
  static void handleCryptoReady(bool success, void *context);
  static void handleRecordProtectionComplete(bool success, void *context);
  static int handleCertificateVerify(void *context, mbedtls_x509_crt *crt,
                                     int depth, uint32_t *flags);
  static int bioSend(void *context, const unsigned char *buffer, size_t length);
  static int bioRecv(void *context, unsigned char *buffer, size_t length);

  TlsTransport *_transport;
  TlsCryptoProvider *_cryptoProvider;
  const uint8_t *_trustAnchors;
  size_t _trustAnchorLength;
  const char *_hostname;
  const char *const *_alpnProtocols;
  uint64_t _trustedUnixTime;
  TlsClientPolicy _policy;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _sslConfig;
  mbedtls_x509_crt _caChain;
  mbedtls_x509_crt _clientCertificate;
  mbedtls_pk_context _clientKey;
  mbedtls_ssl_session _savedSession;
  TlsAesGcmRecordKeys _recordKeys;
  TlsAsyncStatus _status;
  TlsOperation _operation;
  Callback _callback;
  void *_callbackContext;
  TlsAesGcm128Callback _recordCallback;
  void *_recordCallbackContext;
  size_t *_recordOutputLength;
  size_t _recordPendingLength;
  uint8_t _recordNonce[12];
  uint8_t _recordAad[13];
  uint8_t *_readBuffer;
  const uint8_t *_writeBuffer;
  size_t _requestedLength;
  size_t _bytesTransferred;
  uint8_t _peerCertificateSha256[TlsSha256DigestLength];
  uint32_t _bioSendCalls;
  uint32_t _bioRecvCalls;
  uint32_t _bioRecvWantReadCount;
  size_t _bioBytesSent;
  size_t _bioBytesReceived;
  size_t _bioLastSendLength;
  size_t _bioLastSendAccepted;
  size_t _bioLastRecvLength;
  int _bioLastRecvAvailable;
  uint16_t _operationPollLimit;
  uint16_t _operationPollCount;
  int _lastError;
  int _lastMbedTlsResult;
  uint32_t _verificationResult;
  bool _handshakeComplete;
  bool _peerCertificateSha256Available;
  bool _cryptoReady;
  bool _cryptoFailed;
  bool _tlsConfigured;
  bool _peerCloseNotified;
  bool _trustedTimeConfigured;
  bool _clientIdentityConfigured;
  bool _sessionReuseEnabled;
  bool _sessionCached;
  bool _recordKeysConfigured;
  bool _recordProtectionBusy;
};

} // namespace Crypto
