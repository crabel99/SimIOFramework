#include "TlsClientSession.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>
#include <string.h>

namespace Crypto {

namespace MbedTlsPort {
bool setExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
void clearExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
bool setTrustedTime(uint64_t unixTime);
void clearTrustedTime();
bool hasTrustedTime();
} // namespace MbedTlsPort

namespace {
constexpr int TlsErrorInvalidState = -1;
constexpr int TlsErrorInvalidArgument = -2;
constexpr int TlsErrorTransportUnavailable = -3;
constexpr int TlsErrorTransportDisconnected = -4;
constexpr int TlsErrorCryptoUnavailable = -5;
constexpr int TlsErrorCryptoFailed = -6;
constexpr int TlsErrorMbedTlsSetupFailed = -7;
constexpr int TlsErrorMbedTlsIoFailed = -8;
constexpr int TlsErrorOperationDeadlineExceeded = -9;
constexpr int TlsErrorTrustedTimeUnavailable = -10;
constexpr uint64_t MinTrustedUnixTime = 946684800ULL;
constexpr size_t MaxAlpnProtocols = 8;
constexpr size_t TlsGcmExplicitNonceLength = 8;
constexpr size_t TlsGcmTagLength = 16;
constexpr size_t TlsGcmFixedIvLength = 4;
constexpr size_t TlsGcmNonceLength = 12;
constexpr size_t TlsRecordAadLength = 13;
constexpr size_t MaxTlsPlaintextLength = 16384;
constexpr uint8_t Tls12Major = 0x03;
constexpr uint8_t Tls12Minor = 0x03;

constexpr int StrictTls12CipherSuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};

constexpr uint16_t StrictTlsSignatureAlgorithms[] = {
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
    MBEDTLS_TLS1_3_SIG_NONE};

bool policySupported(const TlsClientPolicy &policy) {
  return policy.verification == TlsVerificationPolicy::Required &&
         policy.minVersion == TlsProtocolVersion::Tls12 &&
         policy.maxVersion == TlsProtocolVersion::Tls12 &&
         policy.cipherSuite ==
             TlsCipherSuite::EcdheEcdsaWithAes128GcmSha256;
}

bool alpnListSupported(const char *const *protocols) {
  if (protocols == nullptr)
    return true;

  size_t totalLength = 0;
  for (size_t index = 0; index <= MaxAlpnProtocols; ++index) {
    const char *protocol = protocols[index];
    if (protocol == nullptr)
      return index != 0;

    const size_t length = strlen(protocol);
    if (length == 0 || length > MBEDTLS_SSL_MAX_ALPN_NAME_LEN)
      return false;
    totalLength += length + 1;
    if (totalLength > MBEDTLS_SSL_MAX_ALPN_LIST_LEN)
      return false;
  }

  return false;
}

void configureInterruptableCryptoBudget() {
#if defined(MBEDTLS_ECP_RESTARTABLE)
  psa_interruptible_set_max_ops(DefaultTlsEccOperationBudget);
#endif
}

void storeUint16(uint8_t *destination, uint16_t value) {
  destination[0] = static_cast<uint8_t>((value >> 8) & 0xFFu);
  destination[1] = static_cast<uint8_t>(value & 0xFFu);
}

void storeUint64(uint8_t *destination, uint64_t value) {
  for (uint8_t index = 0; index < 8; ++index) {
    destination[7u - index] = static_cast<uint8_t>(value & 0xFFu);
    value >>= 8;
  }
}

void buildTls12GcmAad(uint8_t aad[TlsRecordAadLength], uint64_t sequenceNumber,
                      TlsRecordContentType type, size_t plaintextLength) {
  storeUint64(aad, sequenceNumber);
  aad[8] = static_cast<uint8_t>(type);
  aad[9] = Tls12Major;
  aad[10] = Tls12Minor;
  storeUint16(&aad[11], static_cast<uint16_t>(plaintextLength));
}

void buildTls12GcmNonce(
    uint8_t nonce[TlsGcmNonceLength],
    const uint8_t fixedIv[TlsGcmFixedIvLength],
    const uint8_t explicitNonce[TlsGcmExplicitNonceLength]) {
  memcpy(nonce, fixedIv, TlsGcmFixedIvLength);
  memcpy(&nonce[TlsGcmFixedIvLength], explicitNonce, TlsGcmExplicitNonceLength);
}

bool validRecordType(TlsRecordContentType type) {
  switch (type) {
  case TlsRecordContentType::ChangeCipherSpec:
  case TlsRecordContentType::Alert:
  case TlsRecordContentType::Handshake:
  case TlsRecordContentType::ApplicationData:
    return true;
  default:
    return false;
  }
}

class ExternalRandomProviderGuard {
public:
  explicit ExternalRandomProviderGuard(TlsCryptoProvider *provider)
      : _provider(provider),
        _active(MbedTlsPort::setExternalRandomProvider(provider)) {}

  ~ExternalRandomProviderGuard() {
    if (_active)
      MbedTlsPort::clearExternalRandomProvider(_provider);
  }

  bool active() const { return _active; }

private:
  TlsCryptoProvider *_provider;
  bool _active;
};
} // namespace

TlsClientSession::TlsClientSession()
    : _transport(nullptr), _cryptoProvider(nullptr), _trustAnchors(nullptr),
      _trustAnchorLength(0), _hostname(nullptr), _alpnProtocols(nullptr),
      _trustedUnixTime(0), _policy(), _status(TlsAsyncStatus::Idle), _operation(TlsOperation::None),
      _callback(nullptr), _callbackContext(nullptr), _recordCallback(nullptr),
      _recordCallbackContext(nullptr), _recordOutputLength(nullptr),
      _recordPendingLength(0), _recordNonce{}, _recordAad{},
      _readBuffer(nullptr), _writeBuffer(nullptr), _requestedLength(0),
      _bytesTransferred(0), _bioSendCalls(0), _bioRecvCalls(0),
      _bioRecvWantReadCount(0), _bioBytesSent(0), _bioBytesReceived(0),
      _bioLastSendLength(0), _bioLastSendAccepted(0), _bioLastRecvLength(0),
      _bioLastRecvAvailable(0),
      _operationPollLimit(DefaultTlsOperationPollLimit),
      _operationPollCount(0), _lastError(0), _lastMbedTlsResult(0),
      _verificationResult(0), _handshakeComplete(false),
      _peerCertificateSha256Available(false), _cryptoReady(false),
      _cryptoFailed(false), _tlsConfigured(false), _peerCloseNotified(false),
      _trustedTimeConfigured(false), _clientIdentityConfigured(false),
      _sessionReuseEnabled(false),
      _sessionCached(false), _recordKeysConfigured(false),
      _recordProtectionBusy(false) {
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_sslConfig);
  mbedtls_x509_crt_init(&_caChain);
  mbedtls_x509_crt_init(&_clientCertificate);
  mbedtls_pk_init(&_clientKey);
  mbedtls_ssl_session_init(&_savedSession);
}

TlsClientSession::~TlsClientSession() {
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_config_free(&_sslConfig);
  mbedtls_x509_crt_free(&_caChain);
  mbedtls_x509_crt_free(&_clientCertificate);
  mbedtls_pk_free(&_clientKey);
  mbedtls_ssl_session_free(&_savedSession);
}

bool TlsClientSession::configureTrustAnchors(const uint8_t *data,
                                             size_t length) {
  if (operationActive() || data == nullptr || length == 0)
    return false;

  const psa_status_t psaInitResult = psa_crypto_init();
  if (psaInitResult != PSA_SUCCESS) {
    _lastError = static_cast<int>(psaInitResult);
    return false;
  }

  mbedtls_x509_crt_free(&_caChain);
  mbedtls_x509_crt_init(&_caChain);
  const int parseResult = mbedtls_x509_crt_parse(&_caChain, data, length);
  if (parseResult != 0) {
    _lastError = parseResult;
    return false;
  }

  _trustAnchors = data;
  _trustAnchorLength = length;
  _tlsConfigured = false;
  return true;
}

bool TlsClientSession::setHostname(const char *hostname) {
  if (operationActive() || hostname == nullptr || hostname[0] == '\0')
    return false;

  _hostname = hostname;
  _tlsConfigured = false;
  return true;
}

bool TlsClientSession::configureClientIdentity(const uint8_t *certificate,
                                               size_t certificateLength,
                                               const uint8_t *privateKey,
                                               size_t privateKeyLength) {
  if (operationActive() || certificate == nullptr || certificateLength == 0 ||
      privateKey == nullptr || privateKeyLength == 0)
    return false;

  const psa_status_t psaInitResult = psa_crypto_init();
  if (psaInitResult != PSA_SUCCESS) {
    _lastError = static_cast<int>(psaInitResult);
    return false;
  }

  mbedtls_x509_crt_free(&_clientCertificate);
  mbedtls_x509_crt_init(&_clientCertificate);
  mbedtls_pk_free(&_clientKey);
  mbedtls_pk_init(&_clientKey);
  _clientIdentityConfigured = false;

  int parseResult =
      mbedtls_x509_crt_parse(&_clientCertificate, certificate, certificateLength);
  if (parseResult != 0) {
    _lastError = parseResult;
    return false;
  }

  parseResult =
      mbedtls_pk_parse_key(&_clientKey, privateKey, privateKeyLength, nullptr, 0);
  if (parseResult != 0) {
    mbedtls_x509_crt_free(&_clientCertificate);
    mbedtls_x509_crt_init(&_clientCertificate);
    _lastError = parseResult;
    return false;
  }

  _clientIdentityConfigured = true;
  _tlsConfigured = false;
  return true;
}

bool TlsClientSession::configureAlpnProtocols(const char *const *protocols) {
  if (operationActive() || !alpnListSupported(protocols))
    return false;

  _alpnProtocols = protocols;
  _tlsConfigured = false;
  return true;
}

const char *TlsClientSession::negotiatedAlpnProtocol() const {
  if (!_handshakeComplete)
    return nullptr;

  return mbedtls_ssl_get_alpn_protocol(&_ssl);
}

bool TlsClientSession::peerCertificateSha256(
    uint8_t digest[TlsSha256DigestLength]) const {
  if (!_handshakeComplete || !_peerCertificateSha256Available ||
      digest == nullptr)
    return false;

  memcpy(digest, _peerCertificateSha256, TlsSha256DigestLength);
  return true;
}

bool TlsClientSession::configureTrustedTime(uint64_t unixTime) {
  if (operationActive() || unixTime < MinTrustedUnixTime)
    return false;

  _trustedUnixTime = unixTime;
  _trustedTimeConfigured = true;
  _tlsConfigured = false;
  return true;
}

void TlsClientSession::clearTrustedTime() {
  if (operationActive())
    return;

  _trustedUnixTime = 0;
  _trustedTimeConfigured = false;
  _tlsConfigured = false;
  MbedTlsPort::clearTrustedTime();
}

bool TlsClientSession::configurePolicy(const TlsClientPolicy &policy) {
  if (operationActive() || !policySupported(policy))
    return false;

  _policy = policy;
  _tlsConfigured = false;
  return true;
}

bool TlsClientSession::configureOperationPollLimit(uint16_t pollLimit) {
  if (operationActive() || pollLimit == 0)
    return false;

  _operationPollLimit = pollLimit;
  return true;
}

bool TlsClientSession::enableSessionReuse(bool enabled) {
  if (operationActive())
    return false;

  _sessionReuseEnabled = enabled;
  if (!enabled)
    return clearSessionCache();

  return true;
}

bool TlsClientSession::clearSessionCache() {
  if (operationActive())
    return false;

  mbedtls_ssl_session_free(&_savedSession);
  mbedtls_ssl_session_init(&_savedSession);
  _sessionCached = false;
  return true;
}

bool TlsClientSession::bindTransport(TlsTransport &transport) {
  if (operationActive())
    return false;

  _transport = &transport;
  _handshakeComplete = false;
  _cryptoReady = false;
  _tlsConfigured = false;
  return true;
}

bool TlsClientSession::bindCryptoProvider(TlsCryptoProvider &provider) {
  if (operationActive())
    return false;

  _cryptoProvider = &provider;
  _cryptoReady = provider.ready();
  _cryptoFailed = false;
  _tlsConfigured = false;
  _peerCloseNotified = false;
  return true;
}

bool TlsClientSession::configureAesGcmRecordKeys(
    const TlsAesGcmRecordKeys &keys) {
  if (operationActive() || _recordProtectionBusy)
    return false;

  _recordKeys = keys;
  _recordKeysConfigured = true;
  return true;
}

bool TlsClientSession::protectAesGcmRecordAsync(
    TlsRecordDirection direction, TlsRecordContentType type,
    uint64_t sequenceNumber, const uint8_t *plaintext, size_t length,
    uint8_t *output, size_t outputCapacity, size_t &outputLength,
    TlsAesGcm128Callback callback, void *context) {
  if (_cryptoProvider == nullptr || !_recordKeysConfigured ||
      _recordProtectionBusy || callback == nullptr || output == nullptr ||
      !validRecordType(type) || length > MaxTlsPlaintextLength ||
      (plaintext == nullptr && length != 0)) {
    return false;
  }

  const size_t protectedLength =
      TlsGcmExplicitNonceLength + length + TlsGcmTagLength;
  if (outputCapacity < protectedLength)
    return false;

  const uint8_t *key = direction == TlsRecordDirection::ClientWrite
                           ? _recordKeys.clientWriteKey
                           : _recordKeys.serverWriteKey;
  const uint8_t *fixedIv = direction == TlsRecordDirection::ClientWrite
                               ? _recordKeys.clientWriteIv
                               : _recordKeys.serverWriteIv;
  storeUint64(output, sequenceNumber);
  buildTls12GcmNonce(_recordNonce, fixedIv, output);
  buildTls12GcmAad(_recordAad, sequenceNumber, type, length);

  _recordCallback = callback;
  _recordCallbackContext = context;
  _recordOutputLength = &outputLength;
  _recordPendingLength = protectedLength;
  _recordProtectionBusy = true;

  const bool submitted = _cryptoProvider->aesGcm128EncryptAsync(
      key, _recordNonce, _recordAad, sizeof(_recordAad), plaintext,
      length == 0 ? nullptr : &output[TlsGcmExplicitNonceLength], length,
      &output[TlsGcmExplicitNonceLength + length],
      TlsClientSession::handleRecordProtectionComplete, this);
  if (!submitted) {
    _recordCallback = nullptr;
    _recordCallbackContext = nullptr;
    _recordOutputLength = nullptr;
    _recordPendingLength = 0;
    mbedtls_platform_zeroize(_recordNonce, sizeof(_recordNonce));
    mbedtls_platform_zeroize(_recordAad, sizeof(_recordAad));
    _recordProtectionBusy = false;
  }

  return submitted;
}

bool TlsClientSession::unprotectAesGcmRecordAsync(
    TlsRecordDirection direction, TlsRecordContentType type,
    uint64_t sequenceNumber, const uint8_t *input, size_t inputLength,
    uint8_t *plaintext, size_t plaintextCapacity, size_t &plaintextLength,
    TlsAesGcm128Callback callback, void *context) {
  if (_cryptoProvider == nullptr || !_recordKeysConfigured ||
      _recordProtectionBusy || callback == nullptr || input == nullptr ||
      !validRecordType(type) ||
      inputLength < TlsGcmExplicitNonceLength + TlsGcmTagLength) {
    return false;
  }

  const size_t ciphertextLength =
      inputLength - TlsGcmExplicitNonceLength - TlsGcmTagLength;
  if (ciphertextLength > MaxTlsPlaintextLength ||
      plaintextCapacity < ciphertextLength ||
      (plaintext == nullptr && ciphertextLength != 0)) {
    return false;
  }

  const uint8_t *key = direction == TlsRecordDirection::ClientWrite
                           ? _recordKeys.clientWriteKey
                           : _recordKeys.serverWriteKey;
  const uint8_t *fixedIv = direction == TlsRecordDirection::ClientWrite
                               ? _recordKeys.clientWriteIv
                               : _recordKeys.serverWriteIv;
  buildTls12GcmNonce(_recordNonce, fixedIv, input);
  buildTls12GcmAad(_recordAad, sequenceNumber, type, ciphertextLength);

  _recordCallback = callback;
  _recordCallbackContext = context;
  _recordOutputLength = &plaintextLength;
  _recordPendingLength = ciphertextLength;
  _recordProtectionBusy = true;

  const bool submitted = _cryptoProvider->aesGcm128DecryptAsync(
      key, _recordNonce, _recordAad, sizeof(_recordAad),
      &input[TlsGcmExplicitNonceLength], plaintext, ciphertextLength,
      &input[inputLength - TlsGcmTagLength],
      TlsClientSession::handleRecordProtectionComplete, this);
  if (!submitted) {
    _recordCallback = nullptr;
    _recordCallbackContext = nullptr;
    _recordOutputLength = nullptr;
    _recordPendingLength = 0;
    mbedtls_platform_zeroize(_recordNonce, sizeof(_recordNonce));
    mbedtls_platform_zeroize(_recordAad, sizeof(_recordAad));
    _recordProtectionBusy = false;
  }

  return submitted;
}

TlsAsyncStatus TlsClientSession::handshakeAsync(Callback callback,
                                                void *context) {
  if (operationActive())
    return reject(TlsErrorInvalidState);
  if (!configured())
    return fail(TlsErrorInvalidState);
  if (_transport == nullptr || !_transport->carrierUp())
    return fail(TlsErrorTransportUnavailable);
  if (_transport->connected() == 0)
    return fail(TlsErrorTransportDisconnected);

  if (!startOperation(TlsOperation::Handshake, callback, context))
    return fail(TlsErrorInvalidState);
  if (!startHandshakeCrypto())
    return fail(TlsErrorCryptoUnavailable);

  return _status;
}

TlsAsyncStatus TlsClientSession::readAsync(uint8_t *buffer, size_t length,
                                           Callback callback, void *context) {
  if (operationActive())
    return reject(TlsErrorInvalidState);
  if (!_handshakeComplete)
    return fail(TlsErrorInvalidState);
  if (buffer == nullptr || length == 0)
    return fail(TlsErrorInvalidArgument);
  if (!startOperation(TlsOperation::Read, callback, context))
    return fail(TlsErrorInvalidState);

  _readBuffer = buffer;
  _requestedLength = length;
  return _status;
}

TlsAsyncStatus TlsClientSession::writeAsync(const uint8_t *buffer,
                                            size_t length, Callback callback,
                                            void *context) {
  if (operationActive())
    return reject(TlsErrorInvalidState);
  if (!_handshakeComplete)
    return fail(TlsErrorInvalidState);
  if (buffer == nullptr || length == 0)
    return fail(TlsErrorInvalidArgument);
  if (!startOperation(TlsOperation::Write, callback, context))
    return fail(TlsErrorInvalidState);

  _writeBuffer = buffer;
  _requestedLength = length;
  return _status;
}

TlsAsyncStatus TlsClientSession::closeNotifyAsync(Callback callback,
                                                  void *context) {
  if (operationActive())
    return reject(TlsErrorInvalidState);
  if (!_handshakeComplete)
    return fail(TlsErrorInvalidState);
  if (!startOperation(TlsOperation::CloseNotify, callback, context))
    return fail(TlsErrorInvalidState);

  return _status;
}

TlsAsyncStatus TlsClientSession::poll() {
  if (_transport == nullptr)
    return fail(TlsErrorTransportUnavailable);

  auto consumeOperationPoll = [this]() -> bool {
    if (_operationPollCount >= _operationPollLimit)
      return false;
    ++_operationPollCount;
    return true;
  };

  switch (_operation) {
  case TlsOperation::Handshake:
    if (!_transport->carrierUp() || _transport->connected() == 0)
      return fail(TlsErrorTransportDisconnected);
    if (!consumeOperationPoll())
      return fail(TlsErrorOperationDeadlineExceeded);
    if (_cryptoFailed)
      return fail(TlsErrorCryptoFailed);
    if (!_cryptoReady) {
      _status = TlsAsyncStatus::WaitingCrypto;
      return _status;
    }
    if (!prepareMbedTlsSession())
      return fail(TlsErrorMbedTlsSetupFailed);
    return pollHandshake();
  case TlsOperation::Read:
    if (!consumeOperationPoll())
      return fail(TlsErrorOperationDeadlineExceeded);
    return pollRead();
  case TlsOperation::Write:
    if (!consumeOperationPoll())
      return fail(TlsErrorOperationDeadlineExceeded);
    return pollWrite();
  case TlsOperation::CloseNotify:
    if (!consumeOperationPoll())
      return fail(TlsErrorOperationDeadlineExceeded);
    return pollCloseNotify();
  case TlsOperation::None:
  default:
    return _status;
  }
}

void TlsClientSession::abort() {
  _status = TlsAsyncStatus::Idle;
  _operation = TlsOperation::None;
  _callback = nullptr;
  _callbackContext = nullptr;
  _recordCallback = nullptr;
  _recordCallbackContext = nullptr;
  _recordOutputLength = nullptr;
  _recordPendingLength = 0;
  mbedtls_platform_zeroize(_recordNonce, sizeof(_recordNonce));
  mbedtls_platform_zeroize(_recordAad, sizeof(_recordAad));
  _recordProtectionBusy = false;
  _readBuffer = nullptr;
  _writeBuffer = nullptr;
  _requestedLength = 0;
  _bytesTransferred = 0;
  mbedtls_platform_zeroize(_peerCertificateSha256,
                           sizeof(_peerCertificateSha256));
  _peerCertificateSha256Available = false;
  _bioSendCalls = 0;
  _bioRecvCalls = 0;
  _bioRecvWantReadCount = 0;
  _bioBytesSent = 0;
  _bioBytesReceived = 0;
  _bioLastSendLength = 0;
  _bioLastSendAccepted = 0;
  _bioLastRecvLength = 0;
  _bioLastRecvAvailable = 0;
  _lastMbedTlsResult = 0;
  _handshakeComplete = false;
  _cryptoReady = false;
  _cryptoFailed = false;
  _peerCloseNotified = false;
  resetMbedTlsSession();
  if (_cryptoProvider != nullptr)
    _cryptoProvider->reset();
}

bool TlsClientSession::configured() const {
  return _transport != nullptr && _trustAnchors != nullptr &&
         _trustAnchorLength != 0 && _hostname != nullptr &&
         _cryptoProvider != nullptr && _trustedTimeConfigured;
}

bool TlsClientSession::operationActive() const {
  return _operation != TlsOperation::None;
}

bool TlsClientSession::startOperation(TlsOperation operation, Callback callback,
                                      void *context) {
  if (operationActive() || callback == nullptr)
    return false;

  _operation = operation;
  _callback = callback;
  _callbackContext = context;
  _readBuffer = nullptr;
  _writeBuffer = nullptr;
  _requestedLength = 0;
  _bytesTransferred = 0;
  _operationPollCount = 0;
  _lastError = 0;
  _lastMbedTlsResult = 0;
  _status = TlsAsyncStatus::Busy;
  if (operation == TlsOperation::Handshake) {
    _verificationResult = 0;
    _peerCloseNotified = false;
    mbedtls_platform_zeroize(_peerCertificateSha256,
                             sizeof(_peerCertificateSha256));
    _peerCertificateSha256Available = false;
  }
  return true;
}

bool TlsClientSession::startHandshakeCrypto() {
  if (_cryptoProvider == nullptr)
    return false;

  _cryptoReady = _cryptoProvider->ready();
  _cryptoFailed = false;
  if (_cryptoReady)
    return true;

  return _cryptoProvider->beginHandshakeCrypto(handleCryptoReady, this);
}

bool TlsClientSession::prepareMbedTlsSession() {
  if (_tlsConfigured)
    return true;
  if (_trustAnchors == nullptr || _trustAnchorLength == 0 ||
      _hostname == nullptr || !_trustedTimeConfigured)
    return false;

  if (!MbedTlsPort::setTrustedTime(_trustedUnixTime) ||
      !MbedTlsPort::hasTrustedTime()) {
    _lastError = TlsErrorTrustedTimeUnavailable;
    return false;
  }

  resetMbedTlsSession();

  int result = mbedtls_ssl_config_defaults(
      &_sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT);
  if (result != 0) {
    _lastError = result;
    return false;
  }

  mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_verify(&_sslConfig,
                          TlsClientSession::handleCertificateVerify, this);
  mbedtls_ssl_conf_min_tls_version(&_sslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&_sslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_ciphersuites(&_sslConfig, StrictTls12CipherSuites);
  mbedtls_ssl_conf_sig_algs(&_sslConfig, StrictTlsSignatureAlgorithms);
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  mbedtls_ssl_conf_session_tickets(&_sslConfig,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
  mbedtls_ssl_conf_ca_chain(&_sslConfig, &_caChain, nullptr);
  if (_alpnProtocols != nullptr) {
    result = mbedtls_ssl_conf_alpn_protocols(&_sslConfig, _alpnProtocols);
    if (result != 0) {
      _lastError = result;
      return false;
    }
  }
  if (_clientIdentityConfigured) {
    result = mbedtls_ssl_conf_own_cert(&_sslConfig, &_clientCertificate,
                                       &_clientKey);
    if (result != 0) {
      _lastError = result;
      return false;
    }
  }

  result = mbedtls_ssl_setup(&_ssl, &_sslConfig);
  if (result != 0) {
    _lastError = result;
    return false;
  }

  result = mbedtls_ssl_set_hostname(&_ssl, _hostname);
  if (result != 0) {
    _lastError = result;
    return false;
  }

  if (_sessionReuseEnabled && _sessionCached) {
    result = mbedtls_ssl_set_session(&_ssl, &_savedSession);
    if (result != 0) {
      _lastError = result;
      return false;
    }
  }

  mbedtls_ssl_set_bio(&_ssl, this, TlsClientSession::bioSend,
                      TlsClientSession::bioRecv, nullptr);

  _tlsConfigured = true;
  return true;
}

void TlsClientSession::resetMbedTlsSession() {
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_config_free(&_sslConfig);
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_sslConfig);
  _tlsConfigured = false;
  _handshakeComplete = false;
  mbedtls_platform_zeroize(_peerCertificateSha256,
                           sizeof(_peerCertificateSha256));
  _peerCertificateSha256Available = false;
}

TlsAsyncStatus TlsClientSession::pollHandshake() {
  ExternalRandomProviderGuard randomGuard(_cryptoProvider);
  if (!randomGuard.active())
    return fail(TlsErrorCryptoUnavailable);

  configureInterruptableCryptoBudget();
  const int result = mbedtls_ssl_handshake_step(&_ssl);
  _lastMbedTlsResult = result;
  if (result == 0 && !mbedtls_ssl_is_handshake_over(&_ssl)) {
    _status = TlsAsyncStatus::Busy;
    return _status;
  }
  if (result == 0) {
    _verificationResult = mbedtls_ssl_get_verify_result(&_ssl);
    _handshakeComplete = true;
    if (_sessionReuseEnabled) {
      mbedtls_ssl_session_free(&_savedSession);
      mbedtls_ssl_session_init(&_savedSession);
      const int sessionResult = mbedtls_ssl_get_session(&_ssl, &_savedSession);
      _sessionCached = sessionResult == 0;
      if (sessionResult != 0)
        _lastError = sessionResult;
    }
    return finish(TlsAsyncStatus::Complete);
  }

  return handleMbedTlsResult(result);
}

TlsAsyncStatus TlsClientSession::pollRead() {
  if (!_transport->carrierUp() || _transport->connected() == 0)
    return fail(TlsErrorTransportDisconnected);

  ExternalRandomProviderGuard randomGuard(_cryptoProvider);
  if (!randomGuard.active())
    return fail(TlsErrorCryptoUnavailable);

  configureInterruptableCryptoBudget();
  const int result = mbedtls_ssl_read(&_ssl, _readBuffer, _requestedLength);
  _lastMbedTlsResult = result;
  if (result > 0) {
    _bytesTransferred = static_cast<size_t>(result);
    return finish(TlsAsyncStatus::Complete);
  }
  if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    _peerCloseNotified = true;
    _handshakeComplete = false;
    _bytesTransferred = 0;
    return finish(TlsAsyncStatus::Complete);
  }

  return handleMbedTlsResult(result);
}

TlsAsyncStatus TlsClientSession::pollWrite() {
  if (!_transport->carrierUp() || _transport->connected() == 0)
    return fail(TlsErrorTransportDisconnected);

  ExternalRandomProviderGuard randomGuard(_cryptoProvider);
  if (!randomGuard.active())
    return fail(TlsErrorCryptoUnavailable);

  configureInterruptableCryptoBudget();
  const int result = mbedtls_ssl_write(&_ssl, _writeBuffer, _requestedLength);
  _lastMbedTlsResult = result;
  if (result > 0) {
    _bytesTransferred = static_cast<size_t>(result);
    return finish(TlsAsyncStatus::Complete);
  }

  return handleMbedTlsResult(result);
}

TlsAsyncStatus TlsClientSession::pollCloseNotify() {
  ExternalRandomProviderGuard randomGuard(_cryptoProvider);
  if (!randomGuard.active())
    return fail(TlsErrorCryptoUnavailable);

  configureInterruptableCryptoBudget();
  const int result = mbedtls_ssl_close_notify(&_ssl);
  _lastMbedTlsResult = result;
  if (result == MBEDTLS_ERR_SSL_WANT_READ ||
      result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return handleMbedTlsResult(result);
  }
  if (result != 0) {
    _lastError = result;
  }

  _handshakeComplete = false;
  _cryptoReady = false;
  _cryptoFailed = false;
  _peerCloseNotified = false;
  resetMbedTlsSession();
  if (_cryptoProvider != nullptr)
    _cryptoProvider->reset();
  _transport->stop();
  return finish(result == 0 ? TlsAsyncStatus::Complete : TlsAsyncStatus::Error);
}

TlsAsyncStatus TlsClientSession::handleMbedTlsResult(int result) {
  if (result == MBEDTLS_ERR_SSL_WANT_READ) {
    _status = TlsAsyncStatus::WantRead;
    return _status;
  }
  if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    _status = TlsAsyncStatus::WantWrite;
    return _status;
  }
#if defined(MBEDTLS_ECP_RESTARTABLE)
  if (result == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
    _status = TlsAsyncStatus::Busy;
    return _status;
  }
#endif
  if (result == MBEDTLS_ERR_NET_CONN_RESET)
    return fail(TlsErrorTransportDisconnected);

  if (_operation == TlsOperation::Handshake)
    _verificationResult = mbedtls_ssl_get_verify_result(&_ssl);

  return fail(result == 0 ? TlsErrorMbedTlsIoFailed : result);
}

TlsAsyncStatus TlsClientSession::finish(TlsAsyncStatus status) {
  _status = status;
  _operation = TlsOperation::None;
  Callback callback = _callback;
  void *callbackContext = _callbackContext;
  _callback = nullptr;
  _callbackContext = nullptr;
  _readBuffer = nullptr;
  _writeBuffer = nullptr;
  _requestedLength = 0;
  if (callback != nullptr)
    callback(status, callbackContext);
  return status;
}

TlsAsyncStatus TlsClientSession::fail(int error) {
  _lastError = error;
  return finish(TlsAsyncStatus::Error);
}

TlsAsyncStatus TlsClientSession::reject(int error) {
  _lastError = error;
  return TlsAsyncStatus::Error;
}

void TlsClientSession::handleCryptoReady(bool success, void *context) {
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || session->_operation != TlsOperation::Handshake)
    return;

  session->_cryptoReady = success;
  session->_cryptoFailed = !success;
}

void TlsClientSession::handleRecordProtectionComplete(bool success,
                                                      void *context) {
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || !session->_recordProtectionBusy)
    return;

  TlsAesGcm128Callback callback = session->_recordCallback;
  void *callbackContext = session->_recordCallbackContext;
  if (success && session->_recordOutputLength != nullptr)
    *session->_recordOutputLength = session->_recordPendingLength;

  session->_recordCallback = nullptr;
  session->_recordCallbackContext = nullptr;
  session->_recordOutputLength = nullptr;
  session->_recordPendingLength = 0;
  mbedtls_platform_zeroize(session->_recordNonce,
                           sizeof(session->_recordNonce));
  mbedtls_platform_zeroize(session->_recordAad, sizeof(session->_recordAad));
  session->_recordProtectionBusy = false;

  if (callback != nullptr)
    callback(success, callbackContext);
}

int TlsClientSession::handleCertificateVerify(void *context,
                                              mbedtls_x509_crt *crt,
                                              int depth, uint32_t *flags) {
  (void)flags;
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || crt == nullptr || depth != 0)
    return 0;

  session->_peerCertificateSha256Available = false;
  mbedtls_platform_zeroize(session->_peerCertificateSha256,
                           sizeof(session->_peerCertificateSha256));
  if (crt->raw.p == nullptr || crt->raw.len == 0)
    return 0;

  size_t hashLength = 0;
  const psa_status_t status = psa_hash_compute(
      PSA_ALG_SHA_256, crt->raw.p, crt->raw.len,
      session->_peerCertificateSha256,
      sizeof(session->_peerCertificateSha256), &hashLength);
  session->_peerCertificateSha256Available =
      status == PSA_SUCCESS &&
      hashLength == sizeof(session->_peerCertificateSha256);
  if (!session->_peerCertificateSha256Available) {
    mbedtls_platform_zeroize(session->_peerCertificateSha256,
                             sizeof(session->_peerCertificateSha256));
  }

  return 0;
}

int TlsClientSession::bioSend(void *context, const unsigned char *buffer,
                              size_t length) {
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || session->_transport == nullptr || buffer == nullptr)
    return MBEDTLS_ERR_NET_SEND_FAILED;
  if (!session->_transport->carrierUp() ||
      session->_transport->connected() == 0)
    return MBEDTLS_ERR_NET_CONN_RESET;

  ++session->_bioSendCalls;
  session->_bioLastSendLength = length;
  const size_t written = session->_transport->write(buffer, length);
  session->_bioLastSendAccepted = written;
  if (written == 0)
    return MBEDTLS_ERR_SSL_WANT_WRITE;

  session->_bioBytesSent += written;
  return static_cast<int>(written);
}

int TlsClientSession::bioRecv(void *context, unsigned char *buffer,
                              size_t length) {
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || session->_transport == nullptr || buffer == nullptr)
    return MBEDTLS_ERR_NET_RECV_FAILED;
  if (!session->_transport->carrierUp() ||
      session->_transport->connected() == 0)
    return MBEDTLS_ERR_NET_CONN_RESET;
  ++session->_bioRecvCalls;
  session->_bioLastRecvLength = length;
  const int available = session->_transport->available();
  session->_bioLastRecvAvailable = available;
  if (available <= 0) {
    ++session->_bioRecvWantReadCount;
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  const int readCount = session->_transport->read(buffer, length);
  if (readCount <= 0) {
    ++session->_bioRecvWantReadCount;
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  session->_bioBytesReceived += static_cast<size_t>(readCount);
  return readCount;
}

} // namespace Crypto
