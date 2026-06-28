#include "TlsClientSession.h"

#include <mbedtls/net_sockets.h>
#include <psa/crypto.h>
#include <string.h>

namespace Crypto {

namespace MbedTlsPort {
bool setExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
void clearExternalRandomProvider(Crypto::TlsCryptoProvider *provider);
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
constexpr size_t MaxAlpnProtocols = 8;

constexpr int StrictTls12CipherSuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0};

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
      _policy(),
      _status(TlsAsyncStatus::Idle), _operation(TlsOperation::None),
      _callback(nullptr),
      _callbackContext(nullptr), _readBuffer(nullptr), _writeBuffer(nullptr),
      _requestedLength(0), _bytesTransferred(0),
      _operationPollLimit(DefaultTlsOperationPollLimit),
      _operationPollCount(0), _lastError(0), _verificationResult(0),
      _handshakeComplete(false), _cryptoReady(false), _cryptoFailed(false),
      _tlsConfigured(false), _peerCloseNotified(false),
      _clientIdentityConfigured(false) {
  mbedtls_ssl_init(&_ssl);
  mbedtls_ssl_config_init(&_sslConfig);
  mbedtls_x509_crt_init(&_caChain);
  mbedtls_x509_crt_init(&_clientCertificate);
  mbedtls_pk_init(&_clientKey);
}

TlsClientSession::~TlsClientSession() {
  mbedtls_ssl_free(&_ssl);
  mbedtls_ssl_config_free(&_sslConfig);
  mbedtls_x509_crt_free(&_caChain);
  mbedtls_x509_crt_free(&_clientCertificate);
  mbedtls_pk_free(&_clientKey);
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
  if (operationActive()) {
    if (_operationPollCount >= _operationPollLimit)
      return fail(TlsErrorOperationDeadlineExceeded);
    ++_operationPollCount;
  }

  switch (_operation) {
  case TlsOperation::Handshake:
    if (!_transport->carrierUp() || _transport->connected() == 0)
      return fail(TlsErrorTransportDisconnected);
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
    return pollRead();
  case TlsOperation::Write:
    return pollWrite();
  case TlsOperation::CloseNotify:
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
  _readBuffer = nullptr;
  _writeBuffer = nullptr;
  _requestedLength = 0;
  _bytesTransferred = 0;
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
         _cryptoProvider != nullptr;
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
  _status = TlsAsyncStatus::Busy;
  if (operation == TlsOperation::Handshake)
    _peerCloseNotified = false;
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
      _hostname == nullptr)
    return false;

  resetMbedTlsSession();

  int result = mbedtls_ssl_config_defaults(
      &_sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT);
  if (result != 0) {
    _lastError = result;
    return false;
  }

  mbedtls_ssl_conf_authmode(&_sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_min_tls_version(&_sslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&_sslConfig, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_ciphersuites(&_sslConfig, StrictTls12CipherSuites);
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
}

TlsAsyncStatus TlsClientSession::pollHandshake() {
  ExternalRandomProviderGuard randomGuard(_cryptoProvider);
  if (!randomGuard.active())
    return fail(TlsErrorCryptoUnavailable);

  const int result = mbedtls_ssl_handshake(&_ssl);
  if (result == 0) {
    _verificationResult = mbedtls_ssl_get_verify_result(&_ssl);
    _handshakeComplete = true;
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

  const int result = mbedtls_ssl_read(&_ssl, _readBuffer, _requestedLength);
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

  const int result = mbedtls_ssl_write(&_ssl, _writeBuffer, _requestedLength);
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

  const int result = mbedtls_ssl_close_notify(&_ssl);
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
  if (result == MBEDTLS_ERR_NET_CONN_RESET)
    return fail(TlsErrorTransportDisconnected);

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

int TlsClientSession::bioSend(void *context, const unsigned char *buffer,
                              size_t length) {
  auto *session = static_cast<TlsClientSession *>(context);
  if (session == nullptr || session->_transport == nullptr || buffer == nullptr)
    return MBEDTLS_ERR_NET_SEND_FAILED;
  if (!session->_transport->carrierUp() ||
      session->_transport->connected() == 0)
    return MBEDTLS_ERR_NET_CONN_RESET;

  const size_t written = session->_transport->write(buffer, length);
  if (written == 0)
    return MBEDTLS_ERR_SSL_WANT_WRITE;

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
  if (session->_transport->available() <= 0)
    return MBEDTLS_ERR_SSL_WANT_READ;

  const int readCount = session->_transport->read(buffer, length);
  if (readCount <= 0)
    return MBEDTLS_ERR_SSL_WANT_READ;

  return readCount;
}

} // namespace Crypto
