#include "TlsClientSession.h"

namespace Crypto {

namespace {
constexpr int TlsErrorInvalidState = -1;
constexpr int TlsErrorInvalidArgument = -2;
constexpr int TlsErrorTransportUnavailable = -3;
constexpr int TlsErrorTransportDisconnected = -4;
} // namespace

TlsClientSession::TlsClientSession()
    : _transport(nullptr), _trustAnchors(nullptr), _trustAnchorLength(0),
      _hostname(nullptr), _status(TlsAsyncStatus::Idle),
      _operation(TlsOperation::None), _callback(nullptr),
      _callbackContext(nullptr), _readBuffer(nullptr), _writeBuffer(nullptr),
      _requestedLength(0), _bytesTransferred(0), _lastError(0),
      _verificationResult(0), _handshakeComplete(false), _cryptoReady(false) {}

bool TlsClientSession::configureTrustAnchors(const uint8_t *data,
                                             size_t length) {
  if (operationActive() || data == nullptr || length == 0)
    return false;

  _trustAnchors = data;
  _trustAnchorLength = length;
  return true;
}

bool TlsClientSession::setHostname(const char *hostname) {
  if (operationActive() || hostname == nullptr || hostname[0] == '\0')
    return false;

  _hostname = hostname;
  return true;
}

bool TlsClientSession::bindTransport(TlsTransport &transport) {
  if (operationActive())
    return false;

  _transport = &transport;
  _handshakeComplete = false;
  _cryptoReady = false;
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

  return _status;
}

bool TlsClientSession::markCryptoReady() {
  if (_handshakeComplete)
    return false;

  _cryptoReady = true;
  return true;
}

TlsAsyncStatus TlsClientSession::readAsync(uint8_t *buffer, size_t length,
                                           Callback callback, void *context) {
  if (!_handshakeComplete)
    return fail(TlsErrorInvalidState);
  if (buffer == nullptr || length == 0)
    return fail(TlsErrorInvalidArgument);
  if (operationActive())
    return reject(TlsErrorInvalidState);
  if (!startOperation(TlsOperation::Read, callback, context))
    return fail(TlsErrorInvalidState);

  _readBuffer = buffer;
  _requestedLength = length;
  return _status;
}

TlsAsyncStatus TlsClientSession::writeAsync(const uint8_t *buffer,
                                            size_t length, Callback callback,
                                            void *context) {
  if (!_handshakeComplete)
    return fail(TlsErrorInvalidState);
  if (buffer == nullptr || length == 0)
    return fail(TlsErrorInvalidArgument);
  if (operationActive())
    return reject(TlsErrorInvalidState);
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
  if (!startOperation(TlsOperation::CloseNotify, callback, context))
    return fail(TlsErrorInvalidState);

  return _status;
}

TlsAsyncStatus TlsClientSession::poll() {
  if (_transport == nullptr)
    return fail(TlsErrorTransportUnavailable);

  switch (_operation) {
  case TlsOperation::Handshake:
    if (!_transport->carrierUp() || _transport->connected() == 0)
      return fail(TlsErrorTransportDisconnected);
    if (!_cryptoReady) {
      _status = TlsAsyncStatus::WaitingCrypto;
      return _status;
    }
    _handshakeComplete = true;
    return finish(TlsAsyncStatus::Complete);
  case TlsOperation::Read: {
    if (!_transport->carrierUp() || _transport->connected() == 0)
      return fail(TlsErrorTransportDisconnected);
    const int available = _transport->available();
    if (available <= 0) {
      _status = TlsAsyncStatus::WantRead;
      return _status;
    }
    const size_t limit =
        static_cast<size_t>(available) < _requestedLength
            ? static_cast<size_t>(available)
            : _requestedLength;
    const int readCount = _transport->read(_readBuffer, limit);
    if (readCount <= 0) {
      _status = TlsAsyncStatus::WantRead;
      return _status;
    }
    _bytesTransferred = static_cast<size_t>(readCount);
    return finish(TlsAsyncStatus::Complete);
  }
  case TlsOperation::Write: {
    if (!_transport->carrierUp() || _transport->connected() == 0)
      return fail(TlsErrorTransportDisconnected);
    const size_t written = _transport->write(_writeBuffer, _requestedLength);
    if (written == 0) {
      _status = TlsAsyncStatus::WantWrite;
      return _status;
    }
    _bytesTransferred = written;
    return finish(TlsAsyncStatus::Complete);
  }
  case TlsOperation::CloseNotify:
    _handshakeComplete = false;
    _cryptoReady = false;
    _transport->stop();
    return finish(TlsAsyncStatus::Complete);
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
}

bool TlsClientSession::configured() const {
  return _transport != nullptr && _trustAnchors != nullptr &&
         _trustAnchorLength != 0 && _hostname != nullptr;
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
  _lastError = 0;
  _status = TlsAsyncStatus::Busy;
  return true;
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

} // namespace Crypto
