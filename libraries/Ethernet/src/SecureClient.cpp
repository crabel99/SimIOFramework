#include "SecureClient.h"

SecureClient::SecureClient()
    : EthernetClient(), _secureProvider(nullptr),
      _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _secureProvider(nullptr),
      _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocketProvider &provider)
    : EthernetClient(provider), _secureProvider(nullptr),
      _lastError(SecureClientNoError) {}

SecureClient::SecureClient(SecureClientProvider &provider)
    : EthernetClient(provider), _secureProvider(&provider),
      _lastError(SecureClientNoError) {}

SecureClient::SecureClient(SecureClient &&other)
    : EthernetClient(static_cast<EthernetClient &&>(other)),
      _secureProvider(other._secureProvider), _lastError(other._lastError) {
  other._secureProvider = nullptr;
  other._lastError = SecureClientNoError;
}

SecureClient &SecureClient::operator=(SecureClient &&other) {
  if (this == &other)
    return *this;

  EthernetClient::operator=(static_cast<EthernetClient &&>(other));
  _secureProvider = other._secureProvider;
  _lastError = other._lastError;
  other._secureProvider = nullptr;
  other._lastError = SecureClientNoError;
  return *this;
}

int SecureClient::connect(IPAddress ip, uint16_t port) {
  if (!tlsAvailable()) {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }

  const int result = EthernetClient::connect(ip, port);
  _lastError = result != 0 ? SecureClientNoError : SecureClientConnectFailed;
  return result;
}

int SecureClient::connect(const char *host, uint16_t port) {
  if (!tlsAvailable()) {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }

  const int result = EthernetClient::connect(host, port);
  _lastError = result != 0 ? SecureClientNoError : SecureClientConnectFailed;
  return result;
}

bool SecureClient::tlsAvailable() const {
  return _secureProvider != nullptr && _secureProvider->tlsAvailable();
}

int SecureClient::lastError() const { return _lastError; }
