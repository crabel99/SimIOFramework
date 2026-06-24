#include "SecureClient.h"

SecureClient::SecureClient()
    : EthernetClient(), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(TransportProvider &provider)
    : EthernetClient(provider), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(SecureClient &&other)
    : EthernetClient(static_cast<EthernetClient &&>(other)),
      _lastError(other._lastError) {
  other._lastError = SecureClientNoError;
}

SecureClient &SecureClient::operator=(SecureClient &&other) {
  if (this == &other)
    return *this;

  EthernetClient::operator=(static_cast<EthernetClient &&>(other));
  _lastError = other._lastError;
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
  TransportProvider *provider = transportProvider();
  return provider != nullptr && provider->tlsAvailable();
}

int SecureClient::lastError() const { return _lastError; }

EthernetSocket *SecureClient::acquireProviderSocket() {
  TransportProvider *provider = transportProvider();
  if (provider == nullptr)
    return nullptr;

  return provider->acquireSecureClientSocket();
}
