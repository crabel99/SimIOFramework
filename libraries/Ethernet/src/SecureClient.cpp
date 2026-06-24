#include "SecureClient.h"

SecureClient::SecureClient()
    : EthernetClient(), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocketProvider &provider)
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

int SecureClient::connect(IPAddress, uint16_t) {
  _lastError = SecureClientTlsUnavailable;
  return 0;
}

int SecureClient::connect(const char *, uint16_t) {
  _lastError = SecureClientTlsUnavailable;
  return 0;
}

bool SecureClient::tlsAvailable() const { return false; }

int SecureClient::lastError() const { return _lastError; }
