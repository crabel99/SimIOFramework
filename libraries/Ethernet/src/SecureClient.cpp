#include "SecureClient.h"

SecureClient::SecureClient()
    : EthernetClient(), _lastError(SecureClientNoError) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _lastError(SecureClientNoError) {}

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
