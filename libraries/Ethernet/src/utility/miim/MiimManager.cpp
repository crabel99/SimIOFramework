#include "MiimManager.h"

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <utility/phy/PhyRegisters.h>

EthernetMiimManager::EthernetMiimManager()
    : _queue{}, _activeOperation{}, _phyAddress(0), _queueReadIndex(0),
      _queueWriteIndex(0), _queueCount(0), _operationActive(false) {}

void EthernetMiimManager::setPhyAddress(uint8_t address) {
  _phyAddress = address;
}

uint8_t EthernetMiimManager::phyAddress() const { return _phyAddress; }

void EthernetMiimManager::reset() {
  _queueReadIndex = 0;
  _queueWriteIndex = 0;
  _queueCount = 0;
  _operationActive = false;
  _activeOperation = {};

  for (uint8_t i = 0; i < QueueDepth; ++i)
    _queue[i] = {};
}

bool EthernetMiimManager::queueRead(uint8_t registerAddress, Callback callback,
                                    void *context) {
  return queueOperation(OperationRead, registerAddress, 0, callback, context);
}

bool EthernetMiimManager::queueWrite(uint8_t registerAddress, uint16_t value,
                                     Callback callback, void *context) {
  return queueOperation(OperationWrite, registerAddress, value, callback,
                        context);
}

bool EthernetMiimManager::service() {
  bool progressed = false;

  if (_operationActive) {
    if (!completeActiveOperation())
      return false;

    progressed = true;
  }

  if (!_operationActive && _queueCount > 0)
    progressed = startNextOperation() || progressed;

  return progressed;
}

bool EthernetMiimManager::busy() const {
  return _operationActive || _queueCount > 0;
}

bool EthernetMiimManager::full() const { return _queueCount >= QueueDepth; }

bool EthernetMiimManager::queueOperation(OperationType type,
                                         uint8_t registerAddress,
                                         uint16_t writeValue,
                                         Callback callback, void *context) {
  if (registerAddress >= PHY_REGISTERS || full())
    return false;

  Operation &operation = _queue[_queueWriteIndex];
  operation.type = type;
  operation.registerAddress = registerAddress;
  operation.writeValue = writeValue;
  operation.callback = callback;
  operation.context = context;
  operation.active = true;
  _queueWriteIndex = nextQueueIndex(_queueWriteIndex);
  ++_queueCount;
  return true;
}

bool EthernetMiimManager::startNextOperation() {
  if (_operationActive || _queueCount == 0)
    return false;

  Operation operation = _queue[_queueReadIndex];
  if (!operation.active)
    return false;

  bool started = false;
  if (operation.type == OperationRead) {
    started = gmac::mdioReadStart(_phyAddress, operation.registerAddress);
  } else {
    started = gmac::mdioWriteStart(_phyAddress, operation.registerAddress,
                                   operation.writeValue);
  }

  if (!started)
    return false;

  _activeOperation = operation;
  _queue[_queueReadIndex].active = false;
  _queueReadIndex = nextQueueIndex(_queueReadIndex);
  --_queueCount;
  _operationActive = true;
  return true;
}

bool EthernetMiimManager::completeActiveOperation() {
  if (!_operationActive)
    return false;

  bool success = false;
  uint16_t value = 0;
  if (_activeOperation.type == OperationRead) {
    success = gmac::mdioReadComplete(&value);
  } else if (gmac::isManagementIdle()) {
    success = true;
    value = _activeOperation.writeValue;
  }

  if (!success)
    return false;

  Callback callback = _activeOperation.callback;
  void *context = _activeOperation.context;
  _activeOperation.active = false;
  _operationActive = false;

  if (callback != nullptr)
    callback(success, value, context);

  return true;
}

uint8_t EthernetMiimManager::nextQueueIndex(uint8_t index) {
  ++index;
  if (index >= QueueDepth)
    return 0;

  return index;
}
#endif /* ETHERNET_HARDWARE_AVAILABLE */
