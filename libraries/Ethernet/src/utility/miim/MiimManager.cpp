#include "MiimManager.h"

/**
 * @file MiimManager.cpp
 * @brief Implementation of the bounded SAME5x GMAC MDIO/MIIM queue.
 *
 * This file binds the abstract MIIM operation contract in `MiimManager.h` to
 * the GMAC non-blocking MDIO start/complete primitives. It intentionally keeps
 * PHY interpretation out of the queue: register values are transported and
 * retained, but decoded by the PHY or Ethernet coordinator layers.
 */

#ifdef ETHERNET_HARDWARE_AVAILABLE
#include <utility/phy/PhyRegisters.h>

MiimManager::MiimManager()
    : _operations{}, _queue{}, _phyAddress(0), _queueReadIndex(0),
      _queueWriteIndex(0), _queueCount(0), _activeOperationIndex(QueueDepth),
      _activeServicePasses(0), _nextHandle(1) {}

bool MiimManager::setup(const Setup &setup) {
  return gmac::beginManagement(setup.hostClockHz, setup.maxMdcHz);
}

void MiimManager::setPhyAddress(uint8_t address) {
  if (address <= MaxPhyAddress)
    _phyAddress = address;
}

uint8_t MiimManager::phyAddress() const { return _phyAddress; }

void MiimManager::reset() {
  _queueReadIndex = 0;
  _queueWriteIndex = 0;
  _queueCount = 0;
  _activeOperationIndex = QueueDepth;
  _activeServicePasses = 0;

  for (uint8_t i = 0; i < QueueDepth; ++i) {
    _queue[i] = QueueDepth;
    _operations[i] = {};
    _operations[i].state = OperationFree;
  }
}

MiimManager::OperationHandle
MiimManager::read(uint8_t phyAddress, uint8_t registerAddress,
                  OperationCallback callback, void *context,
                  OperationResult *result) {
  return queueOperation(OperationRead, phyAddress, registerAddress, phyAddress,
                        0, callback, context, result);
}

MiimManager::OperationHandle
MiimManager::write(uint8_t phyAddress, uint8_t registerAddress, uint16_t value,
                   OperationCallback callback, void *context,
                   OperationResult *result) {
  return queueOperation(OperationWrite, phyAddress, registerAddress, phyAddress,
                        value, callback, context, result);
}

MiimManager::OperationHandle
MiimManager::scan(uint8_t registerAddress, uint8_t firstPhyAddress,
                  uint8_t lastPhyAddress, OperationCallback callback,
                  void *context, OperationResult *result) {
  if (lastPhyAddress < firstPhyAddress) {
    if (result != nullptr)
      *result = ResultInvalidAddress;
    return InvalidOperationHandle;
  }

  return queueOperation(OperationScan, firstPhyAddress, registerAddress,
                        lastPhyAddress, 0, callback, context, result);
}

MiimManager::OperationResult
MiimManager::operationResult(OperationHandle handle, uint16_t *value) const {
  const int8_t index = findOperation(handle);
  if (index < 0)
    return ResultInvalidHandle;

  const Operation &operation = _operations[index];
  if (operation.state == OperationQueued || operation.state == OperationActive)
    return ResultPending;

  if (operation.state != OperationComplete)
    return ResultInvalidHandle;

  if (value != nullptr)
    *value = operation.resultValue;

  return operation.result;
}

MiimManager::OperationResult
MiimManager::operationPhyAddress(OperationHandle handle,
                                 uint8_t *phyAddress) const {
  const int8_t index = findOperation(handle);
  if (index < 0)
    return ResultInvalidHandle;

  if (phyAddress != nullptr)
    *phyAddress = _operations[index].phyAddress;

  return _operations[index].result;
}

MiimManager::OperationResult MiimManager::release(OperationHandle handle) {
  const int8_t index = findOperation(handle);
  if (index < 0)
    return ResultInvalidHandle;

  Operation &operation = _operations[index];
  if (operation.state == OperationQueued || operation.state == OperationActive)
    return ResultBusy;

  releaseOperation(operation);
  return ResultOk;
}

MiimManager::OperationResult MiimManager::abort(OperationHandle handle) {
  const int8_t index = findOperation(handle);
  if (index < 0)
    return ResultInvalidHandle;

  Operation &operation = _operations[index];
  if (operation.state == OperationComplete) {
    releaseOperation(operation);
    return ResultOk;
  }

  if (operation.state == OperationActive)
    return ResultBusy;

  completeOperation(operation, ResultAborted, 0);
  return ResultOk;
}

bool MiimManager::service() {
  bool progressed = false;

  // Finish at most one active hardware transaction, then start at most one
  // queued transaction. This keeps each service pass bounded.
  if (_activeOperationIndex < QueueDepth) {
    if (completeActiveOperation())
      progressed = true;
    else
      return false;
  }

  if (_activeOperationIndex >= QueueDepth && _queueCount > 0)
    progressed = startNextOperation() || progressed;

  return progressed;
}

bool MiimManager::busy() const {
  return _activeOperationIndex < QueueDepth || _queueCount > 0;
}

bool MiimManager::full() const { return allocateOperation() < 0; }

MiimManager::OperationHandle
MiimManager::queueOperation(OperationType type, uint8_t phyAddress,
                            uint8_t registerAddress, uint8_t scanEndAddress,
                            uint16_t writeValue, OperationCallback callback,
                            void *context, OperationResult *result) {
  const OperationResult validation = validateAddress(phyAddress, registerAddress);
  if (validation != ResultOk) {
    if (result != nullptr)
      *result = validation;
    return InvalidOperationHandle;
  }

  if (type == OperationScan && scanEndAddress > MaxPhyAddress) {
    if (result != nullptr)
      *result = ResultInvalidAddress;
    return InvalidOperationHandle;
  }

  const int8_t operationIndex = allocateOperation();
  if (operationIndex < 0 || !queueOperationIndex(operationIndex)) {
    if (result != nullptr)
      *result = ResultBusy;
    return InvalidOperationHandle;
  }

  Operation &operation = _operations[operationIndex];
  operation.handle = _nextHandle++;
  if (operation.handle == InvalidOperationHandle)
    operation.handle = _nextHandle++;

  operation.type = type;
  operation.state = OperationQueued;
  operation.phyAddress = phyAddress;
  operation.registerAddress = registerAddress;
  operation.scanEndAddress = scanEndAddress;
  operation.writeValue = writeValue;
  operation.resultValue = 0;
  operation.result = ResultPending;
  operation.callback = callback;
  operation.context = context;

  if (result != nullptr)
    *result = ResultPending;

  return operation.handle;
}

MiimManager::OperationResult
MiimManager::validateAddress(uint8_t phyAddress,
                             uint8_t registerAddress) const {
  if (phyAddress > MaxPhyAddress)
    return ResultInvalidAddress;

  if (registerAddress >= PHY_REGISTERS)
    return ResultInvalidRegister;

  return ResultOk;
}

int8_t MiimManager::findOperation(OperationHandle handle) const {
  if (handle == InvalidOperationHandle)
    return -1;

  for (uint8_t i = 0; i < QueueDepth; ++i) {
    if (_operations[i].state != OperationFree &&
        _operations[i].handle == handle)
      return static_cast<int8_t>(i);
  }

  return -1;
}

int8_t MiimManager::allocateOperation() const {
  for (uint8_t i = 0; i < QueueDepth; ++i) {
    if (_operations[i].state == OperationFree)
      return static_cast<int8_t>(i);
  }

  return -1;
}

bool MiimManager::queueOperationIndex(uint8_t operationIndex) {
  if (operationIndex >= QueueDepth || _queueCount >= QueueDepth)
    return false;

  _queue[_queueWriteIndex] = operationIndex;
  _queueWriteIndex = nextQueueIndex(_queueWriteIndex);
  ++_queueCount;
  return true;
}

bool MiimManager::startNextOperation() {
  if (_activeOperationIndex < QueueDepth || _queueCount == 0)
    return false;

  const uint8_t operationIndex = _queue[_queueReadIndex];
  if (operationIndex >= QueueDepth)
    return false;

  Operation &operation = _operations[operationIndex];
  if (operation.state != OperationQueued) {
    _queue[_queueReadIndex] = QueueDepth;
    _queueReadIndex = nextQueueIndex(_queueReadIndex);
    --_queueCount;
    return true;
  }

  if (!startOperation(operation))
    return false;

  _queue[_queueReadIndex] = QueueDepth;
  _queueReadIndex = nextQueueIndex(_queueReadIndex);
  --_queueCount;
  _activeOperationIndex = operationIndex;
  _activeServicePasses = 0;
  operation.state = OperationActive;
  return true;
}

bool MiimManager::startOperation(Operation &operation) {
  if (operation.type == OperationWrite) {
    return gmac::mdioWriteStart(operation.phyAddress,
                                operation.registerAddress,
                                operation.writeValue);
  }

  return gmac::mdioReadStart(operation.phyAddress, operation.registerAddress);
}

bool MiimManager::completeActiveOperation() {
  if (_activeOperationIndex >= QueueDepth)
    return false;

  Operation &operation = _operations[_activeOperationIndex];
  if (++_activeServicePasses > OperationTimeoutServicePasses) {
    completeOperation(operation, ResultTimeout, 0);
    _activeOperationIndex = QueueDepth;
    return true;
  }

  if (operation.type == OperationWrite) {
    if (!gmac::isManagementIdle())
      return false;

    completeOperation(operation, ResultOk, operation.writeValue);
    _activeOperationIndex = QueueDepth;
    return true;
  }

  uint16_t value = 0;
  if (!gmac::mdioReadComplete(&value))
    return false;

  if (operation.type == OperationScan && !scanValueIsValid(value))
    return continueScan(operation);

  completeOperation(operation, ResultOk, value);
  _activeOperationIndex = QueueDepth;
  return true;
}

bool MiimManager::continueScan(Operation &operation) {
  if (operation.phyAddress >= operation.scanEndAddress) {
    completeOperation(operation, ResultNotFound, 0);
    _activeOperationIndex = QueueDepth;
    return true;
  }

  ++operation.phyAddress;
  if (!startOperation(operation))
    return false;

  _activeServicePasses = 0;
  return true;
}

void MiimManager::completeOperation(Operation &operation,
                                    OperationResult result, uint16_t value) {
  operation.result = result;
  operation.resultValue = value;
  operation.state = OperationComplete;

  if (operation.callback != nullptr)
    operation.callback(operation.handle, result, value, operation.context);
}

void MiimManager::releaseOperation(Operation &operation) {
  operation = {};
  operation.state = OperationFree;
}

bool MiimManager::scanValueIsValid(uint16_t value) const {
  return value != 0x0000u && value != 0xFFFFu;
}

uint8_t MiimManager::nextQueueIndex(uint8_t index) {
  ++index;
  if (index >= QueueDepth)
    return 0;

  return index;
}
#endif /* ETHERNET_HARDWARE_AVAILABLE */
