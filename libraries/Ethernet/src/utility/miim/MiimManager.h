#pragma once

#include <GMAC.h>
#include <stdint.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE
class EthernetMiimManager {
public:
  using Callback = void (*)(bool success, uint16_t value, void *context);

  EthernetMiimManager();

  void setPhyAddress(uint8_t address);
  uint8_t phyAddress() const;
  void reset();
  bool queueRead(uint8_t registerAddress, Callback callback,
                 void *context = nullptr);
  bool queueWrite(uint8_t registerAddress, uint16_t value,
                  Callback callback = nullptr, void *context = nullptr);
  bool service();
  bool busy() const;
  bool full() const;

private:
  enum OperationType : uint8_t {
    OperationRead,
    OperationWrite,
  };

  struct Operation {
    OperationType type;
    uint8_t registerAddress;
    uint16_t writeValue;
    Callback callback;
    void *context;
    bool active;
  };

  static constexpr uint8_t QueueDepth = 4;

  Operation _queue[QueueDepth];
  Operation _activeOperation;
  uint8_t _phyAddress;
  uint8_t _queueReadIndex;
  uint8_t _queueWriteIndex;
  uint8_t _queueCount;
  bool _operationActive;

  bool queueOperation(OperationType type, uint8_t registerAddress,
                      uint16_t writeValue, Callback callback, void *context);
  bool startNextOperation();
  bool completeActiveOperation();
  static uint8_t nextQueueIndex(uint8_t index);
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
