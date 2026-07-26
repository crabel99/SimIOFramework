#ifndef SERCOM_WIRE_TEST_POINTS_H
#define SERCOM_WIRE_TEST_POINTS_H

#include <stdint.h>

#if defined(SERCOM_WIRE_TEST_POINTS)

enum class SercomWireTestEvent : uint8_t {
  TransportReadAccepted = 1,
  TransportReadRetry,
  TransportReadComplete,
  Di2cWriteReadStart,
  Di2cWritePhaseComplete,
  Di2cReadPhasePrepared,
  Di2cTransactionComplete,
  WireServiceEntry,
  WireAmatch,
  WirePrec,
  SercomStartEntry,
  SercomSlaveStart,
  SercomMasterAddress,
  DmaTxComplete,
  DmaRxComplete,
  DmaError,
  StopEntry,
  StopSlaveComplete,
  StopBusReleaseTimeout,
  StopMasterComplete,
};

struct SercomWireTestPoint {
  uint32_t sequence;
  uint32_t timestampUs;
  uint32_t status;
  uint32_t intflag;
  uint32_t intenset;
  uint32_t address;
  uint32_t ctrlb;
  uint16_t txnLength;
  uint16_t txnIndex;
  int16_t result;
  uint8_t event;
  uint8_t sercomIndex;
  uint8_t role;
  uint8_t dma;
};

extern volatile SercomWireTestPoint gSercomWireTestPoints[64];
extern volatile uint32_t gSercomWireTestPointWrite;
extern volatile bool gSercomWireTestPointCaptureActive;
extern volatile bool gSercomWireTestPointFrozen;

void recordSercomWireTestPoint(SercomWireTestEvent event, int result = 0,
                               uint8_t sercomIndex = 0xFFu,
                               uint8_t role = 0u, uint8_t dma = 0u,
                               uint32_t status = 0u, uint32_t intflag = 0u,
                               uint32_t intenset = 0u, uint32_t address = 0u,
                               uint32_t ctrlb = 0u, uint16_t txnLength = 0u,
                               uint16_t txnIndex = 0u);

#else

enum class SercomWireTestEvent : uint8_t;

#endif

#endif
