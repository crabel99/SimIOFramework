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
  WireBusError,
  DmaRxSuspend,
  DmaRxArm,
  DeferReceiveComplete,
  WireArbitrationLost,
  WireArbitrationContinuedAsOwner,
  WireArbitrationRestart,
  WireBusErrorRetryQueued,
  WireBusErrorRecoveryWait,
  WireBusErrorPeripheralReset,
  WireBusErrorTerminal,
  SercomSetMasterEntry,
  SercomSetMasterDisabled,
  SercomSetMasterEnabled,
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
// Bench-only event-shaping hook. The next real slave AMATCH is serviced as if
// the preceding STOP's PREC flag were coasserted with it.
extern volatile bool gSercomWireInjectPrecWithNextAmatch;
extern volatile uint32_t gSercomWireInjectedPrecAmatchCount;
extern volatile uint32_t gSercomWireArbitrationLostCount;
extern volatile uint32_t gSercomWireArbitrationRetryCount;
extern volatile uint32_t gSercomWireArbitrationContinuedOwnerCount;

struct SercomWireDmaDrdySnapshot {
  uint32_t count;
  uint32_t reason;
  uint32_t timestampUs;
  uint32_t status;
  uint32_t intflag;
  uint32_t intenset;
  uint32_t address;
  uint32_t ctrlb;
  uint32_t ctrla;
  uint32_t syncbusy;
  uint32_t baud;
  uint32_t data;
  uint32_t nvicEnabled;
  uint32_t nvicPending;
  uint32_t nvicActive;
  uint32_t scbIcsr;
  uint32_t portIn0;
  uint32_t portIn1;
  uint32_t pendch;
  uint32_t busych;
  uint32_t active;
  uint32_t ctrl;
  uint32_t ahbmask;
  uint32_t chctrla;
  uint16_t descriptorBtcnt;
  uint16_t writebackBtcnt;
  uint16_t descriptorBtctrl;
  uint16_t writebackBtctrl;
  uint32_t dmaGeneration;
  uint32_t suspendRequestGeneration;
  uint32_t suspendCallbackGeneration;
  uint32_t abortGeneration;
  uint16_t txnLength;
  uint16_t txnIndex;
  uint16_t completionAddress;
  uint16_t completionRequestedLength;
  uint16_t completionTransferredLength;
  uint8_t channel;
  uint8_t chctrlb;
  uint8_t chprilvl;
  uint8_t chintflag;
  uint8_t chstatus;
  int8_t jobStatus;
  uint8_t dmaRxActive;
  uint8_t suspendPending;
  uint8_t role;
  uint8_t completionError;
  uint8_t completionRole;
  uint8_t completionBus;
  uint8_t completionDelivery;
  uint8_t completionRead;
  uint8_t nvicIrqBase;
  uint8_t primask;
  uint8_t ipsr;
  uint8_t control;
};

extern volatile SercomWireDmaDrdySnapshot gSercomWireDmaDrdySnapshot;

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
