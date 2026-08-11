# SERCOM slave completion and retirement

Status: ready-for-agent

## Problem

The asynchronous Wire/SERCOM slave path can intermittently stop servicing transactions after a
completed slave transmission. The production symptom must be reproduced and corrected without
weakening the event-driven DMA contract or leaving the I2C bus, DMA engine, cached transaction
descriptors, or role-switch state inconsistent.

## Observed reproduction

- SAME54J20 acts as I2C master/proxy and reports over USB CDC.
- SAMD21G RedBoard Turbo acts as I2C slave and reports over SEGGER RTT.
- The observed stress sequence failed after 20 short handshakes and a 300-byte combined-read
  precondition.
- Captured SAME54 slave-side state from the failing investigation:
  `STATUS=0x001C`, `INTFLAG=0x00`, `INTENSET=0x87`, `CTRLA=0x12`,
  `CTRLB=0x0100`.
- The software slave TX descriptor was active at 1/1 bytes while DMA was selected and both DMA
  directions were idle.
- Datasheet-backed decoding established `DIR=1` and `RXNACK=1`; no DRDY, AMATCH, PREC, or ERROR
  interrupt flag remained actionable.

## Required seams

### Framework behavioral seam

Exercise the public asynchronous `TwoWire` interface: `beginTransmission()`, callback
`endTransmission()`, chained reads, and slave receive/request callbacks. Tests assert transaction
completion and externally visible behavior, not private implementation structure.

### Hardware seam

Use the paired D21/E54 bench protocol. Observe callback counts, bus progress, raw SERCOM state, DMA
activity, and whether the next addressed or General Call transaction succeeds.

### Production acceptance seam

Replay the original `dI2CProtocol`/Transport transaction shape in `SimIODevice`, including bus
direction, master/slave role transition, transfer size, and STOP/repeated-START behavior.

## State distinctions to validate

- DMA payload transfer complete
- SERCOM byte transfer complete
- Physical I2C transaction complete
- Slave TX awaiting STOP or repeated START
- Cached receive descriptor available but not physically active
- Active slave receive
- Transaction retired and ready for another transaction or role change

## Initial ranked hypotheses

1. A completed slave TX is retired before physical STOP or repeated START.
2. RXNACK handling clears the only actionable flag without arranging later retirement.
3. The cached default receive descriptor is mistaken for an active physical receive.
4. DMA completion and SERCOM bus completion are treated as the same event.
5. A late PREC or AMATCH event is interpreted against the wrong software transaction state.

## Evidence gates

- Native reproduction: FAIL must be recorded before a Framework production edit.
- Focused native verification: PASS required.
- Broader native regression: PASS required.
- Original paired-hardware reproduction: PASS required.
- Production Device reproduction: PASS required before declaring the production fault fixed.

## Non-goals

- No polling or blocking production path.
- No application-level DMA selector.
- No Wire teardown/reconstruction or role switching above Wire/SERCOM.
- No speculative cleanup bundled with the fault fix.
