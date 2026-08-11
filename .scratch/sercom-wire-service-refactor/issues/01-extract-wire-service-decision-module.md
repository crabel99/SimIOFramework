# Extract the Wire service decision module

Type: refactor
Status: pending

## Problem

`TwoWire::onService()` currently combines interrupt snapshot decoding, guarded
test injection, slave `PREC`/`AMATCH` retirement, arbitration recovery, BUSERR
replay classification, DMA teardown, and normal byte servicing. The ordering is
correctness-critical but difficult to review as one function.

## Intended seam

Introduce a small internal decision interface that accepts an immutable event
snapshot and returns an action. Keep register mutation and action execution in
the existing SERCOM/Wire implementation. Avoid adding public Wire methods.

Suggested internal responsibilities:

- classify master terminal errors versus replayable BUSERR;
- classify ARBLOST continuation versus queue-head restart;
- classify slave `PREC`, `AMATCH`, and coasserted boundary events;
- make action precedence explicit and exhaustively testable.

## Acceptance criteria

- Existing hardware behavior and public Wire interface remain unchanged.
- `TwoWire::onService()` becomes snapshot, decide, execute orchestration.
- Production and native tests use the same decision implementation.
- Ordering between flag capture, W1C operations, DMA teardown, and deferred
  completion is documented at the internal interface.
- Existing CTest and three-device I2C matrices continue to pass.

## Comments

- Consider a dedicated SERCOM source directory separately; do not combine the
  physical file move with the behavioral refactor.
