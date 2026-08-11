# Isolate slave exit-path state

Type: task
Status: resolved
Blocked by: 01

## Goal

Turn the minimized reproduction into focused native contract tests for STOP, repeated START,
RXNACK, PREC, AMATCH, error, DMA-complete, and non-DMA exit paths.

## Acceptance

- Tests use an agreed behavioral seam or a documented internal state-transition seam.
- Each test asserts completion, callback behavior, descriptor retirement, DMA reset, and readiness
  for the next transaction as applicable.
- At least one focused test reproduces the observed fault and is recorded failing against committed
  Framework.
- No production Framework change is made in this ticket.

## Comments

## Answer

Focused native contracts now distinguish the cached slave receive descriptor from a physically
addressed transaction and require completed TX-DMA RXNACK to enter common deferred retirement.

Recorded baseline failures:

- `validate_wire_slave_tx_nack_retirement.py`: RXNACK cleared without retirement.
- `validate_wire_slave_idle_late_prec.py`: idle cached receive vulnerable to late PREC completion.

After the candidate change, the focused CTest group passes 3/3 and all ten Framework-labelled Wire
native tests pass.
