# Tighten the paired-hardware feedback loop

Type: task
Status: resolved

## Goal

Produce one unattended command in `SimIOFramework_test` that reliably catches the exact
post-slave-TX stuck condition and records enough state to distinguish the ranked hypotheses.

## Acceptance

- Drives the real D21/E54 transaction sequence.
- Returns nonzero on the exact failure.
- Records the failing iteration and recent transaction history.
- Captures raw SERCOM and DMA state on both targets.
- Reproduction rate and runtime are recorded.
- The sequence is minimized one variable at a time.

## Comments

## Answer

The minimized, unattended reproduction is:

```text
.venv/bin/python scripts/wire_bench_cdc.py --reproduce-slave-tx-stall --timeout 3
```

The original 300-byte response is not load-bearing. A 5-byte combined-read response followed by
the General Call reversal reproduces the same stall. The 4-byte case is excluded because it aliases
the protocol's 4-byte command packet in the current checker.

Baseline results reproduced the exact fault at iterations 4 and 16 in separate runs. Failure output
includes bounded transaction history and raw SAME54 SERCOM/DMA state.
