# Implement and verify the supported fix

Type: task
Status: ready-for-agent
Blocked by: 02

## Goal

Implement the smallest Framework change supported by the minimized reproduction and validate it
through all three seams.

## Acceptance

- Focused native reproduction passes.
- Relevant broader native CTest suite passes.
- Original D21/E54 hardware stress reproduction passes.
- Production Device transaction reproduction passes.
- Tagged diagnostics and unsupported candidate changes are removed.
- The confirmed completion/retirement rule is recorded in domain documentation or an ADR.

## Comments

- Candidate adds explicit `slaveTransactionActive` state at the SERCOM seam.
- Candidate paired-hardware verification passed the minimized loop 100/100 with both boards
  reflashed.
- Broader paired-hardware stress passed 200/200.
- Production Device acceptance failed: slot-5 motor-position reads returned no remote snapshot and
  slot-5 motor-speed writes returned no acknowledgment while topology remained alive.
- Per the evidence standard, the candidate production hunks were removed. The failing contracts and
  harness remain for the next candidate.
