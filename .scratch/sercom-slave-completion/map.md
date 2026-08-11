# SERCOM slave completion and retirement

Status: active

## Notes

- Governing spec: `spec.md`
- Test harness: adjacent `SimIOFramework_test`
- Production acceptance: adjacent `SimIODevice`

## Decisions so far

- Use three confirmed seams: Framework behavior, paired hardware, and production acceptance.
- Treat DMA completion, SERCOM byte completion, and physical transaction completion as distinct
  until evidence proves equivalence for a particular exit path.
- The cached slave receive descriptor represents readiness, not a physically active transaction.
- A slave transaction becomes physically active only after AMATCH and returns to inactive during
  common retirement.
- A completed slave TX must enter common retirement on RXNACK even when TX DMA is already idle.

## Fog

- Smallest deterministic sequence that produces the missing-interrupt state.
- Exact ownership of retirement after RXNACK when DMA has already become idle.
- How cached receive readiness is represented separately from active physical receive.

## Tickets

1. `issues/01-tighten-feedback-loop.md` — resolved
2. `issues/02-isolate-exit-path-state.md` — resolved
3. `issues/03-implement-and-verify-fix.md` — ready; first candidate failed production acceptance
