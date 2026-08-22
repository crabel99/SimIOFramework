# SimIOFramework TODO

Single source of truth for remaining work in the framework library. Design and
background live in [SERCOM_REFACTOR.md](SERCOM_REFACTOR.md).

## Active Focus

- [ ] Fix the last async Wire bug and verify with hardware tests.

## Wire Async Backlog

- [ ] Implement pointer-based `requestFrom()` overload.
- [ ] Preserve existing overloads with internal RX buffer fallback.
- [ ] Document external buffer lifetime requirements.
- [ ] Keep blocking semantics intact via sync wrappers or internal waits.
- [ ] Test DMA and non-DMA paths on the same hardware.
- [ ] Generalize Wire pin tables into shared SERCOM tables (if still needed).
- [ ] Create `SERCOM.inc` from the generator or a minimal duplicate.

## Hs-Mode (High-Speed) TODOs

- [x] Define the Hs-mode transaction constraints (DMA-only, STOP-only) in Wire docs.
- [ ] Add zero-length DMA support for the Hs-mode master-code phase.
- [ ] Validate HSBAUD/HSBAUDLOW and BAUD/BAUDLOW configuration paths. (see 28.10.3)
- [x] Ensure QCEN is never enabled when SCLSM=1 (errata constraint).
- [ ] Add hardware validation tests for Hs-mode timing and stop behavior.
- [ ] Hs-mode Slave mode has arbitrary length DMA support, or it is alluded to in the docs.

## SPI Refactor (Deferred)

- [ ] Move SPI transfers onto SERCOM queue + DMA helpers.
- [ ] Add async completion callbacks + PendSV completion path.
- [ ] Provide a blocking wrapper if needed.
- [ ] Replace large static descriptor pools with bounded pools.

## UART Refactor (Deferred)

- [ ] Add DMA-backed TX/RX with async callbacks.
- [ ] Preserve `available()` and flow control semantics.
- [ ] Minimize ISR work to flags and deferred callbacks.

## Open Questions

- [ ] Shared queue per SERCOM or per-protocol queue?
- [ ] Tagged union entry type vs per-protocol entries?
- [ ] Keep `checkPending()` public or make PendSV-only?
- [ ] DMA abstraction in core vs direct ZeroDMA linkage?
- [ ] Figure out how to implement hardware CRC for DMA transactions
