# SERCOM / WireDMA Refactor Plan (Async + DMA)

This document tracks the planned refactor to move WireDMA functionality into `SERCOM.h` and `Wire.h`, and to make I2C/SPI/UART fully async with DMA where possible. Keep commits small and scoped.

## Goals

- Consolidate SERCOM ownership, bus state, pin-mux constraints, DMA setup, and ISR routing in `SERCOM.h/.cpp`.
- Refactor `Wire.h/.cpp` to expose WireDMA-style async behavior with minimal API breakage.
- Preserve the existing Arduino API surface where possible; introduce a pointer-based `requestFrom` and keep overloads for compatibility.
- After I2C is stable, move SPI and UART to async/DMA using the same SERCOM infrastructure.

## Constraints / Notes

- Wire has stricter pin/pad rules than SPI/UART; keep Wire-specific tables if needed.
- DMA + bus-state tracking should live in SERCOM, not in Wire.
- Keep ISR work minimal; use deferred execution (PendSV) for completion callbacks and queue progression. We can gate this with a compiler variable if s a user needs PendSV for another application.
- SPI already has a DMA path in the core library today; plan should either migrate or wrap it.
- For SimIO we can embed ZeroDMA into core; upstream Adafruit likely requires DMA to remain optional.
- Gate ZeroDMA integration behind `USE_ZERODMA` (mirroring `USE_TINYUSB`) so async works without DMA.
- Avoid large commits; ship in stages with focused diffs.

## Existing Resources

- Pin/pad capability tables and datasheets: `DMA/Wire/docs/` (csv, pdf, txt).
- Python generator for `Wire.inc`: `DMA/Wire/*` (script that generates wire tables).
- Current async implementation: `DMA/WireDMA` (logic to migrate into core).
- SimIO SercomRouter/SercomBus concepts to fold into core SERCOM ownership tracking.
- SercomRouter linker-wrap ISR dispatch: `DMA/SercomRouter` + `DMA/docs/LINKER_WRAPS.md`.

## Pin Mux Generalization

- Reuse the existing pin mux tables (SAMD21 Table 7-1, SAMD51 Table 6-1) as the canonical
  map of pin -> (primary/alt SERCOM, PAD).
- Build protocol-specific filters on top:
  - I2C: keep current Wire tables (PAD0/PAD1 only) using device I2C tables (7-5, 6-8).
  - UART: emit valid TX/RX pad combinations per SERCOM, then map pins to those pads.
  - SPI: emit valid DOPO/DIPO combinations per SERCOM, then map pins to MOSI/MISO/SCK/SS.
- Emit a shared `SERCOM.inc` for common pin/pad knowledge; keep `Wire.inc` if I2C rules remain
  materially stricter than SPI/UART.

## SPI DMA Observations (Current Core)

- SPI already uses ZeroDMA in `libraries/SPI/SPI.cpp` with its own DMA allocation, descriptor pools, and completion flow.
- `dmaAllocate()` preallocates descriptor chains sized to max flash/RAM size, which is a large static footprint even for small transfers.
- DMA completion only toggles a busy flag; there is no unified queue or callback integration.
- SERCOM is used only for data register and DMAC ID lookup, not for DMA ownership or dispatch.

### Opportunities to align with WireDMA-style structure

- Move DMA ownership to SERCOM (channels, descriptors, callbacks), making SPI a client of shared helpers.
- Replace large preallocated descriptor pools with a bounded descriptor pool (per SERCOM or global).
- Use a deferred completion path (PendSV) to run callbacks and advance queues consistently across protocols.
- Keep SPI API behavior intact while routing transfers through SERCOM DMA helpers.

## Target Architecture (High Level)

### SERCOM

- Owns per-SERCOM state:
  - Role (I2C/SPI/UART), bus state, pin mappings, clock source, DMA channels/descriptors.
  - ISR hooks + DMA callbacks.
  - Shared queue / transaction entry storage.
- Exposes:
  - `claim()` / `release()` for protocol ownership and pin validation.
  - `configureClock()/getFreqRef()` for baud/timing.
  - `dmaInit()/dmaStartTx()/dmaStartRx()` (protocol-agnostic helpers).
  - `attachInterrupts()` and routing to protocol handlers.
  - `deferService()` that sets flags and pends PendSV.

### Deferred Execution (PendSV)

- ISR/DMA callbacks only set flags and pend PendSV.
- PendSV handler runs completion callbacks and advances queues.
- Keeps ISR latency low and avoids requiring users to call `checkPending()`.

### Wire

- Public API largely preserved.
- New/updated `requestFrom(addr, uint8_t* dest, size_t len, ...)`.
- Back-compat overloads use an internal RX buffer (likely array, not ring) when no external buffer is provided.
- Async flow and queueing handled by SERCOM-level queue/ISR/DMA.
- `checkPending()` should become internal (PendSV-driven), not user-facing.

### SPI / UART (later phases)

- Use the same SERCOM async queue + DMA.
- Public APIs can remain blocking via “wait for completion” wrappers, but default path uses DMA.
- SPI already uses ZeroDMA in `libraries/SPI`; integrate with SERCOM DMA helpers or wrap existing DMA setup.
- UART currently depends on ISR-driven ring buffers; DMA path must preserve `available()`/`availableForWrite()` semantics and RTS/CTS behavior.

## Task Tracking

Task tracking has moved to [TODO.md](TODO.md). This doc is now kept for design
context, decisions, and background only.

## Progress Log

- 2026-01-27: Created plan and defined phased refactor roadmap.
- 2026-01-27: Updated plan with PendSV deferred service, SPI DMA reality, and core-vs-library DMA considerations.
