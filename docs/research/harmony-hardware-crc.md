# Harmony hardware CRC on SAM D21 and SAM D5x/E5x

## Question and sources

Research date: 2026-09-27. How does Microchip Harmony 3 implement hardware CRC
on the SAM D21 and SAM E54, and what can the Framework reuse? This is source
and datasheet research, not a hardware validation or a protocol CRC selection.

Primary source revisions:

- Harmony CSP templates: [`e846e68aa557b450d9fff03f00b000c50fb97f63`](https://github.com/Microchip-MPLAB-Harmony/csp/tree/e846e68aa557b450d9fff03f00b000c50fb97f63).
- SAM D21 examples: [`9331e79cf2937d2b3166813c6d2886b2481162e3`](https://github.com/Microchip-MPLAB-Harmony/csp_apps_sam_d21_da1/tree/9331e79cf2937d2b3166813c6d2886b2481162e3).
- SAM E54 examples: [`4a38194d468e94d4710c31bbfd67fbfe9f5d2096`](https://github.com/Microchip-MPLAB-Harmony/csp_apps_sam_d5x_e5x/tree/4a38194d468e94d4710c31bbfd67fbfe9f5d2096).
- Locally archived Microchip [D21 datasheet, DS40001882K (2025)][d21],
  [D5x/E5x datasheet, DS60001507M (2024)][e54],
  [D21 errata, DS80000760M (2025)][d21-errata], and
  [D5x/E5x errata, DS80000748T (2023)][e54-errata]. Section numbers below refer
  to these archived editions. The parsed local datasheets were read before
  interpreting registers; later online revisions may differ.

Downloaded source excerpts are under `build/harmony-crc-research/`. Framework
inspection used `5cec3c8817048fe598677d7349c5c55218fd988f` and its ZeroDMA
submodule `9215aa0848a092960fc1ba4e02cb4989af2f46e6`.

## Findings

Harmony provides two distinct routes on these chips: CRC integrated into the
**DMAC peripheral library**, and a **DSU peripheral library** for memory CRC32.
The DMAC route supports both CPU-fed data and a selected DMA channel. Its
asynchronous route uses ordinary DMA completion/error handling. The DSU wrapper
is blocking. Neither supplies a complete queued CRC service for this
Framework's SPI, Serial, and Wire transactions. [D21 DMAC implementation][d21-dmac],
[E54 DMAC implementation][e54-dmac], [D21 DSU implementation][d21-dsu],
[E54 DSU implementation][e54-dsu].

| Property | SAM D21 DMAC | SAM D5x/E5x DMAC | DSU on both families |
| --- | --- | --- | --- |
| Hardware polynomial | CRC16 `0x1021` or CRC32 `0x04C11DB7` | Same | CRC32, reversed representation `0xEDB88320` |
| Input | CPU writes or one selected DMA channel | Same, plus memory generation/monitor modes | Word-aligned address and byte length, both multiples of four |
| Initial value | Caller-provided seed | Caller-provided seed; memory modes take seed through descriptor destination field | Caller-provided seed |
| Harmony completion | CPU routine blocks; DMA channel callback or status | Same | Polls `DONE`, checks bus error |
| Independent CRC resources | One shared DMAC CRC engine | One shared DMAC CRC engine | Separate DSU engine |

Sources: [D21 DMAC header][d21-h], [E54 DMAC header][e54-h]; datasheets [D21][d21]
sections 13.11.3, 20.6.3, 20.8.2-20.8.5 and [D5x/E5x][e54] sections 12.11.3,
22.6.3.8-22.6.3.10, 22.8.2-22.8.5.

## The actual Harmony DMAC sequence

The SAM implementations expose these operations:

```c
void DMAC_ChannelCRCSetup(DMAC_CHANNEL channel, DMAC_CRC_SETUP setup);
uint32_t DMAC_CRCRead(void);
uint32_t DMAC_CRCCalculate(void *buffer, uint32_t length, DMAC_CRC_SETUP setup);
void DMAC_CRCDisable(void);
```

D21's setup contains polynomial selection and seed. D5x/E5x adds `crc_mode`.
There are no caller-selectable polynomial coefficients, input/output reflection,
or final-XOR fields in these SAM structures. [D21 header][d21-h],
[E54 header][e54-h].

For the channel path, Harmony disables the CRC engine, seeds it, selects the
polynomial and channel (`CRCSRC = 0x20 + channel`), then lets the caller start
the DMA transfer. D21 separately enables `CTRL.CRCENABLE`; D5x/E5x enables CRC
by selecting the source. This configures the single engine to observe that
channel; it does not give every channel its own CRC accumulator. Both setup
routines overwrite global CRC state without a busy rejection or software
reservation. [D21 implementation][d21-dmac], [E54 implementation][e54-dmac].

Microchip's [D21 example][d21-example] and [E54 example][e54-example] register a
DMA callback, calculate a software reference, run the CPU-fed CRC, then configure
CRC for channel 0 and launch a memory-to-memory transfer. On successful DMA
completion they check the copied data and compare `DMAC_CRCRead()` with the
software result. Errors are separate callback events. The example tests nine
literal bytes, `123456789`, seeded with `0xFFFFFFFF`, expecting `0xCBF43926`.
It does not append zero padding or convert the seed to a non-direct form.

That last point matters: the [generic Harmony `DMAC_ChannelCRCSetup` page][api]
combines examples from different device families. Its programmable-polynomial,
non-direct-seed and zero-padding material must not be applied to these SAM
implementations. Harmony's separate [`crc_02672` header][other-crc] has reflection,
polynomial-length and final-XOR fields, but it is not the DMAC/DSU interface used
by the D21 and E54 examples.

### CPU feed, alignment, and ordering

`DMAC_CRCCalculate()` also uses the DMAC CRC engine, but consumes no DMA channel
for data transfer. It chooses word beats when length is divisible by four,
halfword beats for other even lengths, otherwise byte beats. It reads the
buffer through matching integer pointers, writes `CRCDATAIN`, waits until
`CRCBUSY` is set, and clears that flag with a write-one-to-clear operation after
each beat. The loop and result return are synchronous; there is no timeout or
error result. It chooses alignment from **length only**, without checking the
buffer address. These details are visible in both [D21][d21-dmac] and
[E54][e54-dmac] implementations and should not be copied without reviewing the
Framework's unaligned byte-buffer requirements.

The hardware processes bytes internally; DMA beat width comes from the channel,
while CPU feed uses `CRCBEATSIZE`. The manuals describe the I/O busy flag as
software-cleared, unlike DMA mode where enabling/disabling the channel controls
it. Harmony therefore must not be translated into a conventional "wait until
busy clears" loop. [D21][d21] sections 20.6.3 and 20.8.5;
[D5x/E5x][e54] sections 22.6.3.8 and 22.8.5.

For completed CRC32, `CRCCHKSUM` reads are automatically bit-reversed and
complemented. While busy, the register exposes the internal value instead;
CRC16 reads are untransformed. A completed CRC32 result consequently is not
interchangeable with an internal continuation seed. The fixed reflection
behavior for the demonstrated CRC32 configuration is also checked by
Microchip's software reference. [D21][d21] section 20.8.4;
[D5x/E5x][e54] section 22.8.4; [D21 example][d21-example],
[E54 example][e54-example].

The nine-byte example does **not** establish equivalence of byte, halfword and
word beats, fragmented buffers, or arbitrary seeds. The reviewed prose does not
unambiguously specify every byte-lane ordering case. Those remain explicit
hardware-vector tests before defining a general API. CRC-register read order,
byte order within a beat, and CRC byte order on the wire are separate questions;
Harmony's example does not define a packet format.

### Completion, cancellation, and E54 memory modes

Harmony uses the existing channel interrupt handler: `TCMPL` produces a complete
event and `TERR` produces an error event; both clear its channel-busy state.
`CRCRead()` only reads the register, without checking completion. An aborted
transfer can therefore have a partial CRC, not a valid complete-frame result.
The caller must retain that distinction and reset the CRC seed before a fresh
calculation. This follows the [E54 implementation][e54-dmac] and [D5x/E5x][e54]
section 22.6.3.8. DMA completion is evidence of DMA data movement, not proof that
a UART/SPI shift register or I2C transaction has completed on the wire.

E54 additionally has `CRCGEN` and `CRCMON`. In memory generation mode a descriptor's
`DSTADDR` is an initial checksum value, not a normal destination pointer. The
hardware calculates directly over source memory and reports DMA completion.
Memory monitor mode checks the block including its expected checksum, reports
CRC mismatch through channel error status/`TERR`, and can repeat descriptor
lists. These modes are not present in the D21 setup type. They are specialized
memory operations, not automatic packet append/verify modes for every SERCOM.
[D5x/E5x][e54] sections 22.6.3.9-22.6.3.10;
[E54 header][e54-h] and descriptor construction in [E54 implementation][e54-dmac].

## DSU is a different option

Both Harmony DSU implementations take a start address, byte length, seed, and
output pointer. They write `ADDR`, `LENGTH`, and `DATA`, clear status, start
`CTRL.CRC`, poll `STATUSA.DONE`, and return failure on `BERR`. They reject zero
length and a null output pointer, but do not check word alignment or bound the
wait. They return the raw `DATA` register; the wrapper does not apply the final
complement. [D21 DSU][d21-dsu], [E54 DSU][e54-dsu].

The hardware accepts a memory region with word-aligned address and length.
Raw results can seed another region; complement the last result for the standard
CRC32 value described in the manual. A running operation can be cancelled with
DSU software reset. Harmony's E54 example clears DSU PAC write protection before
calling the PLIB. This is useful evidence for a memory-check facility, but not
an arbitrary-length streaming CRC API. [D21][d21] section 13.11.3;
[D5x/E5x][e54] section 12.11.3; [E54 DSU example][dsu-example].

## Silicon errata that affect the design

- D21 revisions A-F: consecutive instruction writes to `CRCDATAIN` may calculate
  incorrectly; the documented workaround inserts a NOP between writes.
  Harmony's polling/clear sequence contains intervening accesses, but any tighter
  CPU loop needs this requirement checked in its generated instructions.
  [D21 errata][d21-errata] section 1.7.1.
- D21 revisions A-D: DSU CRC32 over RAM needs the documented workaround around
  the operation (`0x41007058`, clear `0x30000`, then set `0x20000`). The reviewed
  Harmony DSU wrapper does not implement it. [D21 errata][d21-errata] section 1.8.3;
  [D21 DSU source][d21-dsu].
- D5x/E5x revisions A, D, F, G: DSU CRC32 over NVM never completes when the NVM
  cache is disabled; ensure that cache is enabled. A blocking wrapper without a
  timeout will not recover from that condition. [D5x/E5x errata][e54-errata]
  section 2.7.1; [E54 DSU source][e54-dsu].

These are findings from the archived errata editions, not a claim about the
connected board's revision. Read its device revision and check applicable errata
before hardware acceptance. Existing linked-descriptor DMA errata also remain
relevant when adding CRC DMA jobs; CRC does not bypass the underlying DMAC.
[D21 errata][d21-errata] section 1.7.2; [D5x/E5x errata][e54-errata] section 2.10.1.

## What this means for the Framework

The Framework already queues `SercomTxn*` pointers and holds private transmit
and receive ZeroDMA objects. Transaction headers define `I2C_CFG_CRC`,
`SPI_CFG_CRC`, and `UART_CFG_CRC`, but the inspected core, ZeroDMA, SPI and Wire
sources contain no CRC peripheral implementation; those flags are not an
existing CRC service. [SERCOM.h](../../cores/arduino/SERCOM.h),
[SERCOM_Txn.h](../../cores/arduino/SERCOM_Txn.h).

ZeroDMA owns the controller's allocation and lifetime. Its first allocated
channel resets the entire controller and installs descriptor/writeback tables;
freeing its final channel disables the controller, interrupts and clock. Harmony's
`DMAC_Initialize()` installs its own tables. Importing that initialization as a
second runtime would conflict with the Framework, and even CPU-fed DMAC CRC
must participate in the existing clock/reset lifetime. ZeroDMA already exposes
`getChannel()`, which can identify a channel to the CRC hardware without another
allocator. [ZeroDMA implementation][zerodma], [ZeroDMA header][zerodma-h],
[Harmony initialization][e54-dmac].

The reusable Harmony pattern is therefore **configure the existing hardware
engine, start work through the existing DMA owner, consume completion/error,
then read the result**. What still needs Framework design and validation is
serialization of that single CRC accumulator across overlapping clients,
transaction/buffer lifetime, cancellation and retries, continuation semantics,
and the non-DMA path. This is an integration conclusion from the sources above,
not a requirement to introduce an additional transport or ownership protocol.
Selecting one CRC source does not require stopping unrelated DMA channels; the
shared limitation concerns simultaneous independent CRC calculations.

A useful next investigation is a Framework-level hardware harness on D21 and
E54: reproduce Microchip's known vector, compare CPU and channel feed for byte,
halfword and word transfers, vary address alignment and lengths, test seeds and
split buffers, then exercise abort/retry and overlapping SERCOM work. Native
regressions can check scheduling and lifetime, but only hardware tests establish
peripheral byte ordering and silicon behavior. These results should inform the
CRC library contract before or alongside the protocol's polynomial and wire
format decision. No implementation, protocol choice, firmware flash, commit or
PR was made for this research.

[d21]: ../../../SimIODevice/docs/datasheets/SAM-D21-DA1-Family-Data-Sheet-DS40001882.pdf
[e54]: ../../../SimIODevice/docs/datasheets/SAM-D5x-E5x-Family-Data-Sheet-DS60001507.pdf
[d21-errata]: ../../../SimIODevice/docs/datasheets/SAM-D21DA1-Family-Silicon-Errata-and-Data-Sheet-Clarification-DS80000760.pdf
[e54-errata]: ../../../SimIODevice/docs/datasheets/SAM-D5x-E5x-Family-Silicon-Errata-and-Data-Sheet-Clarification-DS80000748.pdf
[d21-dmac]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dmac_u2223/templates/plib_dmac.c.ftl#L544-L656
[e54-dmac]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dmac_u2503/templates/plib_dmac.c.ftl
[d21-h]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dmac_u2223/templates/plib_dmac.h.ftl#L107-L178
[e54-h]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dmac_u2503/templates/plib_dmac.h.ftl#L117-L184
[d21-dsu]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dsu_u2209/templates/plib_dsu.c.ftl#L57-L92
[e54-dsu]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/dsu_u2410/templates/plib_dsu.c.ftl#L57-L92
[d21-example]: https://github.com/Microchip-MPLAB-Harmony/csp_apps_sam_d21_da1/blob/9331e79cf2937d2b3166813c6d2886b2481162e3/apps/dmac/dmac_crc32_generate/firmware/src/main.c
[e54-example]: https://github.com/Microchip-MPLAB-Harmony/csp_apps_sam_d5x_e5x/blob/4a38194d468e94d4710c31bbfd67fbfe9f5d2096/apps/dmac/dmac_crc32_generate/firmware/src/main.c
[dsu-example]: https://github.com/Microchip-MPLAB-Harmony/csp_apps_sam_d5x_e5x/blob/4a38194d468e94d4710c31bbfd67fbfe9f5d2096/apps/dsu/dsu_crc32_generate/firmware/src/main.c#L238-L250
[api]: https://onlinedocs.microchip.com/oxy/GUID-450989FA-38E4-4D68-AB61-15ADB29AD718-en-US-6/GUID-17431D0E-B538-41B9-8FA9-861BAC4C365E.html
[other-crc]: https://github.com/Microchip-MPLAB-Harmony/csp/blob/e846e68aa557b450d9fff03f00b000c50fb97f63/peripheral/crc_02672/templates/plib_crc.h.ftl#L76-L98
[zerodma]: https://github.com/crabel99/Adafruit_ZeroDMA/blob/9215aa0848a092960fc1ba4e02cb4989af2f46e6/Adafruit_ZeroDMA.cpp#L380-L574
[zerodma-h]: https://github.com/crabel99/Adafruit_ZeroDMA/blob/9215aa0848a092960fc1ba4e02cb4989af2f46e6/Adafruit_ZeroDMA.h#L175
