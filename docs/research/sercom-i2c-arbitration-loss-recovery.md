# SERCOM I2C arbitration-loss recovery on SAM D21 and SAM D5x/E5x

## Question

What does the SERCOM I2C hardware do after multi-host arbitration loss, and what is software required to do before retrying a transaction?

This note uses the locally archived primary sources:

- Microchip, *SAM D21/DA1 Family Complete Data Sheet*, DS40001882K (2025), especially sections 28.6.2.3, 28.6.2.4.2, 28.6.2.4.3, and 28.8.8.
- Microchip, *SAM D5x/E5x Family Complete Data Sheet*, DS60001507M (2024), especially sections 36.6.2.3, 36.6.2.4.2, 36.6.2.4.3, and 36.8.8.
- NXP, *UM10204 I2C-bus specification and user manual*, Rev. 7.0 (2021), section 3.1.8.
- Microchip/Atmel, *AT03250: SAM D/R/L/C I2C Master Mode (SERCOM I2C) Driver*, Atmel-42117E (2015), sections 3.5 and 3.6.
- Microchip silicon errata DS80000760 (SAM D21/DA1) and DS80000748 (SAM D5x/E5x), checked for a conflicting SERCOM-I2C arbitration erratum; none was found.

Local source files are under `../SimIODevice/docs/datasheets/` and `../SimIODevice/docs/multi-master/` relative to the SimIO workspace.

## Short answer

The SAM D21 and SAM D5x/E5x specify the same recovery behavior:

1. When arbitration is lost, hardware disables its SDA output and releases SCL.
2. `STATUS.ARBLOST` and `INTFLAG.MB` are set.
3. The bus-state machine changes from `OWNER` to `BUSY` and remains `BUSY` until it detects STOP (or an enabled inactive-bus timeout).
4. Software must not perform bus operations while the winner still owns the bus.
5. Software clears `INTFLAG.MB`. It may clear `ARBLOST` explicitly, but need not do so if it retries by writing `ADDR`, because writing `ADDR` automatically clears `ARBLOST` and the other transaction status flags.
6. Writing `ADDR` while `BUSSTATE=BUSY` is a supported way to queue a retry: the SERCOM waits for `IDLE`, then generates START and transmits the address.
7. The losing host must not issue STOP. It no longer owns the bus, and STOP would interfere with the winning transaction.
8. Neither a peripheral reset nor reinitialization is part of normal arbitration recovery. `SWRST` is documented only as recovery if a protocol violation has already hung the peripheral.

Consequently, the current Wire implementation's immediate `ADDR` rewrite is consistent with the documented SERCOM retry mechanism when the hardware is in `BUSSTATE=BUSY` or `BUSSTATE=IDLE`. The captured `STATUS=0x12` decodes as `ARBLOST=1, BUSSTATE=IDLE`: `BUSSTATE` occupies bits 5:4, so `0x10` is IDLE and `0x02` is ARBLOST. The earlier revision of this note incorrectly decoded it as OWNER.

## Normative I2C behavior

NXP specifies that arbitration continues bit-by-bit for as long as competing controllers transmit identical bits. A controller loses when it attempts to transmit HIGH but observes SDA LOW. It then turns off its SDA output. It may generate clock pulses only through the end of the byte in which it lost, and it "must restart its transaction when the bus is free." If the device also has target capability and loses during addressing, it must immediately consider whether the winner is addressing it and switch to target behavior when applicable. [UM10204 Rev. 7.0, section 3.1.8, page 11.]

This means successful address acknowledgement or successful transmission of an initial common payload byte does not establish that a controller won the complete transaction. Arbitration may be lost at the first later bit where the payloads differ.

## SAM D21 behavior

### Hardware state transition

The D21 bus-state diagram shows `OWNER -> BUSY` on lost arbitration. Its prose is explicit: when a packet collision is detected in `OWNER`, arbitration is lost and the bus state becomes `BUSY` until STOP is detected. `BUSY` means some other host owns the bus. [DS40001882K, section 28.6.2.3, pages 502-503; section 28.8.8, page 544.]

During address transmission, loss sets `INTFLAG.MB` and `STATUS.ARBLOST`; hardware disables SDA output and releases SCL, disabling clock stretching. The host is no longer allowed to execute bus operations until idle. [DS40001882K, section 28.6.2.4.2, page 507.]

Arbitration can also be lost during data transmission. `INTFLAG.MB` is set whether the data byte succeeds or loses arbitration, so `ARBLOST` must be checked at the beginning of MB handling. Microchip states that address- and data-packet arbitration are handled the same way. [DS40001882K, section 28.6.2.4.3, page 508.]

### Retrying with `ADDR`

Writing `ADDR.ADDR` begins a transaction. If the bus is busy, the host waits until the bus becomes idle; only then does it generate START and send the address. [DS40001882K, section 28.6.2.4.2, page 507.]

Microchip says software will typically report the collision and clear the interrupt flag before returning from the ISR. No other flag must be cleared then because the next `ADDR.ADDR` write automatically clears the transaction flags. The `ARBLOST` register description independently states that an `ADDR.ADDR` write automatically clears `ARBLOST`; writing one to `ARBLOST` is also allowed. [DS40001882K, section 28.6.2.4.2, page 507; section 28.8.8, page 544.]

### STOP and reset

Normal arbitration loss does not call for STOP: hardware has released the lines and another host owns the bus. The documented normal path is to wait for the winner's STOP and then retry. `CTRLA.SWRST` is mentioned only as a way to recover after a protocol violation has caused the I2C peripheral to hang. [DS40001882K, section 28.6.2.3, page 503.]

## SAM D5x/E5x behavior

The D5x/E5x text is materially identical to D21:

- lost arbitration changes `OWNER` to `BUSY` until STOP;
- SDA output is disabled and SCL is released;
- `INTFLAG.MB` and `STATUS.ARBLOST` are set;
- no bus operation is permitted until idle;
- an `ADDR.ADDR` write while busy waits for idle before START;
- writing `ADDR.ADDR` automatically clears `ARBLOST` and the transaction flags;
- `SWRST` is a hang-recovery mechanism, not normal arbitration handling.

[DS60001507M, sections 36.6.2.3 and 36.6.2.4.2, pages 938-943; section 36.6.2.4.3, page 944; section 36.8.8, page 983.]

No arbitration-recovery difference was found between SAM D21 and SAM D5x/E5x.

## Application-note corroboration

AT03250 describes a losing host as stopping transmission and waiting until the bus is idle. Its bus-state diagram likewise shows arbitration loss moving `OWNER` to `BUSY`, and STOP moving `BUSY` to `IDLE`. The application-note API reports arbitration loss to the caller as `STATUS_ERR_PACKET_COLLISION`; it does not prescribe reset or STOP by the loser. [Atmel-42117E, sections 3.5.1 and 3.6, pages 9-10, and API status tables.]

## Relation to the current Wire implementation

The current arbitration branch in `libraries/Wire/Wire.h`:

1. aborts DMA,
2. clears interrupt flags,
3. resets the queue head through `startTransmissionWIRE()`, and
4. immediately writes `ADDR`.

Its comment that `ADDR` waits while another host owns the bus accurately reflects both device data sheets. Therefore the existence of an immediate `ADDR` write alone is not evidence of an invalid retry.

However, the hardware behavior of an `ADDR` write depends on `BUSSTATE`:

| `BUSSTATE` | Meaning | Effect of writing `ADDR` |
|---|---|---|
| `IDLE` (`01`) | bus free | generate START |
| `OWNER` (`10`) | this SERCOM owns bus | generate repeated START |
| `BUSY` (`11`) | another host owns bus | wait for idle, then generate START |
| `UNKNOWN` (`00`) | state not established | error/abort in the current driver |

The captured RedBoard value `STATUS=0x12` decodes as:

```text
0x12 = BUSSTATE 0b01 (IDLE) | ARBLOST
```

IDLE can be observed if the winning transaction has already ended before software samples STATUS. Writing `ADDR` in this state is documented to generate a new START immediately. It is more important than a generic ownership check:

- Continuing DATA while `ARBLOST` is set is always wrong.
- Retrying only when `OWNER` is set is also wrong: after a valid arbitration loss the loser must not be owner.
- Rewriting `ADDR` when state is `BUSY` is explicitly supported and hardware queues the retry.
- Rewriting `ADDR` while an independently observed state is `OWNER` asks for a repeated START, not a wait-for-idle retry.

The manuals do not state whether `ARBLOST + OWNER` can be a brief observable transition before the bus-state logic reaches `BUSY`. Therefore, a defensible software guard is to avoid the `ADDR` rewrite while `ARBLOST` is paired with `OWNER`; wait until state is `BUSY` or `IDLE`, then retry. That is an inference from the specified state-dependent `ADDR` behavior, not an interpretation of the captured `0x12` value and not a published erratum.

## Recommended discriminating probes/tests

Before changing retry policy, capture the following in order at ARBLOST ISR entry and immediately before the retry `ADDR` write:

- raw `STATUS`, including `BUSSTATE`;
- raw `INTFLAG`;
- `SYNCBUSY.SYSOP`;
- transaction byte index before it is reset;
- whether `BUSSTATE` changes from `OWNER` to `BUSY` without software intervention.

A focused guarded experiment can defer only the `ARBLOST + OWNER` case and issue `ADDR` once state becomes `BUSY` or `IDLE`. The acceptance criterion is a clean START/address boundary and exactly one complete winning payload at the SAME54. This tests the observed state anomaly without adding STOP, reset, or a protocol-level backoff that the hardware specification does not require.

## Audit of the current BUSY, IDLE, and UNKNOWN branches

This section answers the narrower implementation question: does the current
Wire/SERCOM code already restart the same queued transaction when `ARBLOST` is
observed with `BUSSTATE=BUSY`, `IDLE`, or `UNKNOWN`?

### Common ARBLOST entry path

The ISR does not currently branch on bus state inside its arbitration-loss
handler. For every master `ARBLOST` combination it:

1. aborts both DMA directions and clears the transaction's DMA selection;
2. clears all I2C master interrupt flags;
3. leaves the queue head and `_wire.currentTxn` installed;
4. sets `awaitingAddressAck`;
5. calls `startTransmissionWIRE()`; and
6. returns without retiring the queue head or invoking its completion callback.

[`libraries/Wire/Wire.h`, lines 275-321 in the audited worktree.]

`startTransmissionWIRE()` peeks rather than removes the queue head, recognizes
that it is still `_wire.currentTxn`, resets `_wire.txnIndex` to zero, restores
the transaction length, recalculates DMA eligibility, and writes the same
transaction address. It only resets `_wire.retryCount` when the queue head is a
different transaction. Thus BUSY and IDLE arbitration retries have no software
attempt limit; each later `ARBLOST` re-enters the same path until the transaction
completes or a different terminal error occurs. [`cores/arduino/SERCOM.cpp`,
lines 1279-1383.]

The blanket `clearINTFLAG()` clears the `MB` event that accompanies arbitration
loss. That agrees with Microchip's instruction to clear the interrupt flag
before leaving the ISR. The subsequent `ADDR` write also clears the master
transaction flags, including `ARBLOST`, in hardware. [DS40001882K, section
28.6.2.4.2, page 507 and section 28.8.8, page 544; DS60001507M, section
36.6.2.4.2, pages 942-943 and section 36.8.8, page 983.]

### `ARBLOST + BUSY`

**Current implementation: yes, it restarts the same transaction in the
documented way.** `startTransmissionWIRE()` resets the byte index and writes
`ADDR` while `BUSSTATE=BUSY`. The SERCOM then waits for the bus to become idle,
generates START, and sends the address. The CPU does not need to poll for IDLE
first. [DS40001882K, section 28.6.2.4.2, page 507; DS60001507M, section
36.6.2.4.2, page 942.]

This is the expected steady state after ordinary loss: both families document
the transition `OWNER -> BUSY`, with BUSY retained until STOP is detected.
[DS40001882K, sections 28.6.2.3-28.6.2.4.3, pages 502-508; DS60001507M,
sections 36.6.2.3-36.6.2.4.3, pages 938-944.]

### `ARBLOST + IDLE`

**Current implementation: yes, it restarts the same transaction.** The same
helper resets the byte index and writes `ADDR`; in IDLE, that write generates a
START immediately and transmits the address. [DS40001882K, section 28.6.2.4.2,
page 507; DS60001507M, section 36.6.2.4.2, page 942.]

IDLE is not the documented immediate state at the instant arbitration is lost,
but it can be the software-visible state if the winner has already issued STOP
before software services the flags. The code's action is valid for that state.

### `ARBLOST + UNKNOWN`

**Current implementation: it ultimately restarts the same queue head, but not
by directly writing `ADDR` in UNKNOWN.** The ARBLOST handler is unconditional,
so the later `busState == WIRE_UNKNOWN_STATE` classification in `Wire.h` is not
reached for an event that also has `ARBLOST`; the handler calls
`startTransmissionWIRE()` first and returns. [`libraries/Wire/Wire.h`, lines
303-321 and 324-354.]

The helper detects UNKNOWN before resetting the transaction index or writing
`ADDR`, and calls `stopTransmissionWIRE(BUS_STATE_UNKNOWN)`. That recovery path
keeps the transaction installed, writes `BUSSTATE=IDLE`, waits for system-
operation synchronization, and calls `startTransmissionWIRE()` again. It allows
three such UNKNOWN recoveries; a fourth UNKNOWN result is completed as an error
and the queue head is retired. [`cores/arduino/SERCOM.cpp`, lines 1279-1282 and
1660-1687.]

Therefore the practical matrix is:

| State sampled with `ARBLOST` | What current code does | Same queue head retried? |
|---|---|---|
| BUSY | clear flags, reset index, write `ADDR`; hardware waits for IDLE | Yes, without an ARBLOST retry limit |
| IDLE | clear flags, reset index, write `ADDR`; hardware starts immediately | Yes, without an ARBLOST retry limit |
| UNKNOWN | enter shared UNKNOWN recovery, force IDLE, then reset index/write `ADDR` | Yes, up to three UNKNOWN recoveries |

The data sheets define UNKNOWN as the reset/uninitialized bus state and require
software to establish IDLE before starting normal master operation. The current
forced-IDLE recovery follows that initialization rule; it is separate from the
normal hardware arbitration-loss sequence, which is specified to end in BUSY.
[DS40001882K, sections 28.6.2.3 and 28.6.2.6, pages 502-503 and 512;
DS60001507M, sections 36.6.2.3 and 36.6.2.6, pages 938-939 and 948.]

### Audit conclusion

The proposed understanding is confirmed for BUSY and IDLE: the current
ARBLOST handler already restarts the queued transaction by calling the shared
start helper, and the state-dependent behavior of `ADDR` is supplied by the
SERCOM hardware. It is also functionally true for UNKNOWN, with the important
qualification that current code first converts UNKNOWN to IDLE through its
bounded bus-state recovery path. UNKNOWN never reaches the later ARBLOST-
independent state classifier during the original ISR invocation.

This audit does not validate treating `ARBLOST + OWNER` the same way. In OWNER,
the identical `ADDR` write requests a repeated START rather than waiting for
another controller to release the bus; that remains the one state requiring a
separate decision and hardware test.
