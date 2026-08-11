# SERCOM I2C BUSERR recovery on SAM D21 and SAM D5x/E5x

## Question and sources

This note audits retrying a master transaction after `STATUS.BUSERR`, especially
when BUSERR follows an arbitration-loss retry in a multi-host exchange. It uses
the following locally archived primary sources:

- Microchip, *SAM D21/DA1 Family Complete Data Sheet*, DS40001882K (2025),
  sections 28.6.2.3, 28.6.2.4.2, 28.6.2.4.3, 28.10.6, 28.10.7 and 28.10.9.
- Microchip, *SAM D5x/E5x Family Complete Data Sheet*, DS60001507M (2024),
  sections 36.6.2.3, 36.6.2.4.2, 36.6.2.4.3, 36.8.6-36.8.8 and 36.8.10.
- NXP, *UM10204 I2C-bus specification and user manual*, Rev. 7.0 (2021),
  section 3.1.8.
- Microchip/Atmel, *AT03250: SAM D/R/L/C I2C Master Mode (SERCOM I2C)
  Driver*, Atmel-42117E (2015), sections 3.5-3.6.
- Microchip silicon errata DS80000760M (SAM D21/DA1) and DS80000748 (SAM
  D5x/E5x), SERCOM-I2C entries.

The files are under `../SimIODevice/docs/datasheets/` and
`../SimIODevice/docs/multi-master/` relative to this repository.

## Conclusions

1. `BUSERR` is a detected protocol violation, not merely a missing ACK. The
   examples are an illegal START/repeated START/STOP sequence, START immediately
   followed by STOP, or an enabled timeout during a frame. Detection is
   independent of ownership. [D21 section 28.10.7, page 545; D5x/E5x section
   36.8.8, page 984.]
2. In **host mode while owner**, BUSERR follows the arbitration-loss hardware
   path: hardware also sets `ARBLOST` and `MB`, disables SDA output, releases
   SCL, and the host may perform no bus operation until the bus is idle. [D21
   section 28.6.2.4.2, pages 506-507; D5x/E5x section 36.6.2.4.2, pages
   942-943.]
3. Therefore a STOP is neither required nor appropriate for the normal
   `BUSERR+ARBLOST` case. The local host has released the lines and must not
   disturb the controller that now owns the bus. This also follows the I2C rule
   that a controller losing arbitration must stop driving and restart only
   when the bus is free. [UM10204 section 3.1.8, page 11.]
4. Rewriting `ADDR` is the documented low-level retry mechanism **when sampled
   BUSSTATE is BUSY or IDLE**. In BUSY, hardware waits for IDLE before START; in
   IDLE it generates START immediately. The ADDR write automatically clears
   `BUSERR`, `ARBLOST`, `MB`, and `SB`. [D21 section 28.10.9, pages 547-548;
   D5x/E5x section 36.8.10, pages 985-986.]
5. `ADDR` must not be blindly written in OWNER with neither MB nor SB. In OWNER
   it requests a repeated START, and both manuals expressly say an OWNER-state
   repeated-START ADDR write is performed while MB or SB is set. Thus
   `BUSERR+OWNER+ERROR` with no MB/SB contradicts the documented owner-BUSERR
   result and provides no documented command service point. Clear/snapshot the
   error and wait for BUSY/IDLE; if OWNER/no-service-point persists, treat the
   peripheral as hung and use bounded recovery rather than issuing ADDR or
   STOP. [Same ADDR sections; D21 section 28.6.2.3, page 503; D5x/E5x section
   36.6.2.3, page 939.]
6. A SERCOM reset/reinitialization is not part of ordinary BUSERR recovery.
   Both manuals mention `SWRST` only if a protocol violation has hung the I2C
   peripheral. [D21 section 28.6.2.3, page 503; D5x/E5x section 36.6.2.3,
   page 939.]
7. Retrying the same queue head is electrically supported, but the transaction
   result can be ambiguous. Bytes preceding BUSERR may already have been ACKed;
   I2C supplies no transaction rollback. A complete replay is semantically safe
   only for an idempotent operation or a protocol that detects duplicates.
   This is an inference from byte-oriented I2C operation and the absence of an
   atomic transaction/rollback facility, not a Microchip guarantee.

## Required register and DMA handling

`INTFLAG.ERROR` is the summary interrupt for status errors and is W1C. `BUSERR`
and `ARBLOST` are independently W1C and are also cleared by writing `ADDR`.
`MB` is set even when a transmitted byte ends in BUSERR or ARBLOST. Clearing MB
alone does not terminate or continue a held transaction; a valid DATA, ADDR, or
CMD action is normally the operation that releases it. [D21 sections 28.10.6-
28.10.7, pages 542-545; D5x/E5x sections 36.8.7-36.8.8, pages 980-984.]

The SERCOM manuals do not prescribe a DMAC sequence for BUSERR. Driver logic
must nevertheless abort any DMA channel associated with the failed attempt
before resetting its byte index or rearming it. Otherwise a pending request or
completion can update the failed attempt after the retry is installed. This is
a software ownership requirement derived from the repository's asynchronous
DMA design, not a datasheet BUSERR rule.

An `ADDR` write is write-synchronized. Existing code intentionally waits for a
later MB/SB rather than polling synchronization. A recovery path that performs
additional synchronized operations before that event must respect
`SYNCBUSY.SYSOP`. [D21 section 28.6.6 and 28.10.8; D5x/E5x section 36.6.6 and
36.8.9.]

## Master recovery decision

Use a fresh, single STATUS/INTFLAG snapshot before destructive clearing:

| Observed condition | Documented interpretation | Safe immediate action |
|---|---|---|
| `BUSERR + ARBLOST + BUSY` | Error released ownership; another host owns bus | Abort attempt DMA, preserve queue head, reset index, write ADDR; hardware waits for IDLE |
| `BUSERR + ARBLOST + IDLE` | Winner has already released bus | Abort attempt DMA, preserve queue head, reset index, write ADDR to START |
| `BUSERR + ARBLOST + OWNER + MB/SB` | Not the documented steady result; OWNER ADDR is a repeated START | Do not classify as an ordinary retry without a hardware-specific justification; preserve evidence and handle the legal service point conservatively |
| `BUSERR + OWNER`, no MB/SB | Contradicts the specified owner-BUSERR flags; no documented ADDR/CMD service point | Clear BUSERR/ERROR, wait boundedly for BUSY/IDLE; if stuck, SWRST/reapply configuration and report recovery |
| `BUSERR` while not owner and no ARBLOST | Malformed traffic was observed while another host controlled the bus | Clear warning; do not issue STOP; retry only from BUSY/IDLE according to transaction policy |
| `BUSERR + UNKNOWN` | State is not established | Do not write ADDR (it terminates with BUSERR); use the documented synchronized UNKNOWN-to-IDLE establishment only after proving the lines/transaction are safe |

The manuals say software will *typically* report address-phase collision or bus
error to the application and clear the interrupt flag. They do not require the
driver to retire the logical queue head, nor do they guarantee indefinite
automatic replay. [D21 section 28.6.2.4.2, page 507; D5x/E5x section
36.6.2.4.2, page 943.]

## Slave/client behavior

Client BUSERR also means an illegal condition observed regardless of ownership,
but client mode has no BUSSTATE and does not initiate a retry. Clearing BUSERR
and ERROR and continuing to listen is supported; a future address response or
AMATCH clear normally also clears BUSERR. The D21 errata warns that, on affected
revisions, client BUSERR and several other status bits are *not* automatically
cleared by AMATCH clear, so software must explicitly W1C them. [D21 section
28.8.8 and DS80000760M section 1.15.14; D5x/E5x section 36.8.7.]

The external controller owns replay of a malformed client transaction. The
local client should terminate/count any active DMA phase according to the
actual PREC/AMATCH/DRDY boundary; it must not fabricate a local master retry.

No D21 or D5x/E5x erratum was found that changes the host BUSERR recovery above.
The reviewed errata include client-mode issues (including D21 explicit W1C and
DMA edge cases), but no host BUSERR retry workaround applicable to this setup.

## Audit of the proposed automatic retry

The proposal—abort DMA, clear BUSERR/ERROR, reset the transaction index,
immediately rewrite ADDR without callback or dequeue—is **conditionally sound**,
not universally sound.

It is sound when all of these hold:

- the snapshot establishes BUSY or IDLE;
- no coasserted terminal condition changes the diagnosis;
- the queue head and DMA generation remain installed consistently;
- the entire operation is safe to replay; and
- retry count/deadline policy prevents an electrically malformed bus from
  causing an endless ISR retry loop.

It is missing or unsafe if it:

- writes ADDR in OWNER without MB/SB;
- writes ADDR in UNKNOWN;
- issues STOP merely because BUSERR is set (BUSERR may occur without local
  ownership, and owner BUSERR normally coasserts ARBLOST/release);
- assumes no bytes were accepted before BUSERR;
- retries every BUSERR indefinitely; or
- clears flags before preserving the raw state needed to distinguish these
  cases.

For this lease handshake, a guarded retry can be justified if the lease request
is explicitly classified as idempotent/duplicate-detectable. It should still be
bounded (attempt count and original transaction deadline), expose both the
initial BUSERR and retry outcome, and escalate repeated BUSERR to bus-health or
peripheral recovery. By contrast, ordinary arbitration loss can reasonably be
retried for liveness because it is expected multi-host behavior; BUSERR is a
malformed-bus condition and should not share an unbounded retry policy.

## Correction to prior arbitration note

`STATUS=0x12` is `BUSSTATE=IDLE (0x10) | ARBLOST (0x02)`, not OWNER. BUSSTATE is
bits 5:4 and encodes UNKNOWN=0, IDLE=1, OWNER=2, BUSY=3. The companion research
note has been corrected.
