# SimIO Framework Hardware Support Third-Party Provenance

This document tracks provenance and architecture decisions for SAME5x-class
hardware support needed by the Ethernet work. Keep this file current whenever
code is imported, adapted, or used as a reference during implementation.

## Policy

- Code listed as `copy` may be vendored into this library with the upstream
  license and copyright notices preserved.
- Code listed as `adapt` may be ported into SimIO Framework files with the
  upstream copyright/SPDX header preserved where required, and with meaningful
  SimIO changes documented in the file history.
- Code listed as `reference only` must not be copied into this repository
  unless the licensing decision is revisited and recorded here first.
- Framework glue, Arduino-facing APIs, board configuration, and ControlHub test
  code should be original SimIO code unless explicitly recorded below.

## Architecture Decision

### GMAC And Ethernet

Ethernet should be split into a framework-level GMAC hardware layer and an
Arduino-facing Ethernet library:

- `cores/arduino/GMAC.*` should own SAME5x GMAC hardware control, following the
  same boundary that `cores/arduino/SERCOM.*` provides for SPI, UART, and Wire.
  This layer should handle clocks, pin mux validation helpers, descriptor ring
  setup, DMA ownership, interrupt dispatch, MDIO transactions, MAC address
  programming, and raw frame TX/RX service.
- `libraries/Ethernet` should own the public API, lwIP integration, DHCP/static
  IP configuration, link state, sockets/clients/servers, and board-level
  convenience wrappers.
- PHY-specific behavior can start inside `libraries/Ethernet/src/utility` while
  there is only one supported ControlHub PHY. If multiple PHYs or non-Ethernet
  users need MDIO access, move PHY/MIIM abstractions down beside `GMAC.*`.

The reason for this split is practical: GMAC is an MCU peripheral like SERCOM,
not an Ethernet stack. Keeping the raw hardware layer in the core lets future
libraries or diagnostics use GMAC without pulling in lwIP or Arduino Ethernet
APIs.

### Cryptography Hardware

Cryptography peripherals should also live in `cores/arduino`, not inside
`libraries/Ethernet`. Ethernet, TLS, provisioning, diagnostics, and future
security libraries should be able to share the same hardware access layer.

Break the crypto hardware support up by SAME5x data sheet chapter:

- `cores/arduino/AES.*` for chapter 42, "AES - Advanced Encryption Standard".
  This layer should own AES clocks, enable/reset, key/data register loading,
  interrupt/DMA service hooks, hardware modes, and low-level block operations.
- `cores/arduino/PUKCC.*` for chapter 43, "Public Key Cryptography Controller
  (PUKCC)". This layer should own PUKCC clocking, RAM/workspace ownership,
  service invocation, status/error handling, and low-level public-key primitive
  dispatch. Higher-level ECC/RSA APIs can be layered above it later.
- `cores/arduino/TRNG.*` for chapter 44, "TRNG - True Random Number Generator".
  This layer should own TRNG clocking, enable/disable, polling/interrupt reads,
  entropy health/status reporting, and a minimal random-word API.

The public cryptography API can be added later as one or more bundled libraries.
The first step should be stable, testable hardware modules in the core, with
ControlHub tests proving clocks, interrupt vectors, and basic peripheral
operation. The existing SAME5x vector table already exposes weak `AES_Handler`,
`TRNG_Handler`, and `PUKCC_Handler` entries for these modules.

## Copy Or Adapt Sources

### lwIP

- Upstream: https://github.com/lwip-tcpip/lwip
- Local reference copy: `/Users/crabel/Documents/src/EthernetRefs/lwip`
- Reference commit: `3d896ba`
- License: BSD-style license in upstream `COPYING`
- Local use: TCP/IP stack, ARP, ICMP, DHCP, DNS, UDP, TCP, and optional socket
  compatibility as needed.
- Import mode: `copy`
- Planned local location:
  `libraries/Ethernet/src/utility/lwip/third_party/lwip`
- Required preservation:
  - Keep upstream copyright headers.
  - Include upstream `COPYING` near the copied lwIP source.
  - Record the upstream commit or release tag when imported.

### FreeRTOS-Plus-TCP

- Upstream: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP
- Local reference copy:
  `/Users/crabel/Documents/src/EthernetRefs/FreeRTOS-Plus-TCP`
- Reference commit: `4f674b3`
- License: MIT license in upstream `LICENSE.md`
- Local use: permissive TCP/UDP/socket architecture reference, especially for
  embedded socket ownership, bounded buffers, timeout/error behavior, and test
  organization.
- Import mode: `reference only` unless a later recorded decision promotes a
  specific file or subsystem to `copy` or `adapt`.
- Restriction: Do not copy FreeRTOS-specific tasking, scheduler, or network
  interface code into SimIO Framework unless the file-level import decision is
  recorded here first.

### smoltcp

- Upstream: https://github.com/smoltcp-rs/smoltcp
- Local reference copy: `/Users/crabel/Documents/src/EthernetRefs/smoltcp`
- Reference commit: `d9582fc`
- License: 0BSD license in upstream `LICENSE-0BSD.txt`
- Local use: permissive behavioral and architectural reference for event-driven
  embedded networking, no-heap packet ownership, interface/socket separation,
  and explicit polling/service boundaries.
- Import mode: `reference only`
- Restriction: smoltcp is Rust and should not be translated line-by-line into
  SimIO Framework. Use its architecture and contracts as reference only unless
  a specific translation/adaptation decision is recorded here first.

### Zephyr SAM GMAC Driver

- Upstream: https://github.com/zephyrproject-rtos/zephyr/tree/main/drivers/ethernet
- License: Apache-2.0
- Candidate files:
  - `drivers/ethernet/eth_sam_gmac.c`
  - `drivers/ethernet/eth_sam_gmac_priv.h`
  - `drivers/ethernet/eth_sam0_gmac.h`
- Local use: SAME5x GMAC descriptor rings, TX/RX service model, interrupt flow,
  and register sequencing reference for the SimIO `GMAC.*` core layer.
- Import mode: `adapt`
- Planned local location: `cores/arduino/GMAC.*`
- Required preservation:
  - Keep Apache-2.0 SPDX/copyright notices in adapted files.
  - Include Apache-2.0 license text if Zephyr-derived code is imported.
  - Record the upstream commit used as the adaptation base.

### Zephyr SAM Entropy Driver

- Upstream: https://github.com/zephyrproject-rtos/zephyr/tree/main/drivers/entropy
- License: Apache-2.0
- Candidate files:
  - `drivers/entropy/entropy_sam.c`
- Local use: SAM-family TRNG enable/read/poll sequencing and entropy-driver
  behavior reference for the SimIO `TRNG.*` core layer.
- Import mode: `adapt`
- Planned local location: `cores/arduino/TRNG.*`
- Required preservation:
  - Keep Apache-2.0 SPDX/copyright notices in adapted files.
  - Include Apache-2.0 license text if Zephyr-derived code is imported.
  - Record the upstream commit used as the adaptation base.

## Reference Only Sources

### Microchip MPLAB Harmony 3 Net

- Upstream: https://github.com/Microchip-MPLAB-Harmony/net
- Local reference copy:
  `/Users/crabel/Documents/src/EthernetRefs/microchip-harmony-net`
- License: Microchip Software License Agreement
- Relevant paths:
  - `driver/gmac`
  - `driver/miim`
  - `driver/ethphy`
  - SAME5x network example applications
- Local use: behavioral reference for SAME5x GMAC setup, MIIM/MDIO operations,
  PHY reset/link negotiation, descriptor alignment, cache considerations, and
  supported PHY behavior.
- Import mode: `reference only`
- Restriction: Do not copy Harmony source into SimIO Framework without a
  separate recorded decision to accept the Microchip license restrictions.

### Microchip MPLAB Harmony 3 Crypto

- Upstream: https://github.com/Microchip-MPLAB-Harmony/crypto
- License: Microchip Software License Agreement
- Relevant paths:
  - `drivers`
  - `src`
  - generated configuration/templates for AES, RNG, ECC, and RSA support
- Local use: behavioral and API-shape reference for AES modes, random number
  generation APIs, public-key API expectations, PUKCC-backed operations, and
  integration with Microchip examples.
- Import mode: `reference only`
- Restriction: Do not copy Harmony Crypto source into SimIO Framework without a
  separate recorded decision to accept the Microchip license restrictions.

### Mbed TLS

- Upstream: https://github.com/Mbed-TLS/mbedtls
- Local submodule:
  `libraries/Crypto/src/utility/third_party/mbedtls`
- Upstream revision: `05e0dfb`
- Included upstream submodules:
  - `framework` at `e79f4fdd4877e79a92e6b1e5965132ff0c5cc729`
  - `tf-psa-crypto` at `c35df962041731b08c6ff6a39a59e239c344e1ee`
  - `tf-psa-crypto/drivers/pqcp/mldsa-native` at
    `5772b4f4a0105694b1203abb582273f78fa951b7`
  - `tf-psa-crypto/framework` at
    `e79f4fdd4877e79a92e6b1e5965132ff0c5cc729`
- License: Apache-2.0 OR GPL-2.0-or-later. SimIO Framework uses this
  dependency under Apache-2.0.
- Intended local use: production TLS, X.509, DRBG, authenticated-mode, and
  public-key implementation used by `SecureClient` through `libraries/Crypto`.
  SAME5x `AES`, `PUKCC`, and `TRNG` modules should be integrated as Mbed TLS
  hardware/entropy backends where supported.
- Import mode: `allowed with attribution`
- Restriction: Keep upstream license notices and local attribution current.
  Do not replace Mbed TLS protocol or primitive code with clean-room SimIO
  protocol implementations unless there is a specific audited reason.

### wolfSSL / wolfCrypt

- Upstream: https://github.com/wolfSSL/wolfssl
- License: GPLv3 for open-source redistribution unless a commercial license or
  other explicit license path is obtained.
- Local use: reference only for understanding Microchip/Harmony integration
  patterns where needed.
- Import mode: `reference only`
- Restriction: Do not vendor or copy GPL wolfSSL/wolfCrypt code into the
  permissive framework path.

### Linux Networking And PHY Drivers

- Upstream: https://github.com/torvalds/linux
- Local reference copy: `/Users/crabel/Documents/src/EthernetRefs/linux`
- License: GPL-2.0-only WITH Linux-syscall-note for syscall headers; driver
  source is GPL and not compatible for direct copying into this framework.
- Relevant paths:
  - `drivers/net/ethernet/cadence`
  - `drivers/net/phy`
  - `include/linux/phy.h`
  - `include/linux/phylink.h`
- Local use: behavioral reference for MAC/PHY layering, PHY interrupt handling,
  autonegotiation state flow, carrier notifications, and MDIO bus contracts.
- Import mode: `reference only`
- Restriction: Do not copy Linux source into SimIO Framework. Use it only to
  understand battle-tested structure and observable behavior.

### Infineon Ethernet PHY Driver

- Local reference copy:
  `/Users/crabel/Documents/src/EthernetRefs/infineon-ethernet-phy-driver`
- Local use: PHY-driver structure and vendor-register handling reference for
  DP83867IR, DP83825I, and LAN8710AI-style standalone PHY abstractions.
- Import mode: `reference only`
- Restriction: Do not copy source until the exact upstream license and file
  provenance are recorded here.

### ST STM32 LAN8742 Component

- Local reference copy: `/Users/crabel/Documents/src/EthernetRefs/st-stm32-lan8742`
- Local use: LAN8742 register behavior and PHY wrapper reference.
- Import mode: `reference only`
- Restriction: Do not copy source until the exact upstream license and file
  provenance are recorded here.

### Microchip SAM D5x/E5x Data Sheet

- Local copy in SimIODevice: `docs/SAM-D5x-E5x-Family-Data-Sheet-DS60001507.txt`
- Local use: authoritative source for SAME5x GMAC, AES, PUKCC, and TRNG
  registers; clock masks; pin multiplexing; RMII/MII timing; descriptor fields;
  interrupt behavior; crypto workspace constraints; and peripheral operating
  sequences.
- Relevant chapters:
  - 24. GMAC - Ethernet MAC
  - 42. AES - Advanced Encryption Standard
  - 43. Public Key Cryptography Controller (PUKCC)
  - 44. TRNG - True Random Number Generator
- Import mode: `reference only`

## Original SimIO Code

The following should be implemented as original SimIO code:

- Arduino-facing `Ethernet` API.
- lwIP port configuration and platform hooks.
- Framework-level GMAC, AES, PUKCC, and TRNG hardware modules.
- ControlHub board configuration and tests.
- SAME5x variant pin definitions for GMAC-capable boards.
- Debug output, diagnostics, and test scaffolding.
- `utility/lwip/LwipPort.*`, `LwipTcpSocket.*`, and
  `LwipSocketBackend.*` until lwIP itself is vendored. These files may call
  lwIP public APIs, but should remain SimIO-authored glue rather than copied
  upstream stack code.

## Import Log

No third-party source has been imported into `libraries/Ethernet` yet.

Current Ethernet hardware, PHY, MIIM, netif, transport, and lwIP-adapter files
are SimIO-authored implementation files based on datasheet behavior and
high-level structure reviewed against Harmony, Linux, Zephyr, FreeRTOS-Plus-TCP,
smoltcp, Infineon, and ST references. Source from Harmony, Linux, Infineon, and
ST has not been copied.
