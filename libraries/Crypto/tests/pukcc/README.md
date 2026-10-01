# PUKCC verifier checks

From the Framework root, run the Device Python environment:

```
../SimIODevice/.venv/bin/python libraries/Crypto/tests/pukcc/run.py
```

The native test compiles the actual `PukccEcdsa.cpp`, `PukccEcc.cpp`, and core
PUKCC declarations. Only the Crypto hardware calls and Crypto RAM are faked.
It checks reduction → point validation → signature verification, rejection at
every completion/submission stage, one completion callback, malformed SEC1
prefix, null inputs, zero/out-of-order scalars, out-of-field coordinates, and
unchanged RAM when registration fails, and 48/66-byte curve layouts. ASan/UBSan run.

The fake does not implement ROM elliptic-curve mathematics. Known valid and
invalid signatures, off-curve points, and the mandatory PUKCL self-test still
require an E53/E54 hardware run. Bounds and sequencing alone do not prove a
signature is valid.

## Loader interface

Include `utility/pukcc/PukccEcdsa.h` and keep a
`Crypto::PukccEcc::EcdsaVerifier` alive through completion. Before first use,
complete `pukcc::selfTestAsync` successfully through the real PendSV service.
Then call `verifyP256Async(key65, hash32, signature64, callback, context)`.
The public key is SEC1 uncompressed (`04 || X || Y`); signature is raw `r || s`.
Inputs are copied into Crypto RAM before submission returns. The callback's
boolean is the result; submission returning true is not verification success.

This preserves the provider's existing first-submission failure behavior:
callback(false) may occur synchronously and the function then returns false.
Boundary rejection returns false without callback. Later errors call back
exactly once. The loader must handle submission failure and completion with a
single terminal flag. Keep all PUKCC access serialized. Do not reset or destroy the verifier while
an operation is pending. The core callback-registration API is not an ownership
lock; it does not prevent another caller from replacing the callback.

`MbedTlsCryptoProvider` delegates all of its supported ECDSA curves to this
same operation. Curve constants and ROM parameter layout are shared; no new
signature algorithm or ROM ABI implementation is introduced.
