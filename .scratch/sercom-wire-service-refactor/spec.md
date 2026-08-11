# SERCOM Wire service refactor

Separate `TwoWire::onService()` classification and dispatch logic into a deep
internal module while preserving the public Wire interface and exact ISR
ordering. The refactor should improve reviewability without changing verified
SAMD21/SAME5x behavior.

The module should own classification of master errors, slave transaction
boundaries, and the resulting action. Register access and action execution stay
in the SERCOM/Wire implementation. Tests should exercise the same decision seam
used by production code.

Moving the `SERCOM_*` files into a dedicated directory is related repository
organization, but is not required for the behavioral refactor.
