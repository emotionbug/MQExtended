# Coding standards

Commit to a shape. Every rule below removes a form of hedging.

For testing rules, see [testing](testing.md).

## Crates

- One public API per crate, re-exported from `lib.rs`. No pass-through modules.
- `mqx-topic`, `mqx-codec` and `mqx-auth` are sans-IO: no sockets, no async runtime, no global state. Loading a file from a path is the only I/O allowed, and every loader has a pure `parse` beside it.
- `unsafe` is forbidden workspace-wide.

## Parity code

- A port of Mosquitto behaviour carries a comment naming the Mosquitto file and function. That comment is the review checklist: the reader compares the two side by side.
- Keep the structure of the C code when porting non-trivial routines (same branch order, same early returns) so the comparison stays line-by-line. Rewrite for idiom only where behaviour is obviously identical.
- Quirks stay. If a quirk is wrong for every client, it goes in [Mosquitto compatibility](mosquitto-compatibility.md#deliberate-deviations) with the reason it is invisible.

## Errors

- One `thiserror` enum per crate boundary. Variants carry what the caller needs to choose a reaction (a CONNACK code, a disconnect, a log line with the file line number).
- Validate at the boundary (wire, config file), trust types inside. A decoded packet is valid by construction.
- No catch-all `Other(String)` variants.

## Comments and noise

- Comments explain why. Delete any comment whose removal loses nothing.
- No commented-out code, no `TODO` stubs, no decorative dividers.
- Never print secrets: password hashes and passwords stay out of `Debug` output and logs.
