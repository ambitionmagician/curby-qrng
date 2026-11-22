#!/usr/bin/env python3
"""Roll fair six-sided dice with certified CURBy-Q quantum randomness.

Each face comes from a uint16 out of an RS256-verified pulse whose bytes were
extracted from a loophole-free Bell test (device-independent certification).
The short tail of the uint16 range is rejected so every face is exactly
equally likely. If no verified pulse can be fetched, this script refuses to
roll — classical randomness is never passed off as quantum.

    python examples/quantum_dice.py
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from curby_qrng import fetch_curby, last_error, last_provenance
except ModuleNotFoundError:  # running straight from a source checkout
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from curby_qrng import fetch_curby, last_error, last_provenance

ROLLS = 5
SIDES = 6
# 65536 % 6 == 4, so the top four values are rejected to avoid modulo bias.
_ACCEPT_BELOW = 65_536 - (65_536 % SIDES)


def main() -> int:
    values = fetch_curby(max(ROLLS * 4, 64))
    if not values:
        print("No verified CURBy-Q pulses available — not rolling.",
              file=sys.stderr)
        print(f"reason: {last_error()}", file=sys.stderr)
        print("Unverified randomness is never reported as certified quantum "
              "randomness. Nothing was generated.", file=sys.stderr)
        return 1

    rolls = []
    for value in values:
        if value < _ACCEPT_BELOW:
            rolls.append(value % SIDES + 1)
            if len(rolls) == ROLLS:
                break
    if len(rolls) < ROLLS:
        print(f"Only {len(rolls)} of {ROLLS} rolls could be drawn from the "
              "verified pulses; run again for a fresh walk of the chain.",
              file=sys.stderr)
        return 1

    prov = last_provenance()
    print(f"{ROLLS} dice, certified CURBy-Q quantum randomness")
    print()
    print("   " + "   ".join(f"[{face}]" for face in rolls))
    print()
    print("rounds: " + ", ".join(str(r) for r in prov["rounds"]))
    print("pulse timestamps: "
          + ", ".join(str(t) for t in prov["pulse_timestamps"]))
    print("note: the DIQRNG chain has been dormant since 2025-08-22, so these "
          "values come")
    print("      from banked, signed pulses — certified quantum, not fresh "
          "output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
