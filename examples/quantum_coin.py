#!/usr/bin/env python3
"""Flip a coin with certified CURBy-Q quantum randomness.

Each flip takes one bit from a uint16 in an RS256-verified pulse, so a head or
tail carries certified quantum entropy rather than a seeded PRNG. If no
verified pulse can be fetched, this script refuses to flip — classical
randomness is never passed off as quantum.

    python examples/quantum_coin.py
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from curby_qrng import fetch_curby, last_error, last_provenance
except ModuleNotFoundError:  # running straight from a source checkout
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from curby_qrng import fetch_curby, last_error, last_provenance

FLIPS = 10


def main() -> int:
    values = fetch_curby(FLIPS)
    if not values:
        print("No verified CURBy-Q pulses available — not flipping.",
              file=sys.stderr)
        print(f"reason: {last_error()}", file=sys.stderr)
        print("Unverified randomness is never reported as certified quantum "
              "randomness. Nothing was generated.", file=sys.stderr)
        return 1

    flips = ["Heads" if value & 1 else "Tails" for value in values[:FLIPS]]
    heads = flips.count("Heads")

    prov = last_provenance()
    print(f"{len(flips)} coin flips, certified CURBy-Q quantum randomness")
    print()
    for number, flip in enumerate(flips, 1):
        print(f"  {number:2d}. {flip}")
    print()
    print(f"heads: {heads}   tails: {len(flips) - heads}")
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
