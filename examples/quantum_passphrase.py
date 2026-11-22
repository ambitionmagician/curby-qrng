#!/usr/bin/env python3
"""Build a passphrase from certified CURBy-Q quantum randomness.

Words are picked with rejection sampling from a 96-word list using uint16
values from RS256-verified pulses: 8 words is about 52.7 bits of entropy from
certified quantum randomness (log2(96) * 8). If no verified pulse can be
fetched, this script refuses to produce a passphrase — classical randomness is
never passed off as quantum.

    python examples/quantum_passphrase.py [word_count]
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

try:
    from curby_qrng import fetch_curby, last_error, last_provenance
except ModuleNotFoundError:  # running straight from a source checkout
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from curby_qrng import fetch_curby, last_error, last_provenance

WORDS = (
    "able amber anchor apple arrow aspen atlas autumn badge bamboo barrel "
    "basil beacon birch bishop blossom boulder bridge bronze butter cactus "
    "candle canyon cedar chalk cherry cinder citrus clover cobalt comet copper "
    "coral cotton crimson crystal daisy delta denim desert dolphin dragon "
    "ember falcon fennel fern flute forest fossil garden garnet glacier "
    "granite gravel harbor hazel heron honey indigo island ivory jasper "
    "juniper kernel kettle lagoon lantern lemon lichen lilac linen lotus lunar "
    "magnet mango maple marble meadow mint mirror monsoon mosaic nectar "
    "nickel oak oasis olive onyx opal orchid otter oyster pebble pine quartz "
    "river"
).split()
assert len(WORDS) == 96 and len(set(WORDS)) == 96

# 65536 % 96 == 64, so the top 64 values are rejected to avoid modulo bias.
_ACCEPT_BELOW = 65_536 - (65_536 % len(WORDS))


def main(argv: list[str]) -> int:
    word_count = 8
    if len(argv) > 1:
        try:
            word_count = int(argv[1])
        except ValueError:
            print(f"usage: {Path(argv[0]).name} [word_count]", file=sys.stderr)
            return 2
    if word_count < 1:
        print("word_count must be at least 1", file=sys.stderr)
        return 2

    values = fetch_curby(max(word_count * 4, 64))
    if not values:
        print("No verified CURBy-Q pulses available — no passphrase generated.",
              file=sys.stderr)
        print(f"reason: {last_error()}", file=sys.stderr)
        print("Unverified randomness is never reported as certified quantum "
              "randomness. Nothing was generated.", file=sys.stderr)
        return 1

    words = []
    for value in values:
        if value < _ACCEPT_BELOW:
            words.append(WORDS[value % len(WORDS)])
            if len(words) == word_count:
                break
    if len(words) < word_count:
        print(f"Only {len(words)} of {word_count} words could be drawn from "
              "the verified pulses; run again for a fresh walk of the chain.",
              file=sys.stderr)
        return 1

    prov = last_provenance()
    entropy_bits = round(word_count * math.log2(len(WORDS)), 1)
    print(f"{word_count}-word passphrase, certified CURBy-Q quantum "
          f"randomness (~{entropy_bits} bits of entropy)")
    print()
    print("   " + "-".join(words))
    print()
    print("rounds: " + ", ".join(str(r) for r in prov["rounds"]))
    print("pulse timestamps: "
          + ", ".join(str(t) for t in prov["pulse_timestamps"]))
    print(f"note: ~{entropy_bits} bits is the strength of the word list, not "
          "of any single pulse;")
    print("      the DIQRNG chain has been dormant since 2025-08-22, so these "
          "values come")
    print("      from banked, signed pulses — certified quantum, not fresh "
          "output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
