# curby-qrng

**Certified quantum randomness in one function call.** `curby-qrng` is a
stdlib-only Python client for **CURBy-Q**, the device-independent quantum
randomness chain published by CU Boulder and NIST as
`twine/1.0.x/diqrng/1.0.x`.

Each round's 512 bits were extracted from a **loophole-free Bell test** at NIST
Boulder and passed the device-independent certification test (PEFs) described
in *Nature* (2025), [doi:10.1038/s41586-025-09054-3](https://doi.org/10.1038/s41586-025-09054-3).
Every value this library returns comes from a pulse whose RS256 signature was
verified on your machine against the chain's published key — or you get an
empty list and a reason, never unverified bytes.

by **Dr. Brent Allen Jensen (Radical Blueprinting Research)**

---

## Why this is not just another beacon

Classical randomness beacons (NIST's beacon, its clones, and CURBy's own
`twine/1.0.x/rng/1.0.x` chain) give you signed, timestamped values whose
unpredictability still rests on assumptions about a classical device — a trusted
vendor, a protected seed, a well-behaved sensor. That is useful, but it is not
certified quantum randomness.

CURBy-Q is different: the randomness is certified by a Bell-violation
hypothesis test. No classical model can reproduce the observed correlations, so
the output's unpredictability follows from quantum mechanics rather than from
trust. This client only ever reads that chain:

| | CURBy-Q (`diqrng`) | Classical CURBy-RNG (`rng`) |
|---|---|---|
| Source | Device-independent certified quantum randomness (loophole-free Bell test, NIST Boulder) | Classical NIST-style beacon |
| Certification | Bell-violation test (PEFs); quantumness not assumed of the requester | Assumptions about a classical device |
| Used by this client | **Yes, exclusively** | **No, deliberately never** |

The classical chain is not fetched, wrapped, or relabelled anywhere in this
project. If you want classical beacon randomness, this is the wrong package.

---

## Quickstart

Requires Python 3.11+. Zero runtime dependencies.

```bash
git clone https://github.com/ambitionmagician/curby-qrng.git
cd curby-qrng
pip install -e .          # optional: only needed for the `curby-qrng` command
```

### Python

```python
from curby_qrng import fetch_curby, last_provenance, last_error

values = fetch_curby(8)                     # list of uint16, in [0, 65535]
if not values:
    print("no verified pulses right now:", last_error())
else:
    print(values)                           # e.g. [41207, 90210, ...]
    prov = last_provenance()
    print(prov["rounds"], prov["pulse_timestamps"])
```

`fetch_curby(count)` walks the chain from a persistent cursor so repeated calls
consume previously unconsumed rounds instead of re-reading the same pulses. It
returns `[]` on **any** failure — network, missing chain, bad signature, wrong
stage, broken index continuity — so callers degrade honestly instead of using
unverified data.

### Command line

```bash
curby-qrng -n 8          # or: python -m curby_qrng -n 8
```

Illustrative output (values and CID truncated here):

```
8 uint16 values from CURBy-Q certified quantum randomness (every pulse RS256-verified)
  41207 90210 1733 55614 32768 64001 29184 4711
chain: CURBy quantum (twine/1.0.x/diqrng/1.0.x)
chain CID: bafyrei...
rounds: 28290
pulse timestamps: 2025-08-22T13:41:07Z
pulses used: 1; oldest 2025-08-22T13:41:07Z; newest 2025-08-22T13:41:07Z
cursor pass: 0; fetched at 2026-11-22T15:58:02Z
note: the DIQRNG chain has been dormant since 2025-08-22 — these are banked, signed certified pulses, not fresh output.
```

Exit status is `0` when values were verified and printed, `1` when no verified
pulse could be obtained (nothing is printed as randomness), `2` for usage
errors.

### Examples

Three small, completely independent demos live in [`examples/`](examples):

```bash
python examples/quantum_dice.py        # 5 fair d6 rolls, rejection-sampled
python examples/quantum_coin.py        # 10 coin flips, one certified bit each
python examples/quantum_passphrase.py  # 8-word passphrase, ~52.7 bits
```

Each one prints the rounds and pulse timestamps it used, and each refuses to
produce output — with an explicit message — when no verified pulse is
available.

---

## How verification works

The chain serves signed pulses. Before a single byte reaches your code, the
client applies these gates to every consumed pulse:

| # | Gate | What it rejects |
|---|---|---|
| 1 | **RS256 signature** over the pulse's JWS, verified with stdlib RSA (`pow` + PKCS#1 v1.5 + SHA-256) against the RSA JWK published in the CURBy-Q chain descriptor | Any pulse not signed by the chain's key: tampered signatures, swapped signed payloads, `alg` other than `RS256` |
| 2 | **Chain CID** (`content.chain`) equals the discovered CURBy-Q chain CID | Pulses belonging to another chain |
| 3 | **Stage** is `randomness`, and the `randomness` field decodes to exactly 64 bytes (32 uint16 values) | Parameter/descriptor pulses and malformed payloads |
| 4 | **Bell-chain mixin** referencing the NIST Bell chain is present | Randomness pulses not committed to a Bell round |
| 5 | **Index continuity** along the walk: each fetched pulse's index is checked against the requested reference and is exactly one below the previous pulse | Spliced, reordered, or missing pulses |

The client also records the operator's `paramsHash` and `dataHash`
commitments, the per-pulse CID, the Bell mixin CID, round number and pulse
timestamp in provenance. Full re-extraction auditing of any round is possible
with CU's own verifier,
[`buff-beacon-project/curby_verify`](https://github.com/buff-beacon-project/curby_verify);
the provenance carries the round numbers and CIDs it needs.

If any gate fails, the fetch aborts and returns `[]`. Partial results are never
returned, and the cursor is not advanced, so a failure cannot silently consume
rounds.

### Provenance

`last_provenance()` describes the most recent successful fetch:

| Field | Meaning |
|---|---|
| `source`, `chain`, `specification` | `"CURBy quantum"`, `"CURBy-Q"`, `"twine/1.0.x/diqrng/1.0.x"` |
| `chain_cid`, `bell_chain_cid` | CIDs of the quantum chain and the NIST Bell chain it mixes in |
| `pulses` | Per-pulse record: `index`, `round`, `cid`, `timestamp`, `bell_mixin_cid`, `params_hash`, `data_hash`, `signature_rs256_verified`, `cid_recompute_match` |
| `rounds`, `pulse_timestamps` | The rounds and their timestamps, in the order consumed |
| `oldest_pulse_ts`, `newest_pulse_ts` | Age of the material actually used |
| `cursor_pass` | Wrap counter for the walk (stays `0` unless a wrap ever completes; a wrap mid-fetch is stopped by the continuity gate — see caveats) |
| `fetched_at`, `n_values` | When this fetch ran, and how many values it returned |

`last_error()` gives the human-readable reason whenever `fetch_curby()` returns
`[]`, and `last_provenance()` is `{}` in that case.

---

## Caveats — read these before relying on freshness

* **The DIQRNG chain has been dormant since 2025-08-22** because of a service
  relocation/upgrade. There are no new pulses. What you fetch is genuine,
  signed, **certified quantum** randomness, but it is **banked/historical**
  material, not fresh output. Every result carries its provenance
  timestamps (`last_provenance()["pulse_timestamps"]`, plus
  `oldest_pulse_ts` / `newest_pulse_ts`), so the age of the material is
  auditable and never hidden.
* **The classical CURBy-RNG chain is deliberately not used.** No code path in
  this project fetches `twine/1.0.x/rng/1.0.x`, and nothing here ever labels
  classical randomness as quantum.
* **The supply is finite.** The chain holds roughly 28k rounds, and the
  cursor only walks downward. A fetch that would wrap past the chain's first
  round trips the index-continuity gate and returns `[]` rather than silently
  re-reading rounds inside one result; a cursor already below the first index
  is reset to the latest round on the next call. Deleting `curby_cursor.json`
  (or pointing `CURBY_CURSOR_PATH` elsewhere) resets the walk from the top.
* **`parameters.isQuantum` reads `false` in every request pulse.** Read it in
  the device-independent sense: quantumness is not *assumed* by the requester,
  it is *certified* by the Bell-violation hypothesis test whose parameters the
  request commits to. The field name invites the opposite reading, so it is
  called out here.
* **Pulse CIDs are not independently recomputed.** Recomputing the CIDv1
  (DAG-CBOR, sha2-512) from the API's JSON rendering does not reproduce the
  served CIDs — Twine's canonical serialization evidently differs from the API
  JSON form. The client computes the recomputation diagnostically and reports
  `cid_recompute_match` in provenance; the authentication gate is the RS256
  signature, plus the structural checks above.
* **Certified entropy is not a substitute for a local CSPRNG.** For keys,
  tokens and anything requiring freshness, mix this material with a
  properly seeded local generator (e.g. `secrets`) rather than using it alone.
* **Unofficial client.** This project is not affiliated with or endorsed by CU
  Boulder, NIST, or the CURBy operators.

---

## Tests

The suite is offline — no network, stdlib `unittest` only. It builds minimal
fixture pulses in the chain's format, signs them with a throwaway local RSA key,
and checks that valid pulses are accepted while tampered signatures, wrong
keys, wrong chains, wrong stages, malformed lengths, missing Bell mixins and
broken index continuity all return `[]` with empty provenance.

```bash
python -m unittest discover -s tests -t . -v
```

## License

MIT — see [LICENSE](LICENSE). Copyright © Dr. Brent Allen Jensen.

## Credit

Built by **Dr. Brent Allen Jensen (Radical Blueprinting Research)**. The
underlying chain, Bell test and certification are the work of the CURBy team at
CU Boulder and NIST; see *Nature* (2025),
[doi:10.1038/s41586-025-09054-3](https://doi.org/10.1038/s41586-025-09054-3).
