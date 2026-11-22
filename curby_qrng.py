# ═══════════════════════════════════════════════════════════════════
#  CURBy-Q QUANTUM RANDOMNESS CLIENT
#  Source: CURBy (Colorado University Randomness Beacon, CU + NIST)
#  Chain:  "CURBy-Q" — twine/1.0.x/diqrng/1.0.x
#          Device-independent quantum randomness: 512 certified bits
#          per round, extracted from a loophole-free Bell test at
#          NIST Boulder (Nature, 2025, doi:10.1038/s41586-025-09054-3).
#
#  WHY THIS CHAIN AND NOT THE OTHERS (honesty notes):
#   * The CURBy *RNG* chain (twine/1.0.x/rng/1.0.x) is a CLASSICAL
#     NIST-style beacon. It is deliberately NOT used here — per
#     this project's standing rule, classical beacons are never dressed as
#     quantum. Only CURBy-Q (diqrng) pulses feed this client.
#   * The DIQRNG chain has been dormant since 2025-08-22 (service
#     relocation/upgrade). Its pulses are genuine, signed, certified
#     quantum randomness — but they are NOT fresh. Every fetch's
#     provenance records the exact pulse timestamps so the age of
#     the material is auditable, never hidden. A persistent cursor
#     walks the chain's 28k rounds so callers consume previously
#     unconsumed rounds instead of re-reading the same pulses.
#   * `parameters.isQuantum` reads False in every request pulse
#     (rounds 1..28297 sampled). Read in the device-independent
#     sense: quantumness is not *assumed* by the requester — it is
#     certified by the Bell-violation hypothesis test (PEFs) whose
#     parameters the request commits to. Flagged here because the
#     field name invites the opposite reading; the chain's own
#     descriptor names it the device-independent certified chain,
#     and every randomness pulse intertwines (mixin) the NIST Bell
#     chain pulse whose data it extracted from.
#
#  VERIFICATION PERFORMED ON EVERY CONSUMED PULSE (gating):
#   1. RS256 (RSA PKCS#1 v1.5 + SHA-256) signature over the pulse's
#      JWS verifies against the CURBy-Q chain's published RSA key
#      (JWK in the chain descriptor pulse). Stdlib-only RSA verify.
#   2. content.chain == the CURBy-Q chain CID; payload.stage ==
#      "randomness"; randomness decodes to exactly 64 bytes.
#   3. Index continuity along the walk (each fetched pulse's index
#      is exactly one less than the previous fetched pulse).
#   4. A mixin referencing the NIST Bell chain is present; its CID
#      is recorded (the raw-data commitment for the round).
#   paramsHash / dataHash from the signed payload are recorded in
#   provenance — they are the operator's commitments to the round's
#   parameters and Bell data. Full re-extraction auditing of any
#   round is possible with CU's own verifier
#   (github.com/buff-beacon-project/curby_verify); the provenance
#   below carries everything it needs (round numbers + CIDs).
#
#  KNOWN GAP (recorded, not hidden): recomputing the pulse CID
#  (CIDv1 dag-cbor, sha2-512) from the API's JSON rendering does
#  NOT reproduce the served CIDs under standard DAG-CBOR encoding
#  (tested: content-only, content+signature, multiple signature
#  forms, float-free chain descriptor included). Twine's canonical
#  serialization evidently differs from the API JSON form (its
#  radix link structure is the prime suspect). The client computes
#  the recomputation diagnostically and reports the mismatch in
#  provenance; verification gating rests on the RS256 signature —
#  the protocol's own authentication — plus the structural checks.
#
#  Interface:
#      fetch_curby(count=1024) -> list of uint16, [] on any failure
#      last_provenance()       -> dict describing the last fetch
#      CLI:  curby-qrng [-n N]  (console script; python -m curby_qrng)
#  Stdlib only. Python 3.11 (Q).
# ═══════════════════════════════════════════════════════════════════

import argparse
import base64
import hashlib
import json
import os
import ssl
import struct
import sys
import time
import urllib.request

API_BASE = "https://random.colorado.edu/api"
DIQRNG_SPEC = "twine/1.0.x/diqrng/1.0.x"
BELL_SPEC = "twine/1.0.x/bell/1.0.x"
USER_AGENT = "curby-qrng-client/1.0"
REQUEST_TIMEOUT = 20          # seconds per HTTP request
FETCH_BUDGET = 150            # soft seconds cap per fetch_curby call

_HERE = os.path.dirname(os.path.abspath(__file__))
CURSOR_PATH = os.environ.get("CURBY_CURSOR_PATH",
                             os.path.join(_HERE, "curby_cursor.json"))

_discovery = {"ts": 0.0, "chain_cid": None, "jwk": None, "bell_cid": None}
_last_provenance = {}
_last_error = None


def _ssl_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _get(path, timeout=REQUEST_TIMEOUT):
    req = urllib.request.Request(API_BASE + path,
                                 headers={"User-Agent": USER_AGENT,
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _b64url(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _b64any(s):
    s2 = s + "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s2)
    except Exception:
        return base64.urlsafe_b64decode(s2)


def _discover(force=False):
    """Find the CURBy-Q chain CID, its RSA JWK, and the Bell chain CID."""
    now = time.time()
    if (not force and _discovery["chain_cid"]
            and (now - _discovery["ts"]) < 3600):
        return _discovery
    chains = _get("/chains")
    chain_cid = jwk = bell_cid = None
    for ch in chains:
        content = ch.get("data", {}).get("content", {})
        spec = content.get("specification", "")
        if spec.endswith(DIQRNG_SPEC):
            chain_cid = ch["cid"]["/"]
            jwk = content.get("key")
        elif spec.endswith(BELL_SPEC):
            bell_cid = ch["cid"]["/"]
    if not chain_cid or not jwk:
        raise RuntimeError("CURBy-Q chain or its key not found in /api/chains")
    _discovery.update({"ts": now, "chain_cid": chain_cid,
                       "jwk": jwk, "bell_cid": bell_cid})
    return _discovery


_RSA_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _verify_rs256(jws, jwk):
    """Verify an RS256 JWS against an RSA JWK using stdlib only."""
    try:
        h_b64, p_b64, s_b64 = jws.split(".")
        header = json.loads(_b64url(h_b64))
        if header.get("alg") != "RS256":
            return False
        n = int.from_bytes(_b64url(jwk["n"]), "big")
        e = int.from_bytes(_b64url(jwk["e"]), "big")
        sig = int.from_bytes(_b64url(s_b64), "big")
        if sig >= n:
            return False
        em = pow(sig, e, n).to_bytes((n.bit_length() + 7) // 8, "big")
        digest = hashlib.sha256(f"{h_b64}.{p_b64}".encode()).digest()
        tail = b"\x00" + _RSA_DER_PREFIX + digest
        if not (em.startswith(b"\x00\x01") and em.endswith(tail)):
            return False
        # padding between header and tail must be all 0xFF
        pad = em[2:len(em) - len(tail)]
        return len(pad) >= 8 and all(b == 0xFF for b in pad)
    except Exception:
        return False


# ── diagnostic-only CID recomputation (see KNOWN GAP above) ────────
def _cbor_head(major, val):
    mt = major << 5
    if val < 24:
        return bytes([mt | val])
    if val < 256:
        return bytes([mt | 24, val])
    if val < 65536:
        return bytes([mt | 25]) + struct.pack(">H", val)
    if val < 4294967296:
        return bytes([mt | 26]) + struct.pack(">I", val)
    return bytes([mt | 27]) + struct.pack(">Q", val)


def _b32d(s):
    return base64.b32decode(s.upper() + "=" * ((8 - len(s) % 8) % 8))


def _is_link(o):
    return isinstance(o, dict) and set(o) == {"/"} and isinstance(o["/"], str)


def _is_bytes(o):
    return (isinstance(o, dict) and set(o) == {"/"}
            and isinstance(o["/"], dict) and set(o["/"]) == {"bytes"})


def _cbor_enc(o):
    if o is None:
        return b"\xf6"
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if isinstance(o, int):
        return _cbor_head(0, o) if o >= 0 else _cbor_head(1, -1 - o)
    if isinstance(o, float):
        return b"\xfb" + struct.pack(">d", o)
    if isinstance(o, str):
        b = o.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(o, (bytes, bytearray)):
        return _cbor_head(2, len(o)) + bytes(o)
    if isinstance(o, list):
        return _cbor_head(4, len(o)) + b"".join(_cbor_enc(x) for x in o)
    if _is_link(o):
        raw = _b32d(o["/"][1:])
        return b"\xd8\x2a" + _cbor_head(2, len(raw) + 1) + b"\x00" + raw
    if _is_bytes(o):
        raw = _b64any(o["/"]["bytes"])
        return _cbor_head(2, len(raw)) + raw
    if isinstance(o, dict):
        items = sorted(o.items(), key=lambda kv: _cbor_enc(kv[0]))
        return _cbor_head(5, len(o)) + b"".join(
            _cbor_enc(k) + _cbor_enc(v) for k, v in items)
    raise TypeError(type(o))


def _cid_recompute_match(pulse):
    """Diagnostic: does DAG-CBOR(sha2-512) of the served data match the
    served CID? Currently expected False — see KNOWN GAP in header."""
    try:
        digest = hashlib.sha512(_cbor_enc(pulse["data"])).digest()
        return _b32d(pulse["cid"]["/"][1:])[4:] == digest
    except Exception:
        return None


# ── cursor ──────────────────────────────────────────────────────────
def _load_cursor():
    try:
        with open(CURSOR_PATH, "r", encoding="utf-8") as f:
            c = json.load(f)
        return {"next_index": c.get("next_index"), "pass": int(c.get("pass", 0))}
    except Exception:
        return {"next_index": None, "pass": 0}


def _save_cursor(cursor):
    tmp = CURSOR_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cursor, f)
    os.replace(tmp, CURSOR_PATH)


def _get_pulse(chain_cid, ref):
    return _get(f"/chains/{chain_cid}/pulses/{ref}")


def fetch_curby(count: int = 1024) -> list:
    """
    Fetch `count` uint16 values extracted from verified CURBy-Q
    (device-independent quantum) randomness pulses.

    Walks the chain downward from a persistent cursor so successive
    calls consume previously unconsumed rounds. Returns [] on ANY
    failure or verification mismatch — the caller must fall back
    (and label) honestly rather than consume unverified data.
    Provenance for the fetch is available via last_provenance().
    """
    global _last_provenance, _last_error
    _last_provenance = {}
    _last_error = None
    started = time.time()
    try:
        disc = _discover()
        chain_cid, jwk, bell_cid = disc["chain_cid"], disc["jwk"], disc["bell_cid"]

        latest = _get_pulse(chain_cid, "latest")
        latest_index = latest["data"]["content"]["index"]

        cursor = _load_cursor()
        idx = cursor["next_index"]
        if idx is None or idx > latest_index or idx < 1:
            idx = latest_index
        pass_no = cursor["pass"]

        need_pulses = (count * 2 + 63) // 64   # 64 bytes -> 32 uint16 each
        collected = []                          # list of (pulse, raw_bytes)
        prev_index = None
        while len(collected) < need_pulses:
            if time.time() - started > FETCH_BUDGET:
                raise RuntimeError("fetch budget exceeded")
            if idx < 1:
                # wrapped the whole chain: start again from the top
                idx = latest_index
                pass_no += 1
            pulse = _get_pulse(chain_cid, idx)
            content = pulse["data"]["content"]
            if content.get("index") != idx:
                raise RuntimeError(f"index mismatch at {idx}")
            if prev_index is not None and idx != prev_index - 1:
                raise RuntimeError("walk lost index continuity")
            prev_index = idx
            idx -= 1
            payload = content.get("payload", {})
            if payload.get("stage") != "randomness":
                continue
            # ── gating verification ──
            if content.get("chain", {}).get("/") != chain_cid:
                raise RuntimeError("pulse chain CID mismatch")
            if not _verify_rs256(pulse["data"]["signature"], jwk):
                raise RuntimeError(f"RS256 verification FAILED at index "
                                   f"{content['index']} — refusing pulse")
            raw = _b64any(payload["randomness"]["/"]["bytes"])
            if len(raw) != 64:
                raise RuntimeError("randomness field is not 64 bytes")
            bell_mixin = None
            for mx in content.get("mixins", []):
                if mx.get("chain", {}).get("/") == bell_cid:
                    bell_mixin = mx.get("value", {}).get("/")
            if bell_cid and not bell_mixin:
                raise RuntimeError("no Bell-chain mixin in randomness pulse")
            collected.append((pulse, raw, bell_mixin))

        _save_cursor({"next_index": idx, "pass": pass_no})

        values = []
        pulses_meta = []
        for pulse, raw, bell_mixin in collected:
            values.extend(struct.unpack(">32H", raw))
            content = pulse["data"]["content"]
            payload = content["payload"]
            pulses_meta.append({
                "index": content["index"],
                "round": payload.get("round"),
                "cid": pulse["cid"]["/"],
                "timestamp": payload.get("timestamp"),
                "bell_mixin_cid": bell_mixin,
                "params_hash": payload.get("paramsHash"),
                "data_hash": payload.get("dataHash"),
                "signature_rs256_verified": True,
                "cid_recompute_match": _cid_recompute_match(pulse),
            })
        _last_provenance = {
            "source": "CURBy quantum",
            "chain": "CURBy-Q",
            "specification": DIQRNG_SPEC,
            "chain_cid": chain_cid,
            "bell_chain_cid": bell_cid,
            "cursor_pass": pass_no,
            "pulses": pulses_meta,
            "rounds": [p["round"] for p in pulses_meta],
            "pulse_timestamps": [p["timestamp"] for p in pulses_meta],
            "newest_pulse_ts": max(p["timestamp"] for p in pulses_meta),
            "oldest_pulse_ts": min(p["timestamp"] for p in pulses_meta),
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_values": len(values[:count]),
        }
        return values[:count]
    except Exception as e:
        _last_error = f"{type(e).__name__}: {e}"
        return []


def last_provenance() -> dict:
    """Provenance of the most recent fetch_curby call ({} if none)."""
    return dict(_last_provenance)


def last_error():
    return _last_error


def cli(argv=None) -> int:
    """Command-line entry point: fetch N verified uint16 values.

    Prints the values and their provenance (rounds and pulse timestamps).
    Returns 0 on success, 1 when no verified pulse could be obtained — in
    which case nothing is printed as randomness.
    """
    parser = argparse.ArgumentParser(
        prog="curby-qrng",
        description=(
            "Fetch N uint16 values from the CURBy-Q chain "
            "(twine/1.0.x/diqrng/1.0.x): device-independent certified "
            "quantum randomness. Every value comes from an RS256-verified "
            "pulse; if no verified pulse is available, nothing is output."
        ),
    )
    parser.add_argument("-n", "--count", type=int, default=16, metavar="N",
                        help="number of uint16 values to print (default: 16)")
    args = parser.parse_args(argv)
    if args.count < 1:
        parser.error("N must be at least 1")

    values = fetch_curby(args.count)
    if not values:
        print("No verified CURBy-Q pulses available: refusing to print "
              "randomness.", file=sys.stderr)
        print(f"reason: {last_error() or 'unknown error'}", file=sys.stderr)
        return 1

    prov = last_provenance()
    print(f"{len(values)} uint16 values from CURBy-Q certified quantum "
          f"randomness (every pulse RS256-verified)")
    for start in range(0, len(values), 16):
        print("  " + " ".join(str(v) for v in values[start:start + 16]))
    print(f"chain: {prov['chain']} ({prov['specification']})")
    print(f"chain CID: {prov['chain_cid']}")
    print("rounds: " + ", ".join(str(r) for r in prov["rounds"]))
    print("pulse timestamps: "
          + ", ".join(str(t) for t in prov["pulse_timestamps"]))
    print(f"pulses used: {len(prov['pulses'])}; oldest "
          f"{prov['oldest_pulse_ts']}; newest {prov['newest_pulse_ts']}")
    print(f"cursor pass: {prov['cursor_pass']}; fetched at {prov['fetched_at']}")
    print("note: the DIQRNG chain has been dormant since 2025-08-22 — these "
          "are banked, signed certified pulses, not fresh output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
