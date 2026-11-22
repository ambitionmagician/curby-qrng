"""Offline fixtures: minimal CURBy-Q pulses and a throwaway RSA test key.

Nothing in this module touches the network. The RSA key below was generated
once for this test suite only; it signs fixture pulses and is never used by
the client itself.
"""

from __future__ import annotations

import base64
import hashlib
import json

# ── throwaway 2048-bit RSA test key (test-only; not a production key) ──
_N = int(
    "8ce3b04db40aeb3fdede88b6bfef3ae07c2f5eff6a73cd36c13e8a5f208a0368"
    "a0569f62b0b095e8064a954e2161ff762d2b8996666bc97219e37d2795868f3a"
    "5c6f3932c8a1d56b311ef938941f5b771d0da07042acd64228194e0049ca9ca6"
    "14558516a95fed9f827ee94dfa58270f5c50067659612386ccb1cd8854d586db"
    "8958b9d1bc02a8cb8f4659c448cc834e164f618902135a767f52fc16a9356266"
    "052a1de861afd7dc764f8b9986bbe94b26c62b8987cf4ccc4d13656f4c3bbfa1"
    "12c43f28d3cc068c947ddf28c10bcc112c24e136ba44c667c440ce2a724b709b"
    "0102a925a58259ce1e0eff381c566d43d95c32c0e7fbfe90e840b4e913e9ac3b",
    16,
)
_E = 65537
_D = int(
    "71f8deee7cef384f7ae35a853bcf3339d63c1c0553004aca389977266d14389d"
    "b2d760285df6fbcdaf0936aef5a2691e187c57d92b1196ec8eb4d0d1eccbe5a1"
    "b894e1188be51ed88fec168006933752ac5611abbec442af51f0e680a5311a77d"
    "f8b2f169dfdd4246d546d377f854053d4c187f8c56527702cb6c925b83ae3d41"
    "0d955aef46015162abfe821def37965931deed55db3cec637052889a4287cdcc"
    "7a189c0ecfab467c39099ac2a2945c1c1ec971e1024dccaf080931db59bbdf6f"
    "77eb0282aed6b9cbaab68431e2a82b02705131069e3b9945b550b981a29d3668"
    "31b133d9c99c38f0891419d7f592c432f0cafefc57400c8344a7af2f2afd201",
    16,
)
KEY_BYTES = 256
_RSA_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def b64u(raw: bytes) -> str:
    """Unpadded URL-safe base64, as used by JWS and JWK fields."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64std(raw: bytes) -> str:
    """Standard padded base64, as used by the API for byte fields."""
    return base64.b64encode(raw).decode("ascii")


def _cid(label: str) -> str:
    """A realistic-looking CIDv1 string derived from a label."""
    digest = hashlib.sha256(label.encode("utf-8")).digest()
    raw = b"\x01\x55\x12\x20" + digest  # cidv1 + raw + sha2-256 + length
    return "b" + base64.b32encode(raw).decode("ascii").rstrip("=").lower()


CHAIN_CID = _cid("curby-q-diqrng-chain")
BELL_CID = _cid("nist-bell-chain")
OTHER_CID = _cid("some-other-chain")


def jwk() -> dict:
    """The public JWK the client should verify against."""
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": b64u(_N.to_bytes(KEY_BYTES, "big")),
        "e": b64u(_E.to_bytes(3, "big")),
    }


def wrong_jwk() -> dict:
    """A key that was never used to sign the fixtures."""
    blob = hashlib.sha512(b"not-the-key").digest() * 4  # 256 bytes
    other = int.from_bytes(blob, "big") | (1 << 2047) | 1
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": b64u(other.to_bytes(KEY_BYTES, "big")),
        "e": b64u(_E.to_bytes(3, "big")),
    }


def sign_rs256(payload: bytes, header: dict | None = None) -> str:
    """Produce an RS256 JWS (PKCS#1 v1.5, SHA-256) with the fixture key."""
    header = {"alg": "RS256", "typ": "JWT"} if header is None else header
    h = b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    p = b64u(payload)
    digest = hashlib.sha256(f"{h}.{p}".encode("ascii")).digest()
    tail = b"\x00" + _RSA_DER_PREFIX + digest
    ps = b"\xff" * (KEY_BYTES - 2 - len(tail))
    em = b"\x00\x01" + ps + tail
    assert len(em) == KEY_BYTES
    sig = pow(int.from_bytes(em, "big"), _D, _N)
    return f"{h}.{p}." + b64u(sig.to_bytes(KEY_BYTES, "big"))


def corrupt_signature(jws: str) -> str:
    """Flip one bit of the signature: a tampered token."""
    h, p, s = jws.split(".")
    raw = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
    raw[-1] ^= 0x01
    return f"{h}.{p}.{b64u(bytes(raw))}"


def repayload(jws: str, payload: bytes) -> str:
    """Swap the signed payload while keeping the old signature."""
    h, _p, s = jws.split(".")
    return f"{h}.{b64u(payload)}.{s}"


def pulse_randomness(index: int) -> bytes:
    """Deterministic 64 bytes standing in for one round's extracted bits."""
    return hashlib.sha512(f"randomness-{index}".encode()).digest()


def build_pulse(
    index: int,
    *,
    chain_cid: str = CHAIN_CID,
    bell_cid: str | None = BELL_CID,
    stage: str = "randomness",
    randomness: bytes | None = None,
    round_no: int | None = None,
    timestamp: str | None = None,
    mixins: list | None = None,
    header: dict | None = None,
    jws_payload: bytes | None = None,
) -> dict:
    """Build one minimal pulse in the chain's served JSON shape."""
    if randomness is None:
        randomness = pulse_randomness(index)
    payload = {
        "stage": stage,
        "round": index if round_no is None else round_no,
        "timestamp": timestamp or f"2025-08-22T00:00:{index % 60:02d}Z",
        "randomness": {"/": {"bytes": b64std(randomness)}},
        "paramsHash": "sha256-" + b64u(hashlib.sha256(b"params").digest()),
        "dataHash": "sha256-" + b64u(hashlib.sha256(b"bell-data").digest()),
    }
    if mixins is None:
        mixins = (
            [{"chain": {"/": bell_cid}, "value": {"/": _cid(f"bell-{index}")}}]
            if bell_cid
            else []
        )
    content = {
        "index": index,
        "chain": {"/": chain_cid},
        "payload": payload,
        "mixins": mixins,
    }
    body = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    signature = sign_rs256(body if jws_payload is None else jws_payload, header)
    return {
        "cid": {"/": _cid(f"pulse-{index}")},
        "data": {"content": content, "signature": signature},
    }


def discovery(jwk_override: dict | None = None) -> dict:
    """The cached discovery record the client would have built from /chains."""
    return {
        "ts": 0.0,
        "chain_cid": CHAIN_CID,
        "jwk": jwk_override if jwk_override is not None else jwk(),
        "bell_cid": BELL_CID,
    }


class FakeAPI:
    """Serves fixture pulses through the client's ``_get`` seam."""

    def __init__(self, pulses, latest_index=None, chain_cid=CHAIN_CID):
        self.pulses = {p["data"]["content"]["index"]: p for p in pulses}
        self.overrides = {}
        self.latest_index = (
            latest_index if latest_index is not None else max(self.pulses)
        )
        self.chain_cid = chain_cid
        self.paths = []
        self.failure = None

    def serve_at(self, ref: int, pulse: dict) -> None:
        """Serve ``pulse`` when ``ref`` is requested (to splice the chain)."""
        self.overrides[ref] = pulse

    def get(self, path: str, timeout=None):
        self.paths.append(path)
        if self.failure is not None:
            raise self.failure
        prefix = f"/chains/{self.chain_cid}/pulses/"
        if not path.startswith(prefix):
            raise AssertionError(f"unexpected request path: {path!r}")
        ref = path[len(prefix):]
        if ref == "latest":
            return self.pulses[self.latest_index]
        ref = int(ref)
        if ref in self.overrides:
            return self.overrides[ref]
        return self.pulses[ref]
