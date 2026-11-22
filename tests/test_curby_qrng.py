"""Offline unit tests for curby-qrng: no network, stdlib unittest only.

Run from the repository root:

    python -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from unittest import mock

import curby_qrng
from curby_qrng import _verify_rs256, cli, fetch_curby, last_error, last_provenance
from tests import fixtures


class Harness(unittest.TestCase):
    """Patches the client's two seams (discovery and HTTP) and its cursor."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cursor_path = os.path.join(tmp.name, "curby_cursor.json")
        self._patch("CURSOR_PATH", self.cursor_path)
        self._patch("_discover", lambda force=False: fixtures.discovery())

    def _patch(self, name, value):
        patcher = mock.patch.object(curby_qrng, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, pulses, latest_index=None):
        api = fixtures.FakeAPI(pulses, latest_index=latest_index)
        self._patch("_get", api.get)
        self.api = api
        return api


class SignatureGateTest(Harness):
    def test_verifier_accepts_valid_rs256_jws(self):
        jws = fixtures.sign_rs256(b'{"stage":"randomness"}')
        self.assertTrue(_verify_rs256(jws, fixtures.jwk()))

    def test_verifier_rejects_tampered_signature(self):
        jws = fixtures.sign_rs256(b'{"stage":"randomness"}')
        self.assertFalse(_verify_rs256(fixtures.corrupt_signature(jws),
                                       fixtures.jwk()))

    def test_verifier_rejects_swapped_signed_payload(self):
        jws = fixtures.sign_rs256(b'{"stage":"randomness"}')
        forged = fixtures.repayload(jws, b'{"stage":"params"}')
        self.assertFalse(_verify_rs256(forged, fixtures.jwk()))

    def test_verifier_rejects_wrong_algorithm_and_garbage(self):
        jws = fixtures.sign_rs256(b"{}", header={"alg": "HS256", "typ": "JWT"})
        self.assertFalse(_verify_rs256(jws, fixtures.jwk()))
        for junk in ("", "not-a-jws", "a.b", "a.b.c"):
            with self.subTest(jws=junk):
                self.assertFalse(_verify_rs256(junk, fixtures.jwk()))

    def test_fetch_accepts_a_valid_signed_pulse(self):
        raw = bytes(range(64))
        self.serve([fixtures.build_pulse(7, randomness=raw)])
        self.assertEqual(fetch_curby(4), list(struct.unpack(">32H", raw))[:4])

        prov = last_provenance()
        self.assertEqual(prov["chain"], "CURBy-Q")
        self.assertEqual(prov["specification"], "twine/1.0.x/diqrng/1.0.x")
        self.assertEqual(prov["chain_cid"], fixtures.CHAIN_CID)
        self.assertEqual(prov["bell_chain_cid"], fixtures.BELL_CID)
        self.assertEqual(prov["rounds"], [7])
        self.assertEqual(prov["pulse_timestamps"], ["2025-08-22T00:00:07Z"])
        self.assertTrue(prov["pulses"][0]["signature_rs256_verified"])
        self.assertEqual(prov["pulses"][0]["cid"], fixtures._cid("pulse-7"))
        self.assertEqual(prov["n_values"], 4)

    def test_fetch_rejects_tampered_signature(self):
        pulse = fixtures.build_pulse(9)
        pulse["data"]["signature"] = fixtures.corrupt_signature(
            pulse["data"]["signature"])
        self.serve([pulse])

        self.assertEqual(fetch_curby(4), [])
        self.assertEqual(last_provenance(), {})
        self.assertIn("RS256", last_error())

    def test_fetch_rejects_pulse_signed_by_a_key_we_did_not_publish(self):
        self._patch("_discover",
                    lambda force=False: fixtures.discovery(fixtures.wrong_jwk()))
        self.serve([fixtures.build_pulse(9)])

        self.assertEqual(fetch_curby(4), [])
        self.assertIn("RS256", last_error())


class StructuralGateTest(Harness):
    def test_foreign_chain_cid_returns_empty(self):
        self.serve([fixtures.build_pulse(3, chain_cid=fixtures.OTHER_CID)])
        self.assertEqual(fetch_curby(4), [])
        self.assertIn("chain CID mismatch", last_error())

    def test_non_randomness_stage_pulses_are_skipped(self):
        raw = bytes(range(64))
        params = fixtures.build_pulse(11, stage="params")
        quantum = fixtures.build_pulse(10, randomness=raw)
        self.serve([params, quantum], latest_index=11)

        values = fetch_curby(4)
        self.assertEqual(values, list(struct.unpack(">32H", raw))[:4])
        prov = last_provenance()
        self.assertEqual([p["index"] for p in prov["pulses"]], [10])
        self.assertEqual(prov["rounds"], [10])

    def test_short_randomness_field_returns_empty(self):
        self.serve([fixtures.build_pulse(4, randomness=b"\x00" * 63)])
        self.assertEqual(fetch_curby(4), [])
        self.assertIn("not 64 bytes", last_error())

    def test_missing_bell_mixin_returns_empty(self):
        self.serve([fixtures.build_pulse(4, mixins=[])])
        self.assertEqual(fetch_curby(4), [])
        self.assertIn("Bell-chain mixin", last_error())

    def test_failure_returns_empty_provenance_and_reason(self):
        self.serve([], latest_index=0)  # nothing on the chain
        self.assertEqual(fetch_curby(4), [])
        self.assertEqual(last_provenance(), {})
        self.assertIsNotNone(last_error())


class ContinuityTest(Harness):
    def test_walk_requests_strictly_consecutive_indices(self):
        self.serve([fixtures.build_pulse(2), fixtures.build_pulse(1)])
        fetch_curby(33)
        prefix = f"/chains/{fixtures.CHAIN_CID}/pulses/"
        self.assertEqual(self.api.paths, [
            prefix + "latest",
            prefix + "2",
            prefix + "1",
        ])

    def test_multiple_pulses_fill_exactly_count_values(self):
        first = bytes(range(64))
        second = bytes(range(64, 128))
        self.serve([fixtures.build_pulse(2, randomness=first),
                    fixtures.build_pulse(1, randomness=second)])

        values = fetch_curby(33)
        self.assertEqual(len(values), 33)
        self.assertEqual(values[:32], list(struct.unpack(">32H", first)))
        self.assertEqual(values[32], struct.unpack(">32H", second)[0])
        prov = last_provenance()
        self.assertEqual([p["index"] for p in prov["pulses"]], [2, 1])
        self.assertEqual(prov["n_values"], 33)
        self.assertEqual(prov["oldest_pulse_ts"], "2025-08-22T00:00:01Z")
        self.assertEqual(prov["newest_pulse_ts"], "2025-08-22T00:00:02Z")

    def test_spliced_pulse_breaks_the_walk(self):
        api = self.serve([fixtures.build_pulse(10)])
        api.serve_at(9, fixtures.build_pulse(7))  # served ref 9 claims index 7

        self.assertEqual(fetch_curby(33), [])
        self.assertIn("index mismatch", last_error())

    def test_missing_pulse_breaks_the_walk(self):
        self.serve([fixtures.build_pulse(10)])  # index 9 is absent
        self.assertEqual(fetch_curby(33), [])
        self.assertIn("KeyError", last_error())

    def test_wrap_trips_the_continuity_gate(self):
        # Reaching the chain's first round mid-fetch must not silently
        # re-read rounds: the continuity gate aborts the whole fetch.
        self.serve([fixtures.build_pulse(1), fixtures.build_pulse(2)],
                   latest_index=2)

        self.assertEqual(fetch_curby(65), [])
        self.assertIn("continuity", last_error())
        self.assertFalse(os.path.exists(self.cursor_path))

    def test_cursor_advances_only_after_a_verified_fetch(self):
        pulse = fixtures.build_pulse(5)
        pulse["data"]["signature"] = fixtures.corrupt_signature(
            pulse["data"]["signature"])
        self.serve([pulse])

        self.assertEqual(fetch_curby(4), [])
        self.assertFalse(os.path.exists(self.cursor_path))

    def test_successful_fetch_saves_cursor(self):
        self.serve([fixtures.build_pulse(5)])
        self.assertEqual(len(fetch_curby(4)), 4)
        with open(self.cursor_path, encoding="utf-8") as f:
            cursor = json.load(f)
        self.assertEqual(cursor, {"next_index": 4, "pass": 0})


class CliTest(Harness):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli(argv)
        return code, out.getvalue(), err.getvalue()

    def test_cli_prints_values_and_provenance(self):
        self.serve([fixtures.build_pulse(42, randomness=bytes(range(64)))])
        code, out, err = self.run_cli(["-n", "3"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("1 515 1029", out)
        self.assertIn("rounds: 42", out)
        self.assertIn("2025-08-22T00:00:42Z", out)
        self.assertIn("dormant since 2025-08-22", out)

    def test_cli_refuses_without_verified_pulses(self):
        api = self.serve([fixtures.build_pulse(3)])
        api.failure = OSError("network down")

        code, out, err = self.run_cli(["-n", "3"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("refusing", err.lower())
        self.assertIn("OSError: network down", err)

    def test_cli_rejects_nonpositive_count(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                cli(["-n", "0"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
