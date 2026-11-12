"""Offline tests for verify.py — no network, ever.

Fixtures (all public data):

* ``fixtures/2026-10-04.jsonl``, ``.jsonl.ots``, ``.jsonl.btc.ots`` — one real
  forecast day (18 leaves: 18 -> 9 -> 5 -> 3 -> 2 -> 1, three odd Merkle
  levels) downloaded from https://football.vhristov.com/api/ledger/ on
  2026-10-09;
* ``fixtures/explorers/2026-10-04.json`` — the sixteen explorer responses
  (``block-height/<h>`` and ``block/<hash>/header`` from mempool.space and
  blockstream.info for the proof's four Bitcoin heights), recorded the same
  day by running verify.py once against the network;
* ``fixtures/facts-erratum-2026-08-26.jsonl`` (66 ``entries``) — one more real
  record, for the erratum's field name.

Every test passes its own ``fetch``; ``verify.http_get`` is replaced for the
whole run by a function that fails the test, so an accidental network call
is a red test rather than a silent dependency.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import verify  # noqa: E402

FIX = HERE / "fixtures"
DAY = "2026-10-04"
RECORD = (FIX / f"{DAY}.jsonl").read_bytes()
BTC_PROOF = (FIX / f"{DAY}.jsonl.btc.ots").read_bytes()
CAL_PROOF = (FIX / f"{DAY}.jsonl.ots").read_bytes()
EXPLORER = {
    k: v.encode("ascii")
    for k, v in json.loads((FIX / "explorers" / f"{DAY}.json").read_text()).items()
}
SITE = "https://football.vhristov.com/api/ledger"
HEIGHTS = {969792, 969796, 969803, 969969}
ROOT = "0956c27dca16834b95cdfa92647a5e19034e9c0b6b8b5391318f08f8bb59f6b0"


def _no_network(url: str) -> bytes:
    raise AssertionError(f"test tried the network: {url}")


# The real downloader, kept for the tests that drive it with a fake opener.
REAL_HTTP_GET = verify.http_get
verify.http_get = _no_network  # type: ignore[assignment]


def recorded(overrides: dict[str, bytes] | None = None):
    """A fetcher over the recorded responses (+ the site's files), with overrides."""
    table = dict(EXPLORER)
    table[f"{SITE}/{DAY}.jsonl"] = RECORD
    table[f"{SITE}/{DAY}.jsonl.btc.ots"] = BTC_PROOF
    table.update(overrides or {})
    calls: list[str] = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        if url not in table:
            raise verify.Undecided(f"GET {url}: not recorded (offline)")
        return table[url]

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def run(inputs: verify.Inputs, fetch=None, skip_bitcoin: bool = False) -> tuple[int, str]:
    lines: list[str] = []
    code = verify.verify(
        inputs, fetch=fetch or recorded(), skip_bitcoin=skip_bitcoin, out=lines.append
    )
    return code, "\n".join(lines)


def inputs(record: bytes = RECORD, proof: bytes = BTC_PROOF) -> verify.Inputs:
    return verify.Inputs(record, proof, f"{DAY}.jsonl", f"{DAY}.jsonl.btc.ots")


def reforge(record: bytes) -> bytes:
    """Change one probability AND recompute its commitment and the root.

    The result is a perfectly self-consistent record — only the timestamp
    proof can tell it from the original.
    """
    rec = json.loads(record.decode().split("\n", 1)[0])
    leaf = rec["leaves"][1]
    leaf["canonical_json"] = leaf["canonical_json"].replace("0.5378453686", "0.5378453687")
    assert leaf["canonical_json"] != json.loads(record.decode())["leaves"][1]["canonical_json"]
    leaf["commitment"] = hashlib.sha256(leaf["canonical_json"].encode()).hexdigest()
    rec["root"] = verify.merkle_root([bytes.fromhex(x["commitment"]) for x in rec["leaves"]]).hex()
    return (json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n").encode()


def header_url(base: str, block_hash: str) -> str:
    return f"{base}/block/{block_hash}/header"


def height_url(base: str, height: int) -> str:
    return f"{base}/block-height/{height}"


def both(fn):
    """The same override for both explorers."""
    out: dict[str, bytes] = {}
    for _, base in verify.EXPLORERS:
        out.update(fn(base))
    return out


class MerkleTests(unittest.TestCase):
    def test_empty_is_sha256_of_nothing(self) -> None:
        self.assertEqual(verify.merkle_root([]), hashlib.sha256(b"").digest())

    def test_single_leaf_is_its_own_root(self) -> None:
        self.assertEqual(verify.merkle_root([b"\x01" * 32]), b"\x01" * 32)

    def test_odd_level_duplicates_the_last_node(self) -> None:
        a, b, c = (bytes([i]) * 32 for i in (1, 2, 3))
        h = verify.sha256
        self.assertEqual(verify.merkle_root([a, b, c]), h(h(a + b) + h(c + c)))


class RecordTests(unittest.TestCase):
    def test_real_day_is_self_consistent(self) -> None:
        check = verify.check_record(RECORD)
        # 18 leaves: 18 -> 9 -> 5 -> 3 -> 2 -> 1, three odd levels.
        self.assertEqual((check.root, check.n_leaves), (ROOT, 18))

    def test_header_count_must_match_the_leaves(self) -> None:
        bad = RECORD.replace(b'"n":18,', b'"n":17,')
        self.assertNotEqual(bad, RECORD)
        with self.assertRaisesRegex(verify.VerifyFailed, "n = 17"):
            verify.check_record(bad)

    def test_real_erratum_uses_entries_not_leaves(self) -> None:
        # The §7.5 erratum: 66 entries (odd levels), same rules, other key.
        data = (FIX / "facts-erratum-2026-08-26.jsonl").read_bytes()
        check = verify.check_record(data)
        self.assertEqual(check.n_leaves, 66)
        self.assertEqual(check.root, json.loads(data)["root"])

    def test_changed_leaf_without_new_commitment_fails(self) -> None:
        bad = RECORD.replace(b"0.5378453686", b"0.5378453687")
        with self.assertRaisesRegex(verify.VerifyFailed, "leaf 1"):
            verify.check_record(bad)

    def test_changed_root_fails(self) -> None:
        bad = RECORD.replace(ROOT.encode(), (("1" if ROOT[0] == "0" else "0") + ROOT[1:]).encode())
        self.assertNotEqual(bad, RECORD)
        with self.assertRaisesRegex(verify.VerifyFailed, "Merkle root"):
            verify.check_record(bad)

    def test_not_a_record_is_undecided(self) -> None:
        for data in (b"not json", b'{"leaves": []}', b"\xff\xfe", b'{"leaves": 3, "root": "x"}'):
            with self.subTest(data=data), self.assertRaises(verify.Undecided):
                verify.check_record(data)
        with self.assertRaises(verify.Undecided):
            verify.check_record(b'{"leaves": [{"canonical_json": "x"}], "root": "r"}')


class ProofParsingTests(unittest.TestCase):
    def test_btc_proof_commits_to_the_file_and_names_three_blocks(self) -> None:
        proof = verify.parse_proof(BTC_PROOF)
        self.assertEqual(proof.file_digest, hashlib.sha256(RECORD).digest())
        self.assertEqual({a.height for a in proof.attestations if a.kind == "bitcoin"}, HEIGHTS)
        self.assertEqual(sum(a.kind == "pending" for a in proof.attestations), 4)

    def test_calendar_proof_has_no_bitcoin_attestation(self) -> None:
        proof = verify.parse_proof(CAL_PROOF)
        self.assertEqual(proof.file_digest, hashlib.sha256(RECORD).digest())
        self.assertEqual({a.kind for a in proof.attestations}, {"pending"})

    def test_malformed_proofs_are_undecided(self) -> None:
        magic = verify.OTS_MAGIC
        cases = {
            "bad magic": b"\x01" + BTC_PROOF[1:],
            "truncated": BTC_PROOF[:-5],
            "trailing bytes": BTC_PROOF + b"\x00",
            "version 2": magic + b"\x02" + BTC_PROOF[len(magic) + 1 :],
            "not sha256": magic + b"\x01\x02" + BTC_PROOF[len(magic) + 2 :],
            "unknown op": magic + b"\x01\x08" + b"\x00" * 32 + b"\x99",
            "oversized arg": magic + b"\x01\x08" + b"\x00" * 32 + b"\xf0\xff\xff\x01",
        }
        for name, data in cases.items():
            with self.subTest(name), self.assertRaises(verify.Undecided):
                verify.parse_proof(data)

    def test_unknown_attestation_is_kept_not_trusted(self) -> None:
        data = verify.OTS_MAGIC + b"\x01\x08" + b"\x00" * 32 + b"\x00" + b"\x11" * 8 + b"\x01\x00"
        (att,) = verify.parse_proof(data).attestations
        self.assertEqual(att.kind, "unknown")
        code, out = run(inputs(proof=data.replace(b"\x00" * 32, hashlib.sha256(RECORD).digest())))
        self.assertEqual(code, verify.EXIT_UNDECIDED)
        self.assertIn("unknown attestation", out)

    def test_varuint_is_little_endian_base_128(self) -> None:
        self.assertEqual(verify._Reader(b"\xe5\x8e\x26").varuint(), 624485)
        with self.assertRaises(verify.Undecided):
            verify._Reader(b"\xff" * 10 + b"\x01").varuint()


class BitcoinTests(unittest.TestCase):
    def test_real_day_verifies_with_both_explorers(self) -> None:
        fetch = recorded()
        code, out = run(inputs(), fetch)
        self.assertEqual(code, verify.EXIT_OK, out)
        self.assertIn("no later than about 2026-10-04 03:21:23 UTC (block 969792)", out)
        # A block time is miner-set: the output must not present it as exact.
        self.assertIn("approximate, roughly +/- 2 hours", out)
        self.assertIn("time ~2026-10-04 03:21:23 UTC", out)
        for h in HEIGHTS:
            self.assertIn(f"Bitcoin block {h} ", out)
        hosts = {u.split("/")[2] for u in fetch.calls}  # type: ignore[attr-defined]
        self.assertEqual(hosts, {"mempool.space", "blockstream.info"})

    def test_reforged_record_is_caught_by_the_proof(self) -> None:
        forged = reforge(RECORD)
        verify.check_record(forged)  # self-consistent on its own …
        code, out = run(inputs(record=forged))  # … but not the file the proof is for
        self.assertEqual(code, verify.EXIT_FAILED, out)
        self.assertIn("not for this file", out)

    def test_explorers_disagreeing_is_undecided(self) -> None:
        other = EXPLORER[height_url("https://mempool.space/api", 969796)]
        fetch = recorded({height_url("https://blockstream.info/api", 969792): other})
        code, out = run(inputs(), fetch)
        self.assertEqual(code, verify.EXIT_UNDECIDED, out)
        self.assertIn("disagree", out)

    def test_wrong_block_with_valid_header_fails_on_merkle_root(self) -> None:
        # Both explorers answer height 969792 with the (real, valid) block 969796.
        wrong_hash = EXPLORER[height_url("https://mempool.space/api", 969796)]
        wrong_header = EXPLORER[header_url("https://mempool.space/api", wrong_hash.decode())]
        fetch = recorded(
            both(
                lambda base: {
                    height_url(base, 969792): wrong_hash,
                    header_url(base, wrong_hash.decode()): wrong_header,
                }
            )
        )
        code, out = run(inputs(), fetch)
        self.assertEqual(code, verify.EXIT_FAILED, out)
        self.assertIn("Merkle root", out)

    def test_header_not_hashing_to_the_reported_hash_fails(self) -> None:
        good_hash = EXPLORER[height_url("https://mempool.space/api", 969792)].decode()
        raw = bytearray.fromhex(
            EXPLORER[header_url("https://mempool.space/api", good_hash)].decode()
        )
        raw[0] ^= 1
        fetch = recorded(both(lambda base: {header_url(base, good_hash): raw.hex().encode()}))
        code, out = run(inputs(), fetch)
        self.assertEqual(code, verify.EXIT_FAILED, out)
        self.assertIn("hashes to", out)

    def test_header_without_proof_of_work_fails(self) -> None:
        good_hash = EXPLORER[height_url("https://mempool.space/api", 969792)].decode()
        raw = bytearray.fromhex(
            EXPLORER[header_url("https://mempool.space/api", good_hash)].decode()
        )
        raw[72:76] = (0x03000001).to_bytes(4, "little")  # target = 1
        forged_hash = verify.sha256d(bytes(raw))[::-1].hex()
        fetch = recorded(
            both(
                lambda base: {
                    height_url(base, 969792): forged_hash.encode(),
                    header_url(base, forged_hash): raw.hex().encode(),
                }
            )
        )
        code, out = run(inputs(), fetch)
        self.assertEqual(code, verify.EXIT_FAILED, out)
        self.assertIn("proof of work", out)

    def test_pow_target(self) -> None:
        self.assertEqual(verify.pow_target(0x1D00FFFF), 0xFFFF << 208)
        self.assertEqual(verify.pow_target(0x03000001), 1)
        self.assertEqual(verify.pow_target(0x02000100), 1)
        self.assertEqual(verify.pow_target(0x04800000), -1)

    def test_garbage_from_an_explorer_is_undecided(self) -> None:
        good_hash = EXPLORER[height_url("https://mempool.space/api", 969792)].decode()
        mempool = "https://mempool.space/api"
        cases = {
            "hash is not a hash": {height_url(mempool, 969792): b"<html>rate limited</html>"},
            "header is not hex": {header_url(mempool, good_hash): b"zz"},
            "header is 79 bytes": both(lambda base: {header_url(base, good_hash): b"00" * 79}),
        }
        for name, override in cases.items():
            with self.subTest(name):
                code, out = run(inputs(), recorded(override))
                self.assertEqual(code, verify.EXIT_UNDECIDED, out)

    def test_network_error_is_undecided(self) -> None:
        reachable = {k: v for k, v in EXPLORER.items() if "969969" not in k}

        def one_block_unreachable(url: str) -> bytes:
            if url in reachable:
                return reachable[url]
            raise verify.Undecided(f"GET {url}: connection refused")

        code, out = run(inputs(), one_block_unreachable)
        self.assertEqual(code, verify.EXIT_UNDECIDED, out)
        self.assertIn("connection refused", out)

    def test_calendar_only_proof_is_undecided(self) -> None:
        code, out = run(inputs(proof=CAL_PROOF))
        self.assertEqual(code, verify.EXIT_UNDECIDED, out)
        self.assertIn("no Bitcoin attestation yet", out)

    def test_skip_bitcoin_says_the_time_is_not_verified_and_stays_offline(self) -> None:
        fetch = recorded()
        code, out = run(inputs(), fetch, skip_bitcoin=True)
        self.assertEqual(code, verify.EXIT_OK, out)
        self.assertIn("the TIME is NOT verified", out)
        self.assertEqual(fetch.calls, [])  # type: ignore[attr-defined]


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._data


def _http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError(SITE, code, "status", headers, io.BytesIO(b"error code: 1015"))  # type: ignore[arg-type]


def scripted(*steps: object):
    """An opener that plays ``steps`` in order: an exception is raised, bytes are served."""
    queue = list(steps)
    seen: list[str] = []

    def opener(request, timeout):  # noqa: ANN001
        seen.append(request.full_url)
        step = queue.pop(0)
        if isinstance(step, BaseException):
            raise step
        return _Body(step)  # type: ignore[arg-type]

    opener.seen = seen  # type: ignore[attr-defined]
    return opener


class DownloadTests(unittest.TestCase):
    URL = f"{SITE}/{DAY}.jsonl"

    def test_rate_limited_then_served_waits_and_returns_the_file(self) -> None:
        waits: list[float] = []
        opener = scripted(_http_error(429), _http_error(429), RECORD)
        data = REAL_HTTP_GET(self.URL, opener=opener, sleep=waits.append)
        self.assertEqual(data, RECORD)
        self.assertEqual(waits, [verify.RETRY_WAIT_S, verify.RETRY_WAIT_S])
        self.assertEqual(opener.seen, [self.URL] * 3)

    def test_rate_limited_forever_is_undecided_after_the_last_wait(self) -> None:
        waits: list[float] = []
        opener = scripted(*[_http_error(429)] * (verify.RETRY_ATTEMPTS + 1))
        with self.assertRaises(verify.Undecided) as caught:
            REAL_HTTP_GET(self.URL, opener=opener, sleep=waits.append)
        self.assertIn("rate limited", str(caught.exception))
        self.assertEqual(len(waits), verify.RETRY_ATTEMPTS)
        self.assertEqual(len(opener.seen), verify.RETRY_ATTEMPTS + 1)

    def test_other_http_errors_are_undecided_at_once_without_waiting(self) -> None:
        for code in (404, 500, 503):
            with self.subTest(code):
                waits: list[float] = []
                opener = scripted(_http_error(code))
                with self.assertRaises(verify.Undecided) as caught:
                    REAL_HTTP_GET(self.URL, opener=opener, sleep=waits.append)
                self.assertIn(str(code), str(caught.exception))
                self.assertEqual(waits, [])
                self.assertEqual(len(opener.seen), 1)

    def test_connection_error_is_undecided_at_once(self) -> None:
        waits: list[float] = []
        opener = scripted(urllib.error.URLError("connection refused"))
        with self.assertRaises(verify.Undecided):
            REAL_HTTP_GET(self.URL, opener=opener, sleep=waits.append)
        self.assertEqual(waits, [])

    def test_retry_after_is_used_only_when_it_is_a_sane_number_of_seconds(self) -> None:
        cases = {"5": 5, " 20 ": 20, "60": 60, "61": verify.RETRY_WAIT_S, "0": verify.RETRY_WAIT_S,
                 "-3": verify.RETRY_WAIT_S, "soon": verify.RETRY_WAIT_S, "": verify.RETRY_WAIT_S}
        for header, expected in cases.items():
            with self.subTest(header):
                waits: list[float] = []
                opener = scripted(_http_error(429, header), RECORD)
                REAL_HTTP_GET(self.URL, opener=opener, sleep=waits.append)
                self.assertEqual(waits, [expected])

    def test_served_file_is_returned_without_waiting(self) -> None:
        waits: list[float] = []
        self.assertEqual(REAL_HTTP_GET(self.URL, opener=scripted(RECORD), sleep=waits.append), RECORD)
        self.assertEqual(waits, [])


class CliTests(unittest.TestCase):
    def cli(self, *argv: str, fetch=None) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = verify.main(list(argv), fetch=fetch or recorded())
        return code, buf.getvalue()

    def test_local_path(self) -> None:
        code, out = self.cli(str(FIX / f"{DAY}.jsonl"))
        self.assertEqual(code, 0, out)

    def test_day_name_downloads_both_files_and_can_save_them(self) -> None:
        fetch = recorded()
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self.cli(DAY, "--save-dir", tmp, fetch=fetch)
            self.assertEqual(code, 0, out)
            self.assertEqual((Path(tmp) / f"{DAY}.jsonl").read_bytes(), RECORD)
            self.assertEqual((Path(tmp) / f"{DAY}.jsonl.btc.ots").read_bytes(), BTC_PROOF)
        self.assertEqual(fetch.calls[:2], [f"{SITE}/{DAY}.jsonl", f"{SITE}/{DAY}.jsonl.btc.ots"])  # type: ignore[attr-defined]

    def test_explicit_proof_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "day.jsonl"
            record.write_bytes(RECORD)
            code, out = self.cli(str(record), "--proof", str(FIX / f"{DAY}.jsonl.ots"))
        self.assertEqual(code, 2, out)  # the calendar proof has no Bitcoin attestation yet

    def test_usage_errors_exit_2(self) -> None:
        self.assertEqual(self.cli("not-a-day")[0], 2)
        self.assertEqual(self.cli(str(FIX / "missing.jsonl"))[0], 2)
        self.assertEqual(self.cli("--no-such-flag", DAY)[0], 2)
        self.assertEqual(self.cli()[0], 2)

    def test_help_and_version_exit_0(self) -> None:
        code, out = self.cli("--help")
        self.assertEqual(code, 0)
        self.assertIn("Exit codes", out)
        self.assertEqual(self.cli("--version")[0], 0)

    def test_names_the_site_accepts(self) -> None:
        for name in ("2026-10-04", "facts-2026-08-20", "facts-erratum-2026-08-26"):
            self.assertTrue(verify.NAME_PATTERN.fullmatch(name), name)
        for name in ("2026-10-04.jsonl", "../2026-10-04", "facts-x-2026-10-04", "2026-10-4"):
            self.assertFalse(verify.NAME_PATTERN.fullmatch(name), name)


if __name__ == "__main__":
    unittest.main()
