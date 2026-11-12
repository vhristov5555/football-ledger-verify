#!/usr/bin/env python3
"""Check one day of the football-prediction public forecast ledger yourself.

Standard library only (Python 3.10+). Nothing to install.

What it checks, in order:

  1. the record is self-consistent: ``n`` equals the number of leaves, every
     leaf's ``commitment`` equals ``sha256(canonical_json)``, and the Merkle root over the ordered
     commitments (raw-bytes concatenation, the last node duplicated on an odd
     level, an empty day = ``sha256(b"")``) equals the record's ``root``;
  2. the Bitcoin-attested OpenTimestamps proof (``<name>.jsonl.btc.ots``)
     commits to exactly this file: its file digest equals ``sha256(file)``;
  3. for every Bitcoin attestation in the proof: the block header at that
     height is fetched from TWO independent block explorers
     (mempool.space and blockstream.info), the two must return the same
     header, the header must hash to the block hash they report and carry
     valid proof of work for its own difficulty bits, and its Merkle root
     must equal the value the proof computes. The block time is printed:
     the record existed no later than (about) that. A block's time is set by
     its miner and is only approximate — roughly ±2 hours.

What it does NOT check: whether any forecast was good. The ledger proves WHEN
a record existed and that it has not been changed since — nothing more.

The proof format is parsed here (no ``ots`` dependency). If you prefer the
reference client and run a Bitcoin node, the equivalent is::

    ots verify -f 2026-10-04.jsonl 2026-10-04.jsonl.btc.ots

Exit codes:
  0  every check passed (with --skip-bitcoin: the local checks passed and the
     time was NOT checked);
  1  verification FAILED: the data contradicts the claim (a leaf, the root,
     the proof digest or a block's Merkle root does not match, or a header
     fails its own hash / proof-of-work check);
  2  could not decide: bad usage, a missing or unreadable file, an
     unsupported proof, a network error, the two explorers disagreeing with
     each other, or a proof that has no Bitcoin attestation yet.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

__version__ = "1.0.1"

DEFAULT_BASE_URL = "https://football.vhristov.com/api/ledger"
EXPLORERS: tuple[tuple[str, str], ...] = (
    ("mempool.space", "https://mempool.space/api"),
    ("blockstream.info", "https://blockstream.info/api"),
)
NAME_PATTERN = re.compile(r"^(?:facts-(?:erratum-)?)?\d{4}-\d{2}-\d{2}$")
USER_AGENT = f"football-ledger-verify/{__version__}"
TIMEOUT_S = 30
# The site answers HTTP 429 when one address sends more than 30 requests to
# /api/ in 10 seconds, and keeps refusing for the next 10 seconds. A loop over
# many days reaches that; one day (two files) never does. Wait it out a few
# times, then give up as "undecided" — never as "failed".
RETRY_STATUS = 429
RETRY_ATTEMPTS = 3
RETRY_WAIT_S = 11
RETRY_WAIT_MAX_S = 60

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNDECIDED = 2


class VerifyFailed(Exception):
    """The data contradicts the claim (exit 1)."""


class Undecided(Exception):
    """The check could not be completed (exit 2)."""


# --------------------------------------------------------------------------
# 1. The record
# --------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(commitments: list[bytes]) -> bytes:
    """Root over ordered commitments: raw-bytes concat, duplicate last on odd."""
    if not commitments:
        return sha256(b"")
    level = list(commitments)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


@dataclass
class RecordCheck:
    root: str
    n_leaves: int


def check_record(data: bytes) -> RecordCheck:
    """Re-derive every commitment and the root of a ledger file (one JSON line)."""
    try:
        first_line = data.decode("utf-8").split("\n", 1)[0]
        record = json.loads(first_line)
        # A forecast or facts day names its leaves `leaves`; a §7.5 erratum
        # (facts-erratum-*.jsonl) names them `entries`. Same commitment rule,
        # same Merkle rule.
        leaves = record["leaves"] if "leaves" in record else record["entries"]
        stated_root = record["root"]
        stated_n = record["n"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise Undecided(f"not a ledger day-record: {exc}") from exc
    if (
        not isinstance(leaves, list)
        or not isinstance(stated_root, str)
        or not isinstance(stated_n, int)
    ):
        raise Undecided("not a ledger day-record: unexpected field types")
    if stated_n != len(leaves):
        raise VerifyFailed(f"the record says n = {stated_n} but lists {len(leaves)} leaves")

    commitments: list[bytes] = []
    for index, leaf in enumerate(leaves):
        try:
            canonical = leaf["canonical_json"]
            stated = leaf["commitment"]
        except (KeyError, TypeError) as exc:
            raise Undecided(f"leaf {index}: missing field {exc}") from exc
        derived = sha256(canonical.encode("utf-8"))
        if derived.hex() != stated:
            raise VerifyFailed(
                f"leaf {index}: sha256(canonical_json) = {derived.hex()}, the record says {stated}"
            )
        commitments.append(derived)

    root = merkle_root(commitments).hex()
    if root != stated_root:
        raise VerifyFailed(f"Merkle root = {root}, the record says {stated_root}")
    return RecordCheck(root=root, n_leaves=len(leaves))


# --------------------------------------------------------------------------
# 2. The OpenTimestamps proof (format parsed here, stdlib only)
# --------------------------------------------------------------------------

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_ATTESTATION = 0x00
TAG_FORK = 0xFF
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
MAX_ARG = 4096
MAX_PAYLOAD = 8192
MAX_DEPTH = 256


def _unary(name: str) -> Callable[[bytes], bytes]:
    def apply(msg: bytes) -> bytes:
        try:
            return hashlib.new(name, msg).digest()
        except ValueError as exc:  # e.g. ripemd160 missing from this OpenSSL
            raise Undecided(f"this Python cannot compute {name}") from exc

    return apply


UNARY_OPS: dict[int, Callable[[bytes], bytes]] = {
    0x02: _unary("sha1"),
    0x03: _unary("ripemd160"),
    0x08: _unary("sha256"),
    0xF3: lambda msg: msg.hex().encode("ascii"),
}
BINARY_OPS: dict[int, Callable[[bytes, bytes], bytes]] = {
    0xF0: lambda msg, arg: msg + arg,  # append
    0xF1: lambda msg, arg: arg + msg,  # prepend
}


@dataclass
class Attestation:
    kind: str  # "bitcoin" | "pending" | "unknown"
    msg: bytes  # the commitment the attestation is about
    height: int | None = None
    uri: str | None = None
    tag: bytes = b""


@dataclass
class Proof:
    file_digest: bytes
    attestations: list[Attestation] = field(default_factory=list)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._io = io.BytesIO(data)

    def read(self, n: int) -> bytes:
        chunk = self._io.read(n)
        if len(chunk) != n:
            raise Undecided("proof is truncated")
        return chunk

    def byte(self) -> int:
        return self.read(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise Undecided("proof has an oversized integer")

    def varbytes(self, limit: int) -> bytes:
        length = self.varuint()
        if length > limit:
            raise Undecided("proof has an oversized field")
        return self.read(length)

    def at_end(self) -> bool:
        return self._io.read(1) == b""


def _parse_attestation(r: _Reader, msg: bytes) -> Attestation:
    tag = r.read(8)
    payload = _Reader(r.varbytes(MAX_PAYLOAD))
    if tag == TAG_BITCOIN:
        return Attestation(kind="bitcoin", msg=msg, height=payload.varuint(), tag=tag)
    if tag == TAG_PENDING:
        uri = payload.varbytes(1000).decode("ascii", errors="replace")
        return Attestation(kind="pending", msg=msg, uri=uri, tag=tag)
    return Attestation(kind="unknown", msg=msg, tag=tag)


def _parse_timestamp(r: _Reader, msg: bytes, out: list[Attestation], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise Undecided("proof is nested too deeply")

    def one(tag: int) -> None:
        if tag == TAG_ATTESTATION:
            out.append(_parse_attestation(r, msg))
        elif tag in UNARY_OPS:
            _parse_timestamp(r, UNARY_OPS[tag](msg), out, depth + 1)
        elif tag in BINARY_OPS:
            arg = r.varbytes(MAX_ARG)
            _parse_timestamp(r, BINARY_OPS[tag](msg, arg), out, depth + 1)
        else:
            raise Undecided(f"unsupported proof operation 0x{tag:02x}")

    tag = r.byte()
    while tag == TAG_FORK:
        one(r.byte())
        tag = r.byte()
    one(tag)


def parse_proof(data: bytes) -> Proof:
    """Parse a detached ``.ots`` proof (major version 1, sha256 file digest)."""
    r = _Reader(data)
    if r.read(len(OTS_MAGIC)) != OTS_MAGIC:
        raise Undecided("not an OpenTimestamps proof (bad magic)")
    version = r.varuint()
    if version != 1:
        raise Undecided(f"unsupported proof version {version}")
    if r.byte() != 0x08:
        raise Undecided("proof does not use a sha256 file digest")
    digest = r.read(32)
    attestations: list[Attestation] = []
    _parse_timestamp(r, digest, attestations, 0)
    if not r.at_end():
        raise Undecided("proof has trailing bytes")
    return Proof(file_digest=digest, attestations=attestations)


# --------------------------------------------------------------------------
# 3. Bitcoin block headers, from two independent explorers
# --------------------------------------------------------------------------

Fetcher = Callable[[str], bytes]


def _retry_wait(retry_after: str | None) -> int:
    """Seconds to wait after a 429: the server's Retry-After if it is a sane
    whole number of seconds, else the default."""
    if retry_after is not None and retry_after.strip().isdigit():
        asked = int(retry_after.strip())
        if 0 < asked <= RETRY_WAIT_MAX_S:
            return asked
    return RETRY_WAIT_S


def http_get(
    url: str,
    *,
    opener: Callable[..., object] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(RETRY_ATTEMPTS + 1):
        try:
            with opener(request, timeout=TIMEOUT_S) as response:  # type: ignore[attr-defined]
                return bytes(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code != RETRY_STATUS:
                raise Undecided(f"GET {url}: {exc}") from exc
            if attempt == RETRY_ATTEMPTS:
                raise Undecided(
                    f"GET {url}: still rate limited (HTTP 429) after "
                    f"{RETRY_ATTEMPTS} waits; try again in a minute"
                ) from exc
            sleep(_retry_wait(exc.headers.get("Retry-After") if exc.headers else None))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise Undecided(f"GET {url}: {exc}") from exc
    raise AssertionError("unreachable")  # pragma: no cover


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data))


@dataclass
class Header:
    block_hash: str  # display order (as explorers print it)
    merkle_root: bytes  # internal byte order (as it sits in the header)
    time: int
    bits: int


def parse_header(raw: bytes) -> Header:
    if len(raw) != 80:
        raise Undecided(f"block header is {len(raw)} bytes, expected 80")
    return Header(
        block_hash=sha256d(raw)[::-1].hex(),
        merkle_root=raw[36:68],
        time=int.from_bytes(raw[68:72], "little"),
        bits=int.from_bytes(raw[72:76], "little"),
    )


def pow_target(bits: int) -> int:
    exponent, mantissa = bits >> 24, bits & 0x007FFFFF
    if bits & 0x00800000:  # negative targets are invalid
        return -1
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def fetch_header(base: str, height: int, fetch: Fetcher) -> tuple[str, bytes]:
    """(block hash the explorer reports, raw 80-byte header) for a height."""
    block_hash = fetch(f"{base}/block-height/{height}").decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", block_hash):
        raise Undecided(f"{base}: unexpected block hash for height {height}: {block_hash!r}")
    header_hex = fetch(f"{base}/block/{block_hash}/header").decode("ascii", "replace").strip()
    try:
        raw = bytes.fromhex(header_hex)
    except ValueError as exc:
        raise Undecided(f"{base}: block header is not hex") from exc
    return block_hash, raw


@dataclass
class BlockCheck:
    height: int
    block_hash: str
    time: int


def check_bitcoin_attestation(
    att: Attestation,
    fetch: Fetcher,
    explorers: tuple[tuple[str, str], ...] = EXPLORERS,
) -> BlockCheck:
    assert att.height is not None
    answers: list[tuple[str, str, bytes]] = []
    for name, base in explorers:
        block_hash, raw = fetch_header(base, att.height, fetch)
        answers.append((name, block_hash, raw))

    first_name, first_hash, first_raw = answers[0]
    for name, block_hash, raw in answers[1:]:
        if (block_hash, raw) != (first_hash, first_raw):
            raise Undecided(
                f"block {att.height}: {first_name} and {name} disagree "
                f"({first_hash} vs {block_hash}); cannot decide"
            )

    header = parse_header(first_raw)
    if header.block_hash != first_hash:
        raise VerifyFailed(
            f"block {att.height}: the header hashes to {header.block_hash}, "
            f"the explorers say {first_hash}"
        )
    target = pow_target(header.bits)
    if target <= 0 or int(header.block_hash, 16) > target:
        raise VerifyFailed(f"block {att.height}: the header has no valid proof of work")
    if header.merkle_root != att.msg:
        raise VerifyFailed(
            f"block {att.height}: Merkle root {header.merkle_root[::-1].hex()} "
            f"!= the proof's {att.msg[::-1].hex()}"
        )
    return BlockCheck(height=att.height, block_hash=header.block_hash, time=header.time)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


@dataclass
class Inputs:
    record: bytes
    proof: bytes
    record_label: str
    proof_label: str


def utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def verify(
    inputs: Inputs,
    fetch: Fetcher = http_get,
    skip_bitcoin: bool = False,
    out: Callable[[str], None] = print,
) -> int:
    """Run every check; print a line per check; return the exit code."""
    try:
        record = check_record(inputs.record)
        out(f"OK   record {inputs.record_label}: {record.n_leaves} leaves, root {record.root}")

        file_digest = sha256(inputs.record)
        out(f"OK   sha256({inputs.record_label}) = {file_digest.hex()}")

        proof = parse_proof(inputs.proof)
        if proof.file_digest != file_digest:
            raise VerifyFailed(
                f"{inputs.proof_label} is for sha256 {proof.file_digest.hex()}, "
                f"not for this file ({file_digest.hex()})"
            )
        out(f"OK   {inputs.proof_label} commits to exactly this file")

        bitcoin = [a for a in proof.attestations if a.kind == "bitcoin"]
        for att in proof.attestations:
            if att.kind == "pending":
                out(f"info pending calendar attestation ({att.uri}) — not used")
            elif att.kind == "unknown":
                out(f"info unknown attestation {att.tag.hex()} — not used")

        if skip_bitcoin:
            out("SKIP Bitcoin block check (--skip-bitcoin): the TIME is NOT verified")
            return EXIT_OK
        if not bitcoin:
            raise Undecided(f"{inputs.proof_label} has no Bitcoin attestation yet")

        checked = [check_bitcoin_attestation(att, fetch) for att in bitcoin]
        names = " and ".join(name for name, _ in EXPLORERS)
        for block in checked:
            out(
                f"OK   Bitcoin block {block.height} ({block.block_hash}), time "
                f"~{utc(block.time)}: Merkle root matches; {names} agree"
            )
        earliest = min(checked, key=lambda b: b.time)
        out(
            f"=>   the record existed no later than about {utc(earliest.time)} "
            f"(block {earliest.height}) and has not changed since."
        )
        out("     A block's time is set by its miner: approximate, roughly +/- 2 hours.")
        out("     This says nothing about whether the forecasts were good.")
        return EXIT_OK
    except VerifyFailed as exc:
        out(f"FAIL {exc}")
        return EXIT_FAILED
    except Undecided as exc:
        out(f"???  {exc}")
        return EXIT_UNDECIDED


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise Undecided(f"cannot read {path}: {exc}") from exc


def resolve_inputs(args: argparse.Namespace, fetch: Fetcher) -> Inputs:
    """A day NAME is downloaded from the public site; a PATH is read locally."""
    target: str = args.target
    if NAME_PATTERN.fullmatch(target) and not os.path.exists(target):
        record_name = f"{target}.jsonl"
        proof_name = f"{record_name}.btc.ots"
        base = args.base_url.rstrip("/")
        record = fetch(f"{base}/{record_name}")
        proof = fetch(f"{base}/{proof_name}")
        if args.save_dir:
            os.makedirs(args.save_dir, exist_ok=True)
            for name, data in ((record_name, record), (proof_name, proof)):
                with open(os.path.join(args.save_dir, name), "wb") as fh:
                    fh.write(data)
        return Inputs(record, proof, record_name, proof_name)

    if not target.endswith(".jsonl"):
        raise Undecided(
            f"{target!r}: give a day name (2026-10-04, facts-2026-08-20, "
            "facts-erratum-2026-08-26) or a path to a .jsonl file"
        )
    proof_path = args.proof or f"{target}.btc.ots"
    return Inputs(
        _read(target),
        _read(proof_path),
        os.path.basename(target),
        os.path.basename(proof_path),
    )


def main(argv: list[str] | None = None, fetch: Fetcher = http_get) -> int:
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="Check one day of the football-prediction public forecast ledger.",
        epilog="Exit codes: 0 all checks passed, 1 verification failed, 2 could not decide.",
    )
    parser.add_argument(
        "target",
        help="a day name to download (2026-10-04, facts-2026-08-20, "
        "facts-erratum-2026-08-26) or a path to a local .jsonl file",
    )
    parser.add_argument(
        "--proof", help="local proof file (default: <file>.btc.ots next to the .jsonl)"
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=argparse.SUPPRESS)
    parser.add_argument(
        "--save-dir", help="when downloading, also save the two files into this directory"
    )
    parser.add_argument(
        "--skip-bitcoin",
        action="store_true",
        help="local checks only — no network; the TIME is then NOT verified",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: 0 for --help/--version, 2 for usage
        return int(exc.code or 0)

    try:
        inputs = resolve_inputs(args, fetch)
    except Undecided as exc:
        print(f"???  {exc}")
        return EXIT_UNDECIDED
    return verify(inputs, fetch=fetch, skip_bitcoin=args.skip_bitcoin)


if __name__ == "__main__":
    sys.exit(main())
