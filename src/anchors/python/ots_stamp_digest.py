#!/usr/bin/env python3
"""
ots_stamp_digest.py — OpenTimestamps stamping helper that accepts a raw
SHA-256 digest as input (NOT a file). This is the v1 reference submission
backend for the Script Provenance Protocol.

Why this exists instead of `ots stamp`: the upstream `opentimestamps-client`
CLI's `stamp` subcommand expects a FILE and re-hashes it. For the Script
Provenance Protocol we already have the claimHash and want to stamp it
directly without re-hashing. The opentimestamps library DOES support this
via the DetachedTimestampFile constructor; we just have to invoke the lower-
level pieces ourselves.

Usage:
    python3 ots_stamp_digest.py <hex-digest-64-chars>
    # or: pipe hex from stdin:
    echo deadbeef... | python3 ots_stamp_digest.py -

    Writes the serialized .ots binary to stdout.

Flags:
    --mock                Skip calendar submission; emit an unupgraded .ots
                          with no attestations (useful for offline tests).
    --calendar URL        Add a calendar URL (repeatable). Defaults to the
                          four public OTS pool calendars.
    --timeout SECONDS     Per-calendar request timeout (default 5).
    --min-calendars N     Require attestations from at least N calendars
                          (default 1 to keep the helper resilient under
                          flaky network conditions).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from queue import Queue, Empty
import threading
import time

from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.serialize import StreamSerializationContext
import opentimestamps.calendar


DEFAULT_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
]


def submit_to_calendar(url: str, msg: bytes, q: Queue, timeout: float) -> None:
    """Submit `msg` to `url` in a worker thread; put result onto `q`."""

    def runner() -> None:
        remote = opentimestamps.calendar.RemoteCalendar(
            url,
            user_agent="script-provenance-protocol/0.0.0-wip",
        )
        try:
            ts = remote.submit(msg, timeout=timeout)
            q.put(ts)
        except Exception as e:  # noqa: BLE001
            q.put(e)

    t = threading.Thread(target=runner, daemon=True)
    t.start()


def stamp_digest(
    digest_bytes: bytes,
    calendar_urls: list[str],
    timeout: float,
    min_calendars: int,
    mock: bool,
) -> bytes:
    """Stamp a raw 32-byte SHA-256 digest. Returns the serialized .ots bytes."""

    if len(digest_bytes) != 32:
        raise ValueError(
            f"expected 32-byte SHA-256 digest, got {len(digest_bytes)} bytes"
        )

    # 1. Build a DetachedTimestampFile from the digest (direct constructor).
    file_timestamp = DetachedTimestampFile(OpSHA256(), Timestamp(digest_bytes))

    if mock:
        # In mock mode we add a single PendingAttestation against a placeholder
        # calendar URL. This produces a syntactically valid (but unupgraded)
        # .ots file that can be used for parser tests offline.
        # NOT a verifiable proof — the attestation has no real backing.
        file_timestamp.timestamp.attestations.add(
            PendingAttestation("https://mock.calendar.example/")
        )
        out = bytearray()

        class _Sink:
            def write(self, b: bytes) -> int:
                out.extend(b)
                return len(b)

        sink = _Sink()
        ctx = StreamSerializationContext(sink)
        file_timestamp.serialize(ctx)
        return bytes(out)

    # 2. Add per-submission nonce + SHA-256 op to derive the merkle_root that
    # gets submitted to calendars (mimics otsclient.cmds.stamp_command).
    nonce_appended_stamp = file_timestamp.timestamp.ops.add(
        OpAppend(os.urandom(16))
    )
    merkle_root = nonce_appended_stamp.ops.add(OpSHA256())

    # 3. Submit merkle_root.msg to each calendar in parallel; merge results.
    q: Queue = Queue()
    for url in calendar_urls:
        submit_to_calendar(url, merkle_root.msg, q, timeout)

    start = time.time()
    merged = 0
    for _ in range(len(calendar_urls)):
        remaining = max(0.0, timeout - (time.time() - start))
        try:
            result = q.get(block=True, timeout=remaining)
        except Empty:
            continue
        if isinstance(result, Timestamp):
            try:
                merkle_root.merge(result)
                merged += 1
            except Exception as e:  # noqa: BLE001
                logging.warning("merge failed: %s", e)
        else:
            logging.warning("calendar error: %s", result)

    if merged < min_calendars:
        raise RuntimeError(
            f"only {merged} of {len(calendar_urls)} calendars responded; "
            f"need at least {min_calendars}"
        )

    # 4. Serialize the original file_timestamp (which now contains the merged
    # attestations via its linked sub-timestamp).
    out = bytearray()

    class _ByteSink:
        def __init__(self) -> None:
            self.buf = bytearray()

        def write(self, b: bytes) -> int:
            self.buf.extend(b)
            return len(b)

    sink = _ByteSink()
    ctx = StreamSerializationContext(sink)
    file_timestamp.serialize(ctx)
    return bytes(sink.buf)


def parse_digest_arg(arg: str) -> bytes:
    if arg == "-":
        hex_str = sys.stdin.read().strip()
    else:
        hex_str = arg.strip()
    if hex_str.startswith("sha256:"):
        hex_str = hex_str[len("sha256:") :]
    if len(hex_str) != 64:
        raise ValueError(
            f"expected 64-char hex SHA-256 digest (optionally prefixed with 'sha256:'), got {len(hex_str)} chars"
        )
    return bytes.fromhex(hex_str)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Stamp a raw SHA-256 digest via OpenTimestamps calendars; emit .ots to stdout."
    )
    parser.add_argument(
        "digest",
        help="Hex-encoded 32-byte SHA-256 digest (or 'sha256:<hex>'), or '-' for stdin.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Skip calendar submission; emit a placeholder unupgraded .ots for offline testing.",
    )
    parser.add_argument(
        "--calendar",
        action="append",
        default=[],
        help="Calendar URL to submit to (repeatable). Default: 4 public OTS pool calendars.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-calendar submit timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--min-calendars",
        type=int,
        default=1,
        help="Minimum number of calendar attestations required (default: 1).",
    )

    args = parser.parse_args()
    digest = parse_digest_arg(args.digest)
    calendar_urls = args.calendar or DEFAULT_CALENDARS[:]

    if args.mock:
        ots_bytes = stamp_digest(digest, [], args.timeout, 0, mock=True)
        sys.stdout.buffer.write(ots_bytes)
        return

    try:
        ots_bytes = stamp_digest(
            digest,
            calendar_urls,
            args.timeout,
            max(1, args.min_calendars),
            mock=False,
        )
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.buffer.write(ots_bytes)


if __name__ == "__main__":
    main()
