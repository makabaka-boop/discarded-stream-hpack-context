#!/usr/bin/env python3
"""Test suite and sample generator for h2audit.py.

All samples are produced with the standard encoder (hpack.Encoder); the
auditor under test never uses a ready-made HPACK decoder itself.

Run tests:           python3 tests/test_h2audit.py
Emit demo captures:  python3 tests/test_h2audit.py --emit-demo captures/
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

from hpack import Encoder  # standard encoder, sample generation only

ROOT = pathlib.Path(__file__).resolve().parent.parent
H2AUDIT = ROOT / "h2audit.py"
sys.path.insert(0, str(ROOT))

import h2audit  # noqa: E402

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# --------------------------------------------------------------------------
# Frame builders
# --------------------------------------------------------------------------

def frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([ftype, flags])
        + (sid & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def headers_frame(sid, fragment, end_headers=True, end_stream=False,
                  pad=0, priority=False):
    flags = 0
    if end_headers:
        flags |= 0x4
    if end_stream:
        flags |= 0x1
    payload = b""
    if pad:
        flags |= 0x8
        payload += bytes([pad])
    if priority:
        flags |= 0x20
        payload += b"\x00\x00\x00\x00\x10"  # stream dependency + weight
    payload += fragment + b"\x00" * pad
    return frame(0x1, flags, sid, payload)


def continuation_frame(sid, fragment, end_headers=True):
    return frame(0x9, 0x4 if end_headers else 0, sid, fragment)


def settings_frame(payload=b""):
    return frame(0x4, 0, 0, payload)


def data_frame(sid, payload=b""):
    return frame(0x0, 0x1, sid, payload)


def new_encoder() -> Encoder:
    enc = Encoder()
    enc.header_table_size = 256  # negotiated limit fixed by the audit contract
    return enc


# --------------------------------------------------------------------------
# Sample captures (all encoder-produced)
# --------------------------------------------------------------------------

def build_interleaved():
    """Kept streams 1 and 5, dropped stream 3 whose block feeds the shared
    dynamic table; stream 5 then references those entries by index."""
    enc = new_encoder()
    plain = {
        1: [(":method", "GET"), (":path", "/alpha"), ("x-token", "secret-1")],
        3: [(":method", "GET"), ("x-filter", "dropped-value"), (":path", "/beta")],
        5: [("x-filter", "dropped-value"), (":path", "/beta"), ("x-token", "secret-1")],
    }
    cap = PREFACE + settings_frame()
    for sid in (1, 3, 5):
        cap += headers_frame(sid, enc.encode(plain[sid]), end_stream=True)
    return cap, plain


def build_eviction():
    """256-byte table forced to evict: 95-byte entries, survivors referenced
    by index, evicted entry re-sent as a literal."""
    enc = new_encoder()
    plain = {
        1: [("x-a", "A" * 60)],                       # 95 bytes
        3: [("x-b", "B" * 60)],                       # 190 total
        5: [("x-c", "C" * 60)],                       # evicts x-a -> 190
        7: [("x-c", "C" * 60), ("x-b", "B" * 60)],    # indexed references
        9: [("x-a", "A" * 60)],                       # evicted -> literal again
    }
    cap = settings_frame()
    for sid in (1, 3, 5, 7, 9):
        cap += headers_frame(sid, enc.encode(plain[sid]))
    return cap, plain


def build_fragmented():
    """One header block split over HEADERS + 2 CONTINUATION frames, with
    PADDED and PRIORITY scaffolding on the HEADERS frame."""
    enc = new_encoder()
    plain = {1: [(":method", "POST"), (":path", "/upload"),
                 ("content-type", "application/json"),
                 ("x-session", "fragments-are-fun")]}
    block = enc.encode(plain[1])
    third = max(1, len(block) // 3)
    cap = settings_frame()
    cap += headers_frame(1, block[:third], end_headers=False, pad=8, priority=True)
    cap += continuation_frame(1, block[third:2 * third], end_headers=False)
    cap += continuation_frame(1, block[2 * third:], end_headers=True)
    return cap, plain


def build_too_many_fields():
    """70 fields (> 64) on stream 1: list rejected, connection continues."""
    enc = new_encoder()
    plain = {
        1: [(f"x-h{i:02d}", "v") for i in range(70)],
        3: [("x-after", "ok")],
    }
    cap = settings_frame()
    for sid in (1, 3):
        cap += headers_frame(sid, enc.encode(plain[sid]))
    return cap, plain


def build_duplicates():
    enc = new_encoder()
    plain = {1: [("x-dup", "1"), ("x-dup", "2"), ("x-dup", "1"),
                 (":method", "GET"), (":method", "GET")]}
    return headers_frame(1, enc.encode(plain[1])), plain


def build_bad_huffman():
    # literal without indexing, literal name, huffman flag, 3 zero bytes:
    # 24 zero bits decode to symbols + 4 zero padding bits (must be ones).
    block = b"\x00" + b"\x83\x00\x00\x00" + b"\x00"
    return settings_frame() + headers_frame(1, block)


BAD_BLOCK_CASES = {
    "bad-huffman": (lambda: build_bad_huffman(), "Huffman"),
    "illegal-index": (
        lambda: settings_frame() + headers_frame(1, b"\xff\x00"),
        "illegal index 127",
    ),
    "index-zero": (
        lambda: settings_frame() + headers_frame(1, b"\x80"),
        "illegal index 0",
    ),
    "size-update-too-big": (
        lambda: settings_frame() + headers_frame(1, b"\x3f\xe2\x01"),  # 257
        "exceeds negotiated limit",
    ),
    "size-update-after-field": (
        lambda: settings_frame() + headers_frame(1, b"\x82\x20"),
        "not at start",
    ),
    "interleaved-frame": (
        lambda: headers_frame(1, b"\x82", end_headers=False) + data_frame(1, b"x"),
        "not finished",
    ),
    "continuation-wrong-stream": (
        lambda: headers_frame(1, b"\x82", end_headers=False)
        + continuation_frame(3, b"\x82"),
        "not finished",
    ),
    "capture-ends-mid-block": (
        lambda: headers_frame(1, b"\x82", end_headers=False),
        "ends inside header block",
    ),
    "truncated-payload": (
        lambda: b"\x00\x00\x64" + b"\x01\x04\x00\x00\x00\x01" + b"\x82",
        "truncated frame payload",
    ),
    "truncated-header": (
        lambda: b"\x00\x00",
        "truncated frame header",
    ),
    "push-promise": (
        lambda: settings_frame() + frame(0x5, 0x4, 1, b"\x00\x00\x00\x02"),
        "PUSH_PROMISE",
    ),
    "headers-stream-zero": (
        lambda: headers_frame(0, b"\x82"),
        "stream 0",
    ),
}


# --------------------------------------------------------------------------
# CLI runner + assertion helpers
# --------------------------------------------------------------------------

_tmp = tempfile.TemporaryDirectory(prefix="h2audit-tests-")
_cap_counter = 0


def run_cli(capture: bytes, *args: str):
    global _cap_counter
    _cap_counter += 1
    path = pathlib.Path(_tmp.name) / f"cap-{_cap_counter}.bin"
    path.write_bytes(capture)
    proc = subprocess.run(
        [sys.executable, str(H2AUDIT), str(path), *args],
        capture_output=True, text=True,
    )
    report = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, report, proc.stderr


def delivered(report):
    return {b["stream_id"]: b for b in report["blocks"] if b["status"] == "delivered"}


def nv_list(block):
    return [(h["name"], h["value"]) for h in block["headers"]]


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def eq(got, want, msg):
    if got != want:
        raise AssertionError(f"{msg}\n  got:  {got!r}\n  want: {want!r}")


def assert_plaintext_delivered(report, plain, sids):
    got = delivered(report)
    for sid in sids:
        check(sid in got, f"stream {sid} not delivered: {report['blocks']}")
        eq(nv_list(got[sid]), [tuple(t) for t in plain[sid]],
           f"stream {sid} fields mismatch")


def assert_filter_invariance(capture, plain, drop_ids):
    """Normal requests must decode to identical fields with and without
    filtering; dropped blocks must still feed the shared table."""
    rc_full, full, _ = run_cli(capture)
    rc_filt, filt, _ = run_cli(capture, "--drop-streams", ",".join(map(str, drop_ids)))
    eq(rc_full, 0, "unfiltered run exit code")
    eq(rc_filt, 0, "filtered run exit code")
    keep = [sid for sid in plain if sid not in drop_ids]
    assert_plaintext_delivered(filt, plain, keep)
    for sid in drop_ids:
        statuses = [b["status"] for b in filt["blocks"] if b["stream_id"] == sid]
        eq(statuses, ["dropped"], f"stream {sid} should be dropped")
    full_del, filt_del = delivered(full), delivered(filt)
    for sid in keep:
        eq(filt_del[sid]["headers"], full_del[sid]["headers"],
           f"stream {sid} headers differ before/after filtering")


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_interleaved_drop_shared_table():
    cap, plain = build_interleaved()
    rc, rep, _ = run_cli(cap)
    eq(rc, 0, "exit code")
    assert_plaintext_delivered(rep, plain, [1, 3, 5])

    # stream 5's block is pure dynamic-table references (encoder emitted
    # 0xbf 0xbe 0xc0); they must resolve even when stream 3 is dropped.
    rc, rep, _ = run_cli(cap, "--drop-streams", "3")
    eq(rc, 0, "filtered exit code")
    s5 = delivered(rep)[5]["headers"]
    for h in s5:
        eq(h["source"]["type"], "indexed", "stream 5 source type")
        eq(h["source"]["table"], "dynamic", "stream 5 source table")
    assert_filter_invariance(cap, plain, {3})
    assert_filter_invariance(cap, plain, {1})       # drop block carrying the
    assert_filter_invariance(cap, plain, {1, 3})    # table size update, too


def test_eviction():
    cap, plain = build_eviction()
    rc, rep, _ = run_cli(cap, "--verbose")
    eq(rc, 0, "exit code")
    assert_plaintext_delivered(rep, plain, [1, 3, 5, 7, 9])

    s7 = delivered(rep)[7]["headers"]
    for h in s7:
        eq(h["source"], {"type": "indexed", "table": "dynamic",
                         "index": h["source"]["index"]},
           "survivors must be indexed dynamic references")
        eq(h["source"]["table"], "dynamic", "stream 7 source table")

    # x-a was evicted by x-c: the encoder re-sends it as a literal.
    s9 = delivered(rep)[9]["headers"][0]
    eq(s9["source"]["type"], "literal", "evicted entry re-sent as literal")
    eq(s9["source"]["indexing"], "incremental", "re-indexing after eviction")

    table = rep["dynamic_table"]
    eq(table["size"], 190, "final table size")
    eq(table["max_size"], 256, "final table limit")
    eq([e["name"] for e in table["entries"]], ["x-a", "x-c"],
       "x-b must have been evicted")
    assert_filter_invariance(cap, plain, {3})


def test_fragmentation():
    cap, plain = build_fragmented()
    rc, rep, _ = run_cli(cap)
    eq(rc, 0, "exit code")
    assert_plaintext_delivered(rep, plain, [1])
    eq(rep["frames_consumed"], 4, "settings + 3 fragment frames")


def test_too_many_fields_rejected_connection_continues():
    cap, plain = build_too_many_fields()
    rc, rep, _ = run_cli(cap)
    eq(rc, 0, "exit code")
    b1 = [b for b in rep["blocks"] if b["stream_id"] == 1][0]
    eq(b1["status"], "rejected", "over-long list rejected")
    eq(b1["reason"], "too_many_fields", "reject reason")
    eq(b1["field_count"], 70, "field count")
    check("headers" not in b1, "rejected list must not deliver fields")
    # compression instructions were consumed: stream 3 still decodes.
    assert_plaintext_delivered(rep, plain, [3])
    eq(rep["frames_consumed"], 3, "connection continued after rejection")


def test_duplicates_not_collapsed():
    cap, plain = build_duplicates()
    rc, rep, _ = run_cli(cap)
    eq(rc, 0, "exit code")
    assert_plaintext_delivered(rep, plain, [1])
    eq(len(delivered(rep)[1]["headers"]), 5, "all duplicates kept in order")


def test_bad_blocks_stop_connection():
    for name, (builder, needle) in BAD_BLOCK_CASES.items():
        cap = builder()
        rc, rep, _ = run_cli(cap)
        eq(rc, 2, f"{name}: exit code")
        check(rep["error"] is not None, f"{name}: error reported")
        check(needle in rep["error"]["message"],
              f"{name}: error {rep['error']['message']!r} lacks {needle!r}")
        check(isinstance(rep["error"]["offset"], int),
              f"{name}: error offset recorded")


def test_connection_stops_no_state_guessing():
    # A bad block on stream 1 must stop the connection: the valid block on
    # stream 3 afterwards is never consumed.
    cap = (settings_frame()
           + headers_frame(1, b"\xff\x00")            # illegal index
           + headers_frame(3, b"\x82"))               # valid: :method GET
    rc, rep, _ = run_cli(cap)
    eq(rc, 2, "exit code")
    eq([b["stream_id"] for b in rep["blocks"]], [], "no blocks delivered")
    eq(rep["frames_consumed"], 1, "only SETTINGS consumed before the error")


def test_dropped_block_still_consumed_on_error_later():
    # Dropped block decodes fine; a later bad block still stops everything.
    enc = new_encoder()
    good = enc.encode([("x-filter", "v")])
    cap = (headers_frame(3, good)
           + headers_frame(5, b"\x3f\xe2\x01"))       # size update 257
    rc, rep, _ = run_cli(cap, "--drop-streams", "3")
    eq(rc, 2, "exit code")
    eq([b["status"] for b in rep["blocks"]], ["dropped"], "drop before error")


def test_preface_settings_extension_frames():
    cap, plain = build_interleaved()
    # unknown extension frame + PING between blocks: skipped, no effect.
    ext = frame(0xB, 0, 0, b"ext") + frame(0x6, 0, 0, b"\x00" * 8)
    cap = cap + ext + headers_frame(7, new_encoder().encode([("x-z", "1")]))
    rc, rep, _ = run_cli(cap)
    eq(rc, 0, "exit code")
    assert_plaintext_delivered(rep, plain, [1, 3, 5])


def test_huffman_backends_agree():
    from hpack.huffman import HuffmanEncoder
    from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
    from hpack.huffman_table import decode_huffman as reference

    enc = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
    corpus = [b"", b"a", b"www.example.com", b":method", b"gzip, deflate",
              bytes(range(1, 128)), b"\x00\x01\x02", b"z" * 300]
    for raw in corpus:
        coded = enc.encode(raw)
        eq(h2audit._huffman_decode_embedded(coded), raw, f"embedded {raw!r}")
        eq(reference(coded), raw, f"reference {raw!r}")
    for bad in (b"\x00\x00\x00", b"\xff\xff\xff\xff", b"\xf0"):
        for fn in (h2audit._huffman_decode_embedded,):
            try:
                fn(bad)
            except h2audit.HPACKError:
                pass
            else:
                raise AssertionError(f"embedded decoder accepted {bad!r}")

    # Full-capture equivalence of both Huffman paths.
    cap, plain = build_interleaved()
    saved = h2audit.huffman_decode
    try:
        h2audit.huffman_decode = h2audit._huffman_decode_embedded
        rep_embedded = h2audit.audit_capture(cap, {3})
    finally:
        h2audit.huffman_decode = saved
    rep_component = h2audit.audit_capture(cap, {3})
    eq(rep_embedded["blocks"], rep_component["blocks"],
       "huffman backends disagree on full capture")


def test_usage_errors():
    rc, rep, err = run_cli(b"x" * (16 * 1024 + 1))
    eq(rc, 1, "oversized capture exit code")
    check("limit" in err, "oversized capture message")
    rc, rep, err = run_cli(b"\x82", "--drop-streams", "abc")
    eq(rc, 1, "bad stream id exit code")
    proc = subprocess.run([sys.executable, str(H2AUDIT), "/nonexistent.bin"],
                          capture_output=True, text=True)
    eq(proc.returncode, 1, "missing file exit code")


def test_empty_capture():
    rc, rep, _ = run_cli(b"")
    eq(rc, 0, "exit code")
    eq(rep["blocks"], [], "no blocks")


# --------------------------------------------------------------------------
# Demo capture emission (for the compose-mounted input directory)
# --------------------------------------------------------------------------

def emit_demo(directory: pathlib.Path):
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {}

    cap, plain = build_interleaved()
    (directory / "demo-interleaved.bin").write_bytes(cap)
    manifest["demo-interleaved.bin"] = {
        "description": "streams 1,3,5; stream 3's dropped block feeds the "
                       "shared table that stream 5 references by index",
        "suggested_args": ["--drop-streams", "3"],
    }
    cap, _ = build_eviction()
    (directory / "demo-eviction.bin").write_bytes(cap)
    manifest["demo-eviction.bin"] = {
        "description": "256-byte table eviction; survivors indexed, evicted "
                       "entry re-sent literally",
        "suggested_args": ["--verbose"],
    }
    cap, _ = build_fragmented()
    (directory / "demo-fragmented.bin").write_bytes(cap)
    manifest["demo-fragmented.bin"] = {
        "description": "header block split over HEADERS + 2 CONTINUATION, "
                       "with padding and priority",
        "suggested_args": [],
    }
    cap, _ = build_too_many_fields()
    (directory / "demo-too-many-fields.bin").write_bytes(cap)
    manifest["demo-too-many-fields.bin"] = {
        "description": "70 fields on stream 1: list rejected, connection "
                       "continues",
        "suggested_args": [],
    }
    (directory / "demo-bad-huffman.bin").write_bytes(build_bad_huffman())
    manifest["demo-bad-huffman.bin"] = {
        "description": "bad Huffman padding: connection error, exit 2",
        "suggested_args": [],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"wrote {len(manifest)} demo captures to {directory}")


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-demo", metavar="DIR",
                        help="write demo captures instead of running tests")
    args = parser.parse_args()
    if args.emit_demo:
        emit_demo(pathlib.Path(args.emit_demo))
        return 0

    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: {exc}")
        else:
            print(f"PASS {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
