"""Tests for the stateful HTTP/2 HPACK auditor.

The test encoder is the mature ``hpack.Encoder``. The production decoder never
calls hpack.Decoder or otherwise hands it a complete header block.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from hpack import Encoder

from h2_audit.cli import main
from h2_audit.frame_reader import audit_capture
from h2_audit.hpack_decoder import HPACKConnectionError

HEADERS = 0x01
CONTINUATION = 0x09
PING = 0x06
END_HEADERS = 0x04


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def headers(stream_id: int, block: bytes, end_headers: bool = True, flags: int = 0) -> bytes:
    actual_flags = flags | (END_HEADERS if end_headers else 0)
    return frame(HEADERS, actual_flags, stream_id, block)


def continuation(stream_id: int, payload: bytes, end_headers: bool = True) -> bytes:
    flags = END_HEADERS if end_headers else 0
    return frame(CONTINUATION, flags, stream_id, payload)


def split_block(stream_id: int, block: bytes, cut: int) -> bytes:
    return (
        headers(stream_id, block[:cut], end_headers=False)
        + continuation(stream_id, block[cut:], end_headers=True)
    )


def values(report: dict[str, object], stream_id: int) -> list[tuple[str, str]]:
    for item in report["header_blocks"]:
        if item["stream_id"] == stream_id:
            return [(field["name"], field["value"]) for field in item["fields"]]
    raise KeyError(stream_id)


class AuditorTests(unittest.TestCase):
    def setUp(self) -> None:
        # 256 is fixed by the tool's simulated HTTP/2 SETTINGS negotiation.
        self.encoder = Encoder()
        self.encoder.header_table_size = 256

    def encode(self, raw_headers: list[tuple[bytes, bytes]], huffman: bool = False) -> bytes:
        return self.encoder.encode(raw_headers, huffman=huffman)

    def test_discarded_block_still_inserts_and_later_index_resolves(self) -> None:
        # Standard encoder: discarded stream inserts a non-static custom field.
        discarded_block = self.encode([(b"x-discarded", b"v-discarded")])
        normal_block = bytes([62 | 0x80])  # index static(61)+dynamic(1)=62

        capture = headers(1, self.encode([(":method", "GET")])) + headers(3, discarded_block) + headers(5, normal_block)

        unfiltered = audit_capture(capture, set())
        filtered = audit_capture(capture, {3})

        self.assertEqual(values(unfiltered, 1), values(filtered, 1))
        self.assertEqual(values(unfiltered, 5), values(filtered, 5))
        self.assertEqual(values(filtered, 5), [("x-discarded", "v-discarded")])
        discarded = next(item for item in filtered["header_blocks"] if item["stream_id"] == 3)
        self.assertEqual(discarded["status"], "discarded")
        self.assertEqual(discarded["fields"], [])
        normal = next(item for item in filtered["header_blocks"] if item["stream_id"] == 5)
        reference = normal["fields"][0]["value_reference"]
        self.assertEqual(reference, {"kind": "dynamic", "index": 62})

    def test_standard_encoder_eviction_is_followed_by_decoder(self) -> None:
        first = self.encode([(b"x-first", b"v" * 90)])
        second = self.encode([(b"x-second", b"v" * 90)])
        third = self.encode([(b"x-third", b"v" * 50)])
        capture = (
            headers(2, first)
            + headers(4, second)
            + headers(6, third)
        )

        report = audit_capture(capture, {2})  # discard the first insertion
        statuses = [item["status"] for item in report["header_blocks"]]
        self.assertEqual(statuses, ["discarded", "delivered", "delivered"])
        self.assertLessEqual(report["final_dynamic_table"]["size"], 256)
        # The newest standard-encoder reference must resolve to the third field.
        self.assertEqual(values(report, 6)[-1], ("x-third", "v" * 50))

    def test_headers_continuation_fragmentation(self) -> None:
        block = self.encode(
            [
                (":method", "GET"),
                (":path", "/fragmented"),
                ("x-marker", b"fragment-value"),
            ],
            huffman=True,
        )
        self.assertGreater(len(block), 4)
        capture = split_block(9, block, 4)
        report = audit_capture(capture, set())
        self.assertEqual(
            values(report, 9),
            [
                (":method", "GET"),
                (":path", "/fragmented"),
                ("x-marker", "fragment-value"),
            ],
        )

    def test_padded_headers_payload_is_stripped_before_hpack(self) -> None:
        block = self.encode([(":method", "GET")])
        payload = bytes([2]) + block + b"\x00\x00"
        capture = frame(HEADERS, END_HEADERS | 0x08, 13, payload)
        report = audit_capture(capture, set())
        self.assertEqual(values(report, 13), [(":method", "GET")])

    def test_frame_inserted_before_end_headers_is_connection_error(self) -> None:
        block = self.encode([(":method", "GET")])
        capture = (
            headers(7, block, end_headers=False)
            + frame(PING, 0, 0, b"0" * 8)
            + continuation(7, b"", end_headers=True)
        )
        with self.assertRaisesRegex(HPACKConnectionError, "before END_HEADERS"):
            audit_capture(capture, set())

    def test_bad_huffman_stops_entire_connection(self) -> None:
        # Start from a standard-encoder Huffman block, then corrupt a byte in
        # its Huffman-coded header name. The malformed block is fatal even when
        # it is filtered. (Index 7 is within this encoder's small emitted block.)
        valid = bytearray(self.encode([(b"x-bad", b"abc")], huffman=True))
        valid[7] = 0xFF
        bad_block = bytes(valid)
        capture = headers(11, bad_block) + headers(13, bytes([0x82]))
        with self.assertRaisesRegex(HPACKConnectionError, "Huffman"):
            audit_capture(capture, {11})

    def test_illegal_dynamic_capacity_update_stops_connection(self) -> None:
        # 5-bit prefix all ones, 226=128+98, then 1 => 31+98+128 = 257.
        capture = headers(15, bytes([0x3F, 0xE2, 0x01]))
        with self.assertRaisesRegex(HPACKConnectionError, "capacity"):
            audit_capture(capture, set())

    def test_capacity_update_after_header_in_same_block_is_fatal(self) -> None:
        # Indexed GET followed by a valid zero-capacity update in the same block.
        capture = headers(16, bytes([0x82, 0x20]))
        with self.assertRaisesRegex(HPACKConnectionError, "start"):
            audit_capture(capture, set())

    def test_illegal_index_stops_connection_without_guessing(self) -> None:
        capture = headers(17, bytes([0xBE]))  # indexed index 62 with empty table
        with self.assertRaisesRegex(HPACKConnectionError, "index"):
            audit_capture(capture, set())

    def test_truncated_integer_does_not_resynchronize_inside_block(self) -> None:
        # Indexed representation says a continuation byte follows, but it is
        # missing. The block must be fatal rather than treated as index 31.
        capture = headers(18, bytes([0xFF]))
        with self.assertRaisesRegex(HPACKConnectionError, "truncated"):
            audit_capture(capture, set())

    def test_standard_encoder_capacity_shrink_evicts_discarded_entries(self) -> None:
        inserted = self.encode([(b"x-before-shrink", b"value")])
        # Standard encoder emits a valid reduction to zero on the next block.
        self.encoder.header_table_size = 0
        shrink_then_static = self.encode([(":method", "POST")], huffman=False)
        capture = headers(25, inserted) + headers(27, shrink_then_static)
        report = audit_capture(capture, {25})
        self.assertEqual(report["final_dynamic_table"]["capacity"], 0)
        self.assertEqual(report["final_dynamic_table"]["size"], 0)
        self.assertEqual(values(report, 27), [(":method", "POST")])

    def test_more_than_64_fields_rejects_only_list_and_table_still_advances(self) -> None:
        many = [("x-duplicate", f"value-{index}") for index in range(65)]
        over_block = self.encode(many, huffman=False)
        later = bytes([0xBE])  # dynamic index 62: last inserted x-duplicate
        capture = headers(19, over_block) + headers(21, later)
        report = audit_capture(capture, set())
        rejected = report["header_blocks"][0]
        normal = report["header_blocks"][1]
        self.assertEqual(rejected["status"], "rejected_too_many_fields")
        self.assertEqual(rejected["fields"], [])
        self.assertEqual(rejected["observed_field_count"], 65)
        self.assertEqual(normal["status"], "delivered")
        self.assertEqual(values(report, 21), [("x-duplicate", "value-64")])

    def test_duplicate_fields_are_not_folded(self) -> None:
        block = self.encode([("x-multi", "a"), ("x-multi", "b"), ("x-multi", "c")])
        report = audit_capture(headers(23, block), set())
        self.assertEqual(
            values(report, 23),
            [("x-multi", "a"), ("x-multi", "b"), ("x-multi", "c")],
        )

    def test_cli_reports_connection_error_with_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.bin"
            path.write_bytes(headers(1, bytes([0xBE])))
            with redirect_stderr(io.StringIO()):
                code = main([str(path)])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
