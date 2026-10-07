"""Command line entry point for the HPACK-aware capture auditor."""

from __future__ import annotations

import argparse
import json
import sys

from .frame_reader import audit_file, write_report
from .hpack_decoder import HPACKConnectionError


def parse_stream_list(value: str) -> set[int]:
    streams: set[int] = set()
    if not value:
        return streams
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            stream = int(part, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid stream identifier {part!r}; expected a decimal integer"
            ) from exc
        if stream <= 0 or stream > 0x7FFFFFFF:
            raise argparse.ArgumentTypeError(
                f"stream identifier {stream} is outside the HTTP/2 range 1..2147483647"
            )
        streams.add(stream)
    return streams


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="h2-hpack-audit",
        description=(
            "Audit one captured HTTP/2 direction, decode HEADERS/CONTINUATION "
            "statefully, and suppress complete header blocks for chosen streams "
            "while still advancing their HPACK dynamic table."
        ),
    )
    parser.add_argument(
        "capture",
        metavar="CAPTURE.bin",
        help="raw HTTP/2 frame bytes for a single direction (maximum 16 KiB)",
    )
    parser.add_argument(
        "--discard-stream",
        action="append",
        default=[],
        metavar="STREAM_ID[,STREAM_ID...]",
        help=(
            "stream identifier whose complete header block is decoded for HPACK "
            "state but whose fields are not delivered; may be repeated"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="JSON report path, or '-' for stdout (default: stdout)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    discarded: set[int] = set()
    for item in args.discard_stream:
        try:
            discarded.update(parse_stream_list(item))
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    try:
        report = audit_file(args.capture, discarded)
    except OSError as exc:
        error_report = {
            "status": "input_error",
            "error": type(exc).__name__,
            "message": str(exc),
        }
        sys.stderr.write(json.dumps(error_report, ensure_ascii=False, indent=2) + "\n")
        return 3
    except HPACKConnectionError as exc:
        error_report = {
            "status": "connection_error",
            "error": type(exc).__name__,
            "message": str(exc),
        }
        sys.stderr.write(json.dumps(error_report, ensure_ascii=False, indent=2) + "\n")
        return 2

    if args.output == "-":
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return 0

    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            write_report(report, handle)
    except OSError as exc:
        error_report = {
            "status": "output_error",
            "error": type(exc).__name__,
            "message": str(exc),
        }
        sys.stderr.write(json.dumps(error_report, ensure_ascii=False, indent=2) + "\n")
        return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
