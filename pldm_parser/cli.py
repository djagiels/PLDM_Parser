"""Command-line entry point: ``python -m pldm_parser <hex>``."""

from __future__ import annotations

import argparse
import sys

from .parser import parse_frame


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="pldm_parser",
        description="Parse a PLDM-over-MCTP frame (with optional Intel sideband prefix).",
    )
    p.add_argument(
        "hex",
        nargs="*",
        help="Hex bytes of the frame. If omitted, reads from stdin.",
    )
    p.add_argument(
        "--no-intel-prefix",
        action="store_true",
        help="Disable Intel sideband prefix auto-detection.",
    )
    p.add_argument(
        "--intel-prefix",
        action="store_true",
        help="Force Intel sideband prefix parsing.",
    )
    args = p.parse_args(argv)

    text = " ".join(args.hex) if args.hex else sys.stdin.read()
    if not text.strip():
        p.error("no input provided")

    has_prefix = None
    if args.intel_prefix:
        has_prefix = True
    elif args.no_intel_prefix:
        has_prefix = False

    frame = parse_frame(text, has_intel_prefix=has_prefix)
    print(frame.to_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
