"""Helpers for converting loose hex text into bytes and reading fields."""

from __future__ import annotations

import re
import struct
from typing import Iterable


_HEX_TOKEN_RE = re.compile(r"[0-9a-fA-F]{1,2}")
# Anything that is *not* a valid hex digit, separator, or 0x prefix marker.
_FORBIDDEN_CHAR_RE = re.compile(r"[^0-9a-fA-FxX\s,;:\-]")


class HexParseError(ValueError):
    """Raised when the input cannot be interpreted as a stream of hex bytes."""


def parse_hex_stream(text: str) -> bytes:
    """Convert a loose hex string into bytes.

    Accepts tokens separated by ``:``, whitespace, ``-``, ``;`` or ``,`` and
    tolerates ``0x`` prefixes. Each token must be 1 or 2 hex digits.

    Raises :class:`HexParseError` with a human-readable message when the input
    contains illegal characters or oversized tokens.
    """
    if text is None:
        raise HexParseError("Input is empty.")
    if not isinstance(text, str):
        raise HexParseError(f"Expected str, got {type(text).__name__}.")

    # Reject obviously bad characters early with a precise location.
    bad = _FORBIDDEN_CHAR_RE.search(text)
    if bad is not None:
        line = text.count("\n", 0, bad.start()) + 1
        col = bad.start() - (text.rfind("\n", 0, bad.start()))
        raise HexParseError(
            f"Illegal character {bad.group()!r} at line {line}, column {col}."
        )

    cleaned = text.replace("0x", " ").replace("0X", " ")
    cleaned = re.sub(r"[\s,;\-:]+", " ", cleaned).strip()
    if not cleaned:
        raise HexParseError("Input contains no hex bytes.")

    out = bytearray()
    for idx, token in enumerate(cleaned.split(), start=1):
        if not _HEX_TOKEN_RE.fullmatch(token):
            raise HexParseError(
                f"Token #{idx} {token!r} is not a 1-2 digit hex byte."
            )
        out.append(int(token, 16))
    return bytes(out)


def to_hex(data: Iterable[int], sep: str = " ") -> str:
    return sep.join(f"{b:02X}" for b in data)


class ByteReader:
    """Sequential byte reader with little-endian helpers (PLDM is LE)."""

    def __init__(self, data: bytes, offset: int = 0):
        self._data = data
        self._pos = offset

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def peek(self, n: int) -> bytes:
        return self._data[self._pos : self._pos + n]

    def read(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ValueError(
                f"Not enough bytes: need {n}, have {self.remaining} at offset {self._pos}"
            )
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16_le(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_u32_le(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_rest(self) -> bytes:
        chunk = self._data[self._pos :]
        self._pos = len(self._data)
        return chunk
