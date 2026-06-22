"""Intel OOB-MSM / sideband transport prefix.

Intel sideband transports (e.g. PMT/OOB-MSM) prepend a 12-byte transport header
in front of the standard MCTP transport header. The detailed field semantics
are vendor-specific; this module captures the raw bytes and exposes them so the
rest of the stack can be parsed.

If the buffer does not look like it has this prefix, callers should skip
``parse_intel_prefix`` and start directly with the MCTP header.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hexutil import ByteReader, to_hex


INTEL_PREFIX_LEN = 12


@dataclass
class IntelTransportPrefix:
    raw: bytes

    def describe(self) -> list[str]:
        # Best-effort labelling of observed fields.
        b = self.raw
        return [
            f"raw                = {to_hex(b)}",
            f"byte[0] dest addr  = 0x{b[0]:02X}",
            f"byte[1]            = 0x{b[1]:02X}",
            f"byte[2] direction? = 0x{b[2]:02X}  (req/rsp marker)",
            f"byte[3] src addr?  = 0x{b[3]:02X}",
            f"byte[4..11]        = {to_hex(b[4:12])}",
        ]


def parse_intel_prefix(reader: ByteReader) -> IntelTransportPrefix:
    return IntelTransportPrefix(raw=reader.read(INTEL_PREFIX_LEN))


def looks_like_intel_prefix(data: bytes) -> bool:
    """Heuristic: Intel prefix is 12 bytes, then MCTP header byte 0 must have
    header version 0x01 in its low nibble (per DSP0236)."""
    if len(data) < INTEL_PREFIX_LEN + 1:
        return False
    mctp_first = data[INTEL_PREFIX_LEN]
    return (mctp_first & 0x0F) == 0x01
