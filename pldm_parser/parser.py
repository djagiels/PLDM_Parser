"""Top-level frame parser that ties transport + MCTP + PLDM layers together.

The parser is defensive: every decoding step is wrapped in a guard, and any
issue (under-length buffer, unexpected protocol version, bogus completion
code, etc.) is recorded as a :class:`Note` with a severity rather than raised
as an exception. ``parse_frame`` never raises for in-range bytes; it only
raises for caller errors (wrong input type) or for hex tokenization errors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union

from .hexutil import ByteReader, HexParseError, parse_hex_stream, to_hex
from .mctp import (
    MCTP_MSG_TYPE_PLDM,
    MctpMessageType,
    MctpTransportHeader,
    parse_mctp_header,
    parse_mctp_message_type,
)
from .pldm import (
    PLATFORM_CMD_GET_PDR,
    PLDM_TYPE_PLATFORM,
    PldmHeader,
    parse_pldm_header,
)
from .pldm_platform import (
    GetPdrRequest,
    GetPdrResponse,
    parse_get_pdr_request,
    parse_get_pdr_response,
)
from .platform_commands import find_decoder
from .transport import (
    INTEL_PREFIX_LEN,
    IntelTransportPrefix,
    looks_like_intel_prefix,
    parse_intel_prefix,
)


log = logging.getLogger("pldm_parser")

PldmPayload = Union[GetPdrRequest, GetPdrResponse, bytes, None]

# Sanity bound. 64 KiB easily covers any realistic MCTP/PLDM frame and protects
# us from pathological inputs (e.g. someone pasting megabytes of hex).
MAX_FRAME_BYTES = 64 * 1024

# Minimum length for the GetPDR request payload (per DSP0248 Table 33).
_GET_PDR_REQ_PAYLOAD_LEN = 13


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class Note:
    severity: Severity
    message: str

    def __str__(self) -> str:  # backward compat for "- {note}" formatters
        return f"[{self.severity.value.upper()}] {self.message}"


@dataclass
class ParsedFrame:
    raw: bytes
    intel_prefix: Optional[IntelTransportPrefix]
    mctp_header: Optional[MctpTransportHeader]
    mctp_msg_type: Optional[MctpMessageType]
    pldm_header: Optional[PldmHeader]
    pldm_payload_raw: bytes
    pldm_payload: PldmPayload
    trailing: bytes  # leftover bytes (e.g. PEC)
    notes: list[Note] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(n.severity is Severity.ERROR for n in self.notes)

    @property
    def has_warnings(self) -> bool:
        return any(n.severity is Severity.WARNING for n in self.notes)

    def to_text(self) -> str:
        out: list[str] = []
        out.append(f"Raw frame ({len(self.raw)} B): {to_hex(self.raw)}")
        out.append("")

        if self.intel_prefix is not None:
            out.append("[Intel sideband transport prefix]")
            out += [f"  {l}" for l in self.intel_prefix.describe()]
            out.append("")

        if self.mctp_header is not None:
            out.append("[MCTP transport header]")
            out += [f"  {l}" for l in self.mctp_header.describe()]
            out.append("")

        if self.mctp_msg_type is not None:
            out.append("[MCTP message type]")
            out += [f"  {l}" for l in self.mctp_msg_type.describe()]
            out.append("")

        if self.pldm_header is not None:
            out.append("[PLDM header]")
            out += [f"  {l}" for l in self.pldm_header.describe()]
            out.append("")
            out.append(
                f"[PLDM payload raw ({len(self.pldm_payload_raw)} B)] "
                f"{to_hex(self.pldm_payload_raw)}"
            )
            if self.pldm_payload is not None and hasattr(self.pldm_payload, "describe"):
                out.append("")
                kind = "Request" if self.pldm_header.is_request else "Response"
                out.append(f"[Decoded {self.pldm_header.command_name} {kind}]")
                out += [f"  {l}" for l in self.pldm_payload.describe()]
            out.append("")

        if self.trailing:
            out.append(f"[Trailing bytes ({len(self.trailing)} B)] {to_hex(self.trailing)}")

        if self.notes:
            out.append("")
            out.append("Notes:")
            out += [f"  - {n}" for n in self.notes]

        return "\n".join(out)


_SEV_TO_LOG = {
    Severity.INFO: logging.INFO,
    Severity.WARNING: logging.WARNING,
    Severity.ERROR: logging.ERROR,
}


def _add(notes: list[Note], severity: Severity, msg: str) -> None:
    log.log(_SEV_TO_LOG[severity], msg)
    notes.append(Note(severity, msg))


def _finalize(
    data: bytes,
    intel_prefix,
    mctp_hdr,
    mctp_msg,
    pldm_hdr,
    pldm_payload_raw: bytes,
    pldm_payload,
    trailing: bytes,
    notes: list[Note],
) -> ParsedFrame:
    return ParsedFrame(
        raw=data,
        intel_prefix=intel_prefix,
        mctp_header=mctp_hdr,
        mctp_msg_type=mctp_msg,
        pldm_header=pldm_hdr,
        pldm_payload_raw=pldm_payload_raw,
        pldm_payload=pldm_payload,
        trailing=trailing,
        notes=notes,
    )


def parse_frame(
    data: Union[bytes, str, bytearray, memoryview],
    *,
    has_intel_prefix: Optional[bool] = None,
) -> ParsedFrame:
    """Parse a raw PLDM-over-MCTP frame.

    Parameters
    ----------
    data:
        Frame bytes or a hex string. Hex strings may use ``:``, spaces, ``-``,
        ``,`` or ``;`` as separators and may contain ``0x`` prefixes.
    has_intel_prefix:
        If ``None`` (default), auto-detect the Intel sideband prefix. Set to
        ``True``/``False`` to force the choice.

    Raises
    ------
    HexParseError
        If a string input cannot be tokenized as hex bytes.
    TypeError
        If ``data`` is not a bytes-like object or str.
    """
    # ---- input normalization & guard rails ----
    if data is None:
        raise TypeError("parse_frame: input is None.")
    if isinstance(data, str):
        data = parse_hex_stream(data)  # may raise HexParseError
    elif isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError(
            f"parse_frame: unsupported input type {type(data).__name__}; "
            "expected str, bytes, bytearray or memoryview."
        )

    notes: list[Note] = []

    if len(data) == 0:
        _add(notes, Severity.ERROR, "Empty frame: nothing to decode.")
        return _finalize(data, None, None, None, None, b"", None, b"", notes)

    if len(data) > MAX_FRAME_BYTES:
        _add(
            notes,
            Severity.ERROR,
            f"Frame too large ({len(data)} B > {MAX_FRAME_BYTES} B limit); aborting.",
        )
        return _finalize(data, None, None, None, None, b"", None, b"", notes)

    reader = ByteReader(data)

    # 1) Optional Intel sideband prefix.
    if has_intel_prefix is None:
        has_intel_prefix = looks_like_intel_prefix(data)
        if has_intel_prefix:
            _add(
                notes,
                Severity.INFO,
                "Intel sideband prefix auto-detected (12 B).",
            )
    intel_prefix = None
    if has_intel_prefix:
        if reader.remaining < INTEL_PREFIX_LEN:
            _add(
                notes,
                Severity.WARNING,
                f"Frame shorter than Intel sideband prefix "
                f"(need {INTEL_PREFIX_LEN} B, have {reader.remaining}); skipped.",
            )
        else:
            try:
                intel_prefix = parse_intel_prefix(reader)
            except (ValueError, IndexError) as exc:
                _add(notes, Severity.ERROR, f"Intel prefix decode failed: {exc}")

    mctp_hdr: Optional[MctpTransportHeader] = None
    mctp_msg: Optional[MctpMessageType] = None
    pldm_hdr: Optional[PldmHeader] = None
    pldm_payload_raw: bytes = b""
    pldm_payload: PldmPayload = None
    trailing: bytes = b""

    # 2) MCTP transport header (4 B).
    if reader.remaining < 4:
        _add(
            notes,
            Severity.ERROR,
            f"Frame too short for MCTP transport header "
            f"(need 4 B, have {reader.remaining}).",
        )
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    try:
        mctp_hdr = parse_mctp_header(reader)
    except (ValueError, IndexError) as exc:
        _add(notes, Severity.ERROR, f"MCTP header decode failed: {exc}")
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    if mctp_hdr.header_version != 1:
        _add(
            notes,
            Severity.WARNING,
            f"Unexpected MCTP header_version {mctp_hdr.header_version} (expected 1).",
        )
    if not (mctp_hdr.som and mctp_hdr.eom):
        _add(
            notes,
            Severity.WARNING,
            "MCTP packet is not a single complete message (SOM/EOM not both set); "
            "multi-packet reassembly is not implemented.",
        )
    if mctp_hdr.dest_eid == mctp_hdr.src_eid and mctp_hdr.dest_eid != 0:
        _add(
            notes,
            Severity.INFO,
            f"MCTP dst_eid == src_eid (0x{mctp_hdr.dest_eid:02X}); loopback?",
        )

    # 3) MCTP message type byte.
    if reader.remaining < 1:
        _add(notes, Severity.ERROR, "Missing MCTP message-type byte.")
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    try:
        mctp_msg = parse_mctp_message_type(reader)
    except (ValueError, IndexError) as exc:
        _add(notes, Severity.ERROR, f"MCTP message-type decode failed: {exc}")
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    if mctp_msg.msg_type != MCTP_MSG_TYPE_PLDM:
        _add(
            notes,
            Severity.WARNING,
            f"MCTP message type 0x{mctp_msg.msg_type:02X} ({mctp_msg.name}) is not PLDM; "
            "remaining bytes left undecoded.",
        )
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    # 4) PLDM header (3 B request, 4 B response).
    if reader.remaining < 3:
        _add(
            notes,
            Severity.ERROR,
            f"Frame too short for PLDM header (need >= 3 B, have {reader.remaining}).",
        )
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    try:
        pldm_hdr = parse_pldm_header(reader)
    except (ValueError, IndexError) as exc:
        _add(notes, Severity.ERROR, f"PLDM header decode failed: {exc}")
        trailing = reader.read_rest()
        return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                         pldm_payload_raw, pldm_payload, trailing, notes)

    if pldm_hdr.header_version != 0:
        _add(
            notes,
            Severity.WARNING,
            f"PLDM header_version {pldm_hdr.header_version} != 0 (per DSP0240).",
        )
    if pldm_hdr.pldm_type > 0x3F:
        _add(
            notes,
            Severity.WARNING,
            f"PLDM type 0x{pldm_hdr.pldm_type:02X} is out of the 6-bit range.",
        )

    # 5) Payload.
    pldm_payload_raw = bytes(reader._data[reader.pos:])  # noqa: SLF001
    reader._pos = len(reader._data)  # noqa: SLF001

    if pldm_hdr.pldm_type == PLDM_TYPE_PLATFORM and pldm_hdr.command == PLATFORM_CMD_GET_PDR:
        if pldm_hdr.is_request:
            if len(pldm_payload_raw) < _GET_PDR_REQ_PAYLOAD_LEN:
                _add(
                    notes,
                    Severity.ERROR,
                    f"GetPDR request payload too short "
                    f"({len(pldm_payload_raw)} B, need {_GET_PDR_REQ_PAYLOAD_LEN}).",
                )
                pldm_payload = pldm_payload_raw
            else:
                try:
                    pldm_payload = parse_get_pdr_request(
                        pldm_payload_raw[:_GET_PDR_REQ_PAYLOAD_LEN]
                    )
                    if len(pldm_payload_raw) > _GET_PDR_REQ_PAYLOAD_LEN:
                        trailing = pldm_payload_raw[_GET_PDR_REQ_PAYLOAD_LEN:]
                        pldm_payload_raw = pldm_payload_raw[:_GET_PDR_REQ_PAYLOAD_LEN]
                        _add(
                            notes,
                            Severity.INFO,
                            f"{len(trailing)} trailing byte(s) after GetPDR request "
                            "(possibly MCTP/PEC).",
                        )
                except (ValueError, IndexError) as exc:
                    _add(notes, Severity.ERROR, f"GetPDR request decode failed: {exc}")
                    pldm_payload = pldm_payload_raw
        else:
            if pldm_hdr.completion_code not in (None, 0x00):
                _add(
                    notes,
                    Severity.WARNING,
                    f"GetPDR response completion code is non-zero "
                    f"(0x{pldm_hdr.completion_code:02X}); body may be empty.",
                )
            try:
                pldm_payload = parse_get_pdr_response(pldm_payload_raw)
            except (ValueError, IndexError) as exc:
                _add(notes, Severity.ERROR, f"GetPDR response decode failed: {exc}")
                pldm_payload = pldm_payload_raw
    else:
        # Try the dispatch registry for any other command (DSP0240 Base or
        # DSP0248 Platform commands beyond GetPDR).
        decoded: Optional[object] = None
        if pldm_hdr.completion_code in (None, 0x00):
            decoder = find_decoder(
                pldm_hdr.pldm_type, pldm_hdr.command, pldm_hdr.is_request
            )
            if decoder is not None:
                try:
                    decoded = decoder(pldm_payload_raw)
                except (ValueError, IndexError) as exc:
                    _add(notes, Severity.ERROR,
                         f"{pldm_hdr.command_name} decode failed: {exc}")
        else:
            _add(notes, Severity.WARNING,
                 f"{pldm_hdr.command_name} response carries non-success completion "
                 f"code 0x{pldm_hdr.completion_code:02X}; body may be absent.")

        if decoded is not None:
            pldm_payload = decoded
        else:
            pldm_payload = pldm_payload_raw
            if pldm_hdr.pldm_type == PLDM_TYPE_PLATFORM and not pldm_payload_raw:
                pass  # nothing to say
            elif pldm_hdr.completion_code in (None, 0x00) and pldm_payload_raw:
                _add(
                    notes,
                    Severity.INFO,
                    f"{pldm_hdr.type_name} command 0x{pldm_hdr.command:02X} "
                    f"({pldm_hdr.command_name}) has no structured decoder yet; "
                    "payload kept raw.",
                )

    return _finalize(data, intel_prefix, mctp_hdr, mctp_msg, pldm_hdr,
                     pldm_payload_raw, pldm_payload, trailing, notes)
