"""PDR (Platform Descriptor Record) decoding -- DSP0248.

Implements the common PDR header (10 bytes) and the Terminus Locator PDR
(type 1) body. Other PDR types are returned as raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .hexutil import ByteReader, to_hex


# PDR Type values (DSP0248 Table)
PDR_TYPE_TERMINUS_LOCATOR = 1
PDR_TYPE_NUMERIC_SENSOR = 2
PDR_TYPE_NUMERIC_SENSOR_INIT = 3
PDR_TYPE_STATE_SENSOR = 4
PDR_TYPE_STATE_SENSOR_INIT = 5
PDR_TYPE_COMPACT_NUMERIC_SENSOR = 21
PDR_TYPE_SENSOR_AUX_NAMES = 13
PDR_TYPE_OEM_DEVICE = 126
PDR_TYPE_OEM = 127
PDR_TYPE_ENTITY_ASSOCIATION = 15
PDR_TYPE_FRU_RECORD_SET = 20

_PDR_TYPE_NAMES = {
    1: "Terminus Locator PDR",
    2: "Numeric Sensor PDR",
    3: "Numeric Sensor Initialization PDR",
    4: "State Sensor PDR",
    5: "State Sensor Initialization PDR",
    9: "OEM EID PDR",
    11: "Numeric Effecter PDR",
    13: "Sensor Auxiliary Names PDR",
    14: "Effecter Auxiliary Names PDR",
    15: "Entity Association PDR",
    16: "Entity Auxiliary Names PDR",
    20: "FRU Record Set PDR",
    21: "Compact Numeric Sensor PDR",
    126: "OEM Device PDR",
    127: "OEM PDR",
}


_TERMINUS_LOCATOR_TYPE_NAMES = {
    0x00: "UID",
    0x01: "MCTP_EID",
    0x02: "SMBus Relative",
    0x03: "System Software",
}


def pdr_type_name(t: int) -> str:
    return _PDR_TYPE_NAMES.get(t, f"Unknown(0x{t:02X})")


@dataclass
class PdrHeader:
    record_handle: int
    pdr_header_version: int
    pdr_type: int
    record_change_number: int
    data_length: int  # length of the body that follows the header

    @property
    def type_name(self) -> str:
        return pdr_type_name(self.pdr_type)

    def describe(self) -> list[str]:
        return [
            f"record_handle        = {self.record_handle} (0x{self.record_handle:08X})",
            f"pdr_header_version   = {self.pdr_header_version}",
            f"pdr_type             = {self.pdr_type} ({self.type_name})",
            f"record_change_number = {self.record_change_number}",
            f"data_length          = {self.data_length}",
        ]


@dataclass
class TerminusLocatorPdr:
    pldm_terminus_handle: int
    validity: int  # 0=not valid, 1=valid
    tid: int
    container_id: int
    locator_type: int
    locator_value: bytes

    @property
    def locator_type_name(self) -> str:
        return _TERMINUS_LOCATOR_TYPE_NAMES.get(
            self.locator_type, f"Unknown(0x{self.locator_type:02X})"
        )

    def describe(self) -> list[str]:
        lines = [
            f"pldm_terminus_handle = {self.pldm_terminus_handle}",
            f"validity             = {self.validity} "
            f"({'valid' if self.validity == 1 else 'not valid'})",
            f"tid                  = {self.tid}",
            f"container_id         = {self.container_id}",
            f"locator_type         = 0x{self.locator_type:02X} ({self.locator_type_name})",
            f"locator_value        = {to_hex(self.locator_value)}",
        ]
        if self.locator_type == 0x01 and len(self.locator_value) >= 1:
            lines.append(f"  -> MCTP EID        = {self.locator_value[0]}")
        return lines


@dataclass
class Pdr:
    header: PdrHeader
    body_raw: bytes
    body: Optional[object] = None  # decoded body, when known

    def describe(self) -> list[str]:
        lines = ["PDR Header:"]
        lines += [f"  {l}" for l in self.header.describe()]
        lines.append(f"PDR Body raw ({len(self.body_raw)} B): {to_hex(self.body_raw)}")
        if self.body is not None and hasattr(self.body, "describe"):
            lines.append(f"Decoded {self.header.type_name}:")
            lines += [f"  {l}" for l in self.body.describe()]
        return lines


def parse_pdr_header(reader: ByteReader) -> PdrHeader:
    return PdrHeader(
        record_handle=reader.read_u32_le(),
        pdr_header_version=reader.read_u8(),
        pdr_type=reader.read_u8(),
        record_change_number=reader.read_u16_le(),
        data_length=reader.read_u16_le(),
    )


def parse_terminus_locator_pdr(body: bytes) -> TerminusLocatorPdr:
    r = ByteReader(body)
    handle = r.read_u16_le()
    validity = r.read_u8()
    tid = r.read_u8()
    container_id = r.read_u16_le()
    locator_type = r.read_u8()
    locator_size = r.read_u8()
    locator_value = r.read(locator_size) if locator_size else b""
    return TerminusLocatorPdr(
        pldm_terminus_handle=handle,
        validity=validity,
        tid=tid,
        container_id=container_id,
        locator_type=locator_type,
        locator_value=locator_value,
    )


def parse_pdr(record_bytes: bytes) -> Pdr:
    r = ByteReader(record_bytes)
    header = parse_pdr_header(r)
    body = r.read(min(header.data_length, r.remaining))
    decoded = None
    if header.pdr_type == PDR_TYPE_TERMINUS_LOCATOR:
        try:
            decoded = parse_terminus_locator_pdr(body)
        except ValueError:
            decoded = None
    return Pdr(header=header, body_raw=body, body=decoded)
