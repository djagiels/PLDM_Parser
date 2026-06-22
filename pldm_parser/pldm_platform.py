"""PLDM Platform Monitoring & Control commands (DSP0248)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .hexutil import ByteReader, to_hex
from .pdr import Pdr, parse_pdr


# Transfer operation flag (request)
XFER_OP_GET_NEXT_PART = 0x00
XFER_OP_GET_FIRST_PART = 0x01

# Transfer flag (response)
XFER_FLAG_START = 0x00
XFER_FLAG_MIDDLE = 0x01
XFER_FLAG_END = 0x04
XFER_FLAG_START_AND_END = 0x05


_XFER_OP_NAMES = {
    XFER_OP_GET_NEXT_PART: "GetNextPart",
    XFER_OP_GET_FIRST_PART: "GetFirstPart",
}

_XFER_FLAG_NAMES = {
    XFER_FLAG_START: "Start",
    XFER_FLAG_MIDDLE: "Middle",
    XFER_FLAG_END: "End",
    XFER_FLAG_START_AND_END: "StartAndEnd",
}


# ----------------------------- GetPDR (0x51) --------------------------------


@dataclass
class GetPdrRequest:
    record_handle: int
    data_transfer_handle: int
    transfer_operation_flag: int
    request_count: int
    record_change_number: int

    @property
    def transfer_op_name(self) -> str:
        return _XFER_OP_NAMES.get(
            self.transfer_operation_flag,
            f"Unknown(0x{self.transfer_operation_flag:02X})",
        )

    def describe(self) -> list[str]:
        return [
            f"record_handle           = {self.record_handle} (0x{self.record_handle:08X})",
            f"data_transfer_handle    = 0x{self.data_transfer_handle:08X}",
            f"transfer_operation_flag = 0x{self.transfer_operation_flag:02X} "
            f"({self.transfer_op_name})",
            f"request_count           = {self.request_count}",
            f"record_change_number    = {self.record_change_number}",
        ]


@dataclass
class GetPdrResponse:
    next_record_handle: int
    next_data_transfer_handle: int
    transfer_flag: int
    response_count: int
    record_data: bytes
    transfer_crc: Optional[int]
    pdr: Optional[Pdr]

    @property
    def transfer_flag_name(self) -> str:
        return _XFER_FLAG_NAMES.get(
            self.transfer_flag, f"Unknown(0x{self.transfer_flag:02X})"
        )

    def describe(self) -> list[str]:
        lines = [
            f"next_record_handle        = {self.next_record_handle} "
            f"(0x{self.next_record_handle:08X})",
            f"next_data_transfer_handle = 0x{self.next_data_transfer_handle:08X}",
            f"transfer_flag             = 0x{self.transfer_flag:02X} "
            f"({self.transfer_flag_name})",
            f"response_count            = {self.response_count}",
            f"record_data ({len(self.record_data)} B) = {to_hex(self.record_data)}",
        ]
        if self.transfer_crc is not None:
            lines.append(f"transfer_crc              = 0x{self.transfer_crc:02X}")
        if self.pdr is not None:
            lines.append("Decoded PDR:")
            lines += [f"  {l}" for l in self.pdr.describe()]
        return lines


def parse_get_pdr_request(payload: bytes) -> GetPdrRequest:
    r = ByteReader(payload)
    return GetPdrRequest(
        record_handle=r.read_u32_le(),
        data_transfer_handle=r.read_u32_le(),
        transfer_operation_flag=r.read_u8(),
        request_count=r.read_u16_le(),
        record_change_number=r.read_u16_le(),
    )


def parse_get_pdr_response(payload: bytes) -> GetPdrResponse:
    r = ByteReader(payload)
    next_rh = r.read_u32_le()
    next_dth = r.read_u32_le()
    xfer_flag = r.read_u8()
    resp_count = r.read_u16_le()

    take = min(resp_count, r.remaining)
    record_data = r.read(take)

    transfer_crc: Optional[int] = None
    # CRC is included only for End / StartAndEnd of a multi-part transfer.
    if r.remaining >= 1 and xfer_flag in (XFER_FLAG_END, XFER_FLAG_START_AND_END):
        transfer_crc = r.read_u8()

    pdr = None
    if record_data:
        try:
            pdr = parse_pdr(record_data)
        except ValueError:
            pdr = None

    return GetPdrResponse(
        next_record_handle=next_rh,
        next_data_transfer_handle=next_dth,
        transfer_flag=xfer_flag,
        response_count=resp_count,
        record_data=record_data,
        transfer_crc=transfer_crc,
        pdr=pdr,
    )
