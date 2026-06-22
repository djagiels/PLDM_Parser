"""MCTP transport header (DSP0236) and message-type byte."""

from __future__ import annotations

from dataclasses import dataclass

from .hexutil import ByteReader


# MCTP message types (DSP0239)
MCTP_MSG_TYPE_CONTROL = 0x00
MCTP_MSG_TYPE_PLDM = 0x01
MCTP_MSG_TYPE_NCSI = 0x02
MCTP_MSG_TYPE_ETHERNET = 0x03
MCTP_MSG_TYPE_NVME_MI = 0x04
MCTP_MSG_TYPE_SPDM = 0x05
MCTP_MSG_TYPE_SECURED = 0x06
MCTP_MSG_TYPE_VENDOR_PCI = 0x7E
MCTP_MSG_TYPE_VENDOR_IANA = 0x7F


_MSG_TYPE_NAMES = {
    MCTP_MSG_TYPE_CONTROL: "MCTP Control",
    MCTP_MSG_TYPE_PLDM: "PLDM",
    MCTP_MSG_TYPE_NCSI: "NC-SI over MCTP",
    MCTP_MSG_TYPE_ETHERNET: "Ethernet over MCTP",
    MCTP_MSG_TYPE_NVME_MI: "NVMe-MI",
    MCTP_MSG_TYPE_SPDM: "SPDM",
    MCTP_MSG_TYPE_SECURED: "Secured Messages",
    MCTP_MSG_TYPE_VENDOR_PCI: "Vendor Defined PCI",
    MCTP_MSG_TYPE_VENDOR_IANA: "Vendor Defined IANA",
}


@dataclass
class MctpTransportHeader:
    raw: bytes
    header_version: int
    dest_eid: int
    src_eid: int
    som: bool
    eom: bool
    pkt_seq: int
    to: bool
    msg_tag: int

    def describe(self) -> list[str]:
        return [
            f"header_version = {self.header_version}",
            f"dest_eid       = 0x{self.dest_eid:02X} ({self.dest_eid})",
            f"src_eid        = 0x{self.src_eid:02X} ({self.src_eid})",
            f"SOM            = {int(self.som)}",
            f"EOM            = {int(self.eom)}",
            f"pkt_seq        = {self.pkt_seq}",
            f"TO             = {int(self.to)}  (1=request owner / originator)",
            f"msg_tag        = {self.msg_tag}",
        ]


@dataclass
class MctpMessageType:
    raw: int
    ic: bool          # integrity check bit
    msg_type: int     # 7-bit message type

    @property
    def name(self) -> str:
        return _MSG_TYPE_NAMES.get(self.msg_type, f"Unknown(0x{self.msg_type:02X})")

    def describe(self) -> list[str]:
        return [
            f"IC             = {int(self.ic)}",
            f"msg_type       = 0x{self.msg_type:02X} ({self.name})",
        ]


def parse_mctp_header(reader: ByteReader) -> MctpTransportHeader:
    raw = reader.read(4)
    b0, b1, b2, b3 = raw
    return MctpTransportHeader(
        raw=raw,
        header_version=b0 & 0x0F,
        dest_eid=b1,
        src_eid=b2,
        som=bool(b3 & 0x80),
        eom=bool(b3 & 0x40),
        pkt_seq=(b3 >> 4) & 0x03,
        to=bool(b3 & 0x08),
        msg_tag=b3 & 0x07,
    )


def parse_mctp_message_type(reader: ByteReader) -> MctpMessageType:
    b = reader.read_u8()
    return MctpMessageType(raw=b, ic=bool(b & 0x80), msg_type=b & 0x7F)
