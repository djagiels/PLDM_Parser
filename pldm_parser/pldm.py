"""PLDM common message header (DSP0240).

Wire layout (3 bytes for requests, 4 bytes for responses including
completion code):

    Byte 0:   [Rq:1][D:1][Rsv:1][Instance ID:5]
    Byte 1:   [Hdr Ver:2][PLDM Type:6]
    Byte 2:   PLDM Command
    (Byte 3:  Completion Code -- responses only)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .hexutil import ByteReader


# PLDM Types (DSP0245)
PLDM_TYPE_BASE = 0x00
PLDM_TYPE_SMBIOS = 0x01
PLDM_TYPE_PLATFORM = 0x02
PLDM_TYPE_BIOS = 0x03
PLDM_TYPE_FRU = 0x04
PLDM_TYPE_FW_UPDATE = 0x05
PLDM_TYPE_REDFISH = 0x06
PLDM_TYPE_FILE = 0x07
PLDM_TYPE_OEM = 0x3F

_TYPE_NAMES = {
    PLDM_TYPE_BASE: "Base",
    PLDM_TYPE_SMBIOS: "SMBIOS",
    PLDM_TYPE_PLATFORM: "Platform Monitoring & Control",
    PLDM_TYPE_BIOS: "BIOS Control & Configuration",
    PLDM_TYPE_FRU: "FRU Data",
    PLDM_TYPE_FW_UPDATE: "Firmware Update",
    PLDM_TYPE_REDFISH: "Redfish Device Enablement",
    PLDM_TYPE_FILE: "File Transfer",
    PLDM_TYPE_OEM: "OEM",
}


# ---------------------------------------------------------------------------
# PLDM Base commands (DSP0240 Table 5)
# ---------------------------------------------------------------------------
BASE_CMD_SET_TID = 0x01
BASE_CMD_GET_TID = 0x02
BASE_CMD_GET_PLDM_VERSION = 0x03
BASE_CMD_GET_PLDM_TYPES = 0x04
BASE_CMD_GET_PLDM_COMMANDS = 0x05
BASE_CMD_SELECT_PLDM_VERSION = 0x06
BASE_CMD_NEGOTIATE_TRANSFER_PARAMETERS = 0x07
BASE_CMD_MULTIPART_SEND = 0x08
BASE_CMD_MULTIPART_RECEIVE = 0x09

_BASE_CMD_NAMES = {
    0x01: "SetTID",
    0x02: "GetTID",
    0x03: "GetPLDMVersion",
    0x04: "GetPLDMTypes",
    0x05: "GetPLDMCommands",
    0x06: "SelectPLDMVersion",
    0x07: "NegotiateTransferParameters",
    0x08: "MultipartSend",
    0x09: "MultipartReceive",
}


# ---------------------------------------------------------------------------
# PLDM Platform Monitoring & Control commands (DSP0248 v1.3.0, pages 59-135)
# ---------------------------------------------------------------------------
# Terminus group
PLATFORM_CMD_SET_TID = 0x01
PLATFORM_CMD_GET_TID = 0x02
PLATFORM_CMD_GET_TERMINUS_UID = 0x03
PLATFORM_CMD_SET_EVENT_RECEIVER = 0x04
PLATFORM_CMD_GET_EVENT_RECEIVER = 0x05
PLATFORM_CMD_PLATFORM_EVENT_MESSAGE = 0x0A
PLATFORM_CMD_POLL_FOR_PLATFORM_EVENT_MESSAGE = 0x0B
PLATFORM_CMD_EVENT_MESSAGE_SUPPORTED = 0x0C
PLATFORM_CMD_EVENT_MESSAGE_BUFFER_SIZE = 0x0D
# Numeric sensor group
PLATFORM_CMD_SET_NUMERIC_SENSOR_ENABLE = 0x10
PLATFORM_CMD_GET_SENSOR_READING = 0x11
PLATFORM_CMD_GET_SENSOR_THRESHOLDS = 0x12
PLATFORM_CMD_SET_SENSOR_THRESHOLDS = 0x13
PLATFORM_CMD_RESTORE_SENSOR_THRESHOLDS = 0x14
PLATFORM_CMD_GET_SENSOR_HYSTERESIS = 0x15
PLATFORM_CMD_SET_SENSOR_HYSTERESIS = 0x16
PLATFORM_CMD_INIT_NUMERIC_SENSOR = 0x17
# State sensor group
PLATFORM_CMD_SET_STATE_SENSOR_ENABLES = 0x20
PLATFORM_CMD_GET_STATE_SENSOR_READINGS = 0x21
PLATFORM_CMD_INIT_STATE_SENSOR = 0x22
# Numeric effecter group
PLATFORM_CMD_SET_NUMERIC_EFFECTER_ENABLE = 0x30
PLATFORM_CMD_SET_NUMERIC_EFFECTER_VALUE = 0x31
PLATFORM_CMD_GET_NUMERIC_EFFECTER_VALUE = 0x32
# State effecter group
PLATFORM_CMD_SET_STATE_EFFECTER_ENABLES = 0x38
PLATFORM_CMD_SET_STATE_EFFECTER_STATES = 0x39
PLATFORM_CMD_GET_STATE_EFFECTER_STATES = 0x3A
# PDR repository group
PLATFORM_CMD_GET_PDR_REPOSITORY_INFO = 0x50
PLATFORM_CMD_GET_PDR = 0x51
PLATFORM_CMD_FIND_PDR = 0x52
PLATFORM_CMD_RUN_INIT_AGENT = 0x58
PLATFORM_CMD_GET_PDR_REPOSITORY_SIGNATURE = 0x53

_PLATFORM_CMD_NAMES = {
    0x01: "SetTID",
    0x02: "GetTID",
    0x03: "GetTerminusUID",
    0x04: "SetEventReceiver",
    0x05: "GetEventReceiver",
    0x0A: "PlatformEventMessage",
    0x0B: "PollForPlatformEventMessage",
    0x0C: "EventMessageSupported",
    0x0D: "EventMessageBufferSize",
    0x10: "SetNumericSensorEnable",
    0x11: "GetSensorReading",
    0x12: "GetSensorThresholds",
    0x13: "SetSensorThresholds",
    0x14: "RestoreSensorThresholds",
    0x15: "GetSensorHysteresis",
    0x16: "SetSensorHysteresis",
    0x17: "InitNumericSensor",
    0x20: "SetStateSensorEnables",
    0x21: "GetStateSensorReadings",
    0x22: "InitStateSensor",
    0x30: "SetNumericEffecterEnable",
    0x31: "SetNumericEffecterValue",
    0x32: "GetNumericEffecterValue",
    0x38: "SetStateEffecterEnables",
    0x39: "SetStateEffecterStates",
    0x3A: "GetStateEffecterStates",
    0x50: "GetPDRRepositoryInfo",
    0x51: "GetPDR",
    0x52: "FindPDR",
    0x53: "GetPDRRepositorySignature",
    0x58: "RunInitAgent",
}


# ---------------------------------------------------------------------------
# Completion codes
# ---------------------------------------------------------------------------
PLDM_CC_SUCCESS = 0x00
_COMPLETION_NAMES = {
    # Generic (DSP0240 Table 7)
    0x00: "SUCCESS",
    0x01: "ERROR",
    0x02: "ERROR_INVALID_DATA",
    0x03: "ERROR_INVALID_LENGTH",
    0x04: "ERROR_NOT_READY",
    0x05: "ERROR_UNSUPPORTED_PLDM_CMD",
    0x20: "ERROR_INVALID_PLDM_TYPE",
    # Platform-specific (DSP0248 Annex A)
    0x80: "INVALID_PROTOCOL_TYPE",
    0x81: "ENABLE_METHOD_NOT_SUPPORTED",
    0x82: "INVALID_RECORD_HANDLE",
    0x83: "INVALID_DATA_TRANSFER_HANDLE",
    0x84: "INVALID_TRANSFER_OPERATION_FLAG",
    0x85: "INVALID_RECORD_CHANGE_NUMBER",
    0x86: "TRANSFER_TIMEOUT",
    0x87: "REPOSITORY_UPDATE_IN_PROGRESS",
    0x88: "INVALID_SENSOR_ID",
    0x89: "REARM_UNAVAILABLE_IN_PRESENT_STATE",
    0x8A: "INVALID_SENSOR_OPERATIONAL_STATE",
    0x8B: "EVENT_GENERATION_NOT_SUPPORTED",
    0x8C: "HEARTBEAT_FREQUENCY_TOO_HIGH",
    0x8D: "INVALID_STATE_VALUE",
    0x8E: "UNSUPPORTED_SENSORSTATE",
    0x90: "INVALID_EFFECTER_ID",
    0x91: "INVALID_EFFECTER_STATE",
    0x92: "UNSUPPORTED_EFFECTERSTATE",
}


def pldm_type_name(t: int) -> str:
    return _TYPE_NAMES.get(t, f"Unknown(0x{t:02X})")


def pldm_command_name(pldm_type: int, cmd: int) -> str:
    if pldm_type == PLDM_TYPE_PLATFORM:
        return _PLATFORM_CMD_NAMES.get(cmd, f"Unknown(0x{cmd:02X})")
    if pldm_type == PLDM_TYPE_BASE:
        return _BASE_CMD_NAMES.get(cmd, f"Unknown(0x{cmd:02X})")
    return f"0x{cmd:02X}"


def completion_code_name(cc: int) -> str:
    return _COMPLETION_NAMES.get(cc, f"Unknown(0x{cc:02X})")


@dataclass
class PldmHeader:
    raw: bytes
    rq: bool                   # 1 = request
    datagram: bool             # D bit
    instance_id: int           # 5-bit
    header_version: int        # 2-bit, must be 0
    pldm_type: int             # 6-bit
    command: int               # 8-bit
    completion_code: Optional[int]  # response only

    @property
    def is_request(self) -> bool:
        return self.rq

    @property
    def type_name(self) -> str:
        return pldm_type_name(self.pldm_type)

    @property
    def command_name(self) -> str:
        return pldm_command_name(self.pldm_type, self.command)

    def describe(self) -> list[str]:
        lines = [
            f"Rq             = {int(self.rq)}  ({'Request' if self.rq else 'Response'})",
            f"D (datagram)   = {int(self.datagram)}",
            f"instance_id    = {self.instance_id}",
            f"header_version = {self.header_version}",
            f"pldm_type      = 0x{self.pldm_type:02X} ({self.type_name})",
            f"command        = 0x{self.command:02X} ({self.command_name})",
        ]
        if self.completion_code is not None:
            lines.append(
                f"completion_code= 0x{self.completion_code:02X} "
                f"({completion_code_name(self.completion_code)})"
            )
        return lines


def parse_pldm_header(reader: ByteReader) -> PldmHeader:
    raw_start = reader.pos
    b0 = reader.read_u8()
    b1 = reader.read_u8()
    cmd = reader.read_u8()

    rq = bool(b0 & 0x80)
    datagram = bool(b0 & 0x40)
    inst = b0 & 0x1F
    hdr_ver = (b1 >> 6) & 0x03
    ptype = b1 & 0x3F

    completion = None
    if not rq:  # response carries a completion code byte
        completion = reader.read_u8()

    raw = bytes(reader._data[raw_start : reader.pos])  # noqa: SLF001
    return PldmHeader(
        raw=raw,
        rq=rq,
        datagram=datagram,
        instance_id=inst,
        header_version=hdr_ver,
        pldm_type=ptype,
        command=cmd,
        completion_code=completion,
    )
