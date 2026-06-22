"""Structured decoders for PLDM commands.

Covers:
- PLDM Base commands (DSP0240): SetTID, GetTID, GetPLDMVersion, GetPLDMTypes,
  GetPLDMCommands.
- PLDM Platform Monitoring & Control commands (DSP0248 v1.3.0, pages 59-135):
  terminus, numeric sensor, state sensor, numeric effecter, state effecter,
  and PDR repository commands.

Each decoder returns a dataclass with a ``describe()`` method yielding
``list[str]`` lines. The dispatch registry :data:`COMMAND_DECODERS` maps
``(pldm_type, command, is_request) -> decoder fn``.

The decoders here aim to surface every field the spec defines for the common
"control-plane" sized payloads. For variable-length records with optional
fields (e.g. ``PlatformEventMessage`` per-class event data, ``FindPDR``),
we decode the fixed prefix and keep the rest as raw bytes so users still see
the structure.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Union

from .hexutil import ByteReader, to_hex
from .pldm import (
    PLDM_TYPE_BASE, PLDM_TYPE_PLATFORM,
    BASE_CMD_SET_TID, BASE_CMD_GET_TID,
    BASE_CMD_GET_PLDM_VERSION, BASE_CMD_GET_PLDM_TYPES,
    BASE_CMD_GET_PLDM_COMMANDS,
    PLATFORM_CMD_SET_TID, PLATFORM_CMD_GET_TID,
    PLATFORM_CMD_GET_TERMINUS_UID,
    PLATFORM_CMD_SET_EVENT_RECEIVER, PLATFORM_CMD_GET_EVENT_RECEIVER,
    PLATFORM_CMD_PLATFORM_EVENT_MESSAGE,
    PLATFORM_CMD_POLL_FOR_PLATFORM_EVENT_MESSAGE,
    PLATFORM_CMD_EVENT_MESSAGE_SUPPORTED,
    PLATFORM_CMD_EVENT_MESSAGE_BUFFER_SIZE,
    PLATFORM_CMD_SET_NUMERIC_SENSOR_ENABLE,
    PLATFORM_CMD_GET_SENSOR_READING,
    PLATFORM_CMD_GET_SENSOR_THRESHOLDS,
    PLATFORM_CMD_SET_SENSOR_THRESHOLDS,
    PLATFORM_CMD_RESTORE_SENSOR_THRESHOLDS,
    PLATFORM_CMD_GET_SENSOR_HYSTERESIS,
    PLATFORM_CMD_SET_SENSOR_HYSTERESIS,
    PLATFORM_CMD_INIT_NUMERIC_SENSOR,
    PLATFORM_CMD_SET_STATE_SENSOR_ENABLES,
    PLATFORM_CMD_GET_STATE_SENSOR_READINGS,
    PLATFORM_CMD_INIT_STATE_SENSOR,
    PLATFORM_CMD_SET_NUMERIC_EFFECTER_ENABLE,
    PLATFORM_CMD_SET_NUMERIC_EFFECTER_VALUE,
    PLATFORM_CMD_GET_NUMERIC_EFFECTER_VALUE,
    PLATFORM_CMD_SET_STATE_EFFECTER_ENABLES,
    PLATFORM_CMD_SET_STATE_EFFECTER_STATES,
    PLATFORM_CMD_GET_STATE_EFFECTER_STATES,
    PLATFORM_CMD_GET_PDR_REPOSITORY_INFO,
    PLATFORM_CMD_FIND_PDR,
    PLATFORM_CMD_RUN_INIT_AGENT,
    PLATFORM_CMD_GET_PDR_REPOSITORY_SIGNATURE,
    completion_code_name,
)


# ---------------------------------------------------------------------------
# Enum tables (DSP0248)
# ---------------------------------------------------------------------------

OP_STATE_NAMES = {
    0: "enabled", 1: "disabled", 2: "unavailable",
    3: "statusUnknown", 4: "failed", 5: "initializing",
    6: "shuttingDown", 7: "inTest",
}

PRESENT_REASON_NAMES = {
    0: "initializing", 1: "operating-state-change",
    2: "operationFailed", 3: "non-operational",
}

EVENT_STATE_NAMES = {
    0: "unknown", 1: "normal", 2: "warning", 3: "critical",
    4: "fatal", 5: "lowerWarning", 6: "lowerCritical",
    7: "lowerFatal", 8: "upperWarning", 9: "upperCritical",
    10: "upperFatal",
}

SENSOR_DATA_SIZE_NAMES = {
    0: "uint8", 1: "sint8", 2: "uint16", 3: "sint16",
    4: "uint32", 5: "sint32",
}

EFFECTER_DATA_SIZE_NAMES = SENSOR_DATA_SIZE_NAMES

EFFECTER_OP_STATE_NAMES = {
    0: "Enabled-updatePending", 1: "Enabled-noUpdatePending",
    2: "Disabled", 3: "Unavailable",
    4: "statusUnknown", 5: "failed",
    6: "initializing", 7: "shuttingDown", 8: "inTest",
}

EVENT_RECEIVER_PROTOCOL = {
    0x00: "MCTP", 0x01: "NC-SI", 0xFF: "Other",
}

# DSP0248 Table 19 - sensor/effecter event message class identifiers
EVENT_CLASS_NAMES = {
    0x00: "sensorEvent",
    0x01: "effecterEvent",
    0x02: "redfishTaskExecutedEvent",
    0x03: "redfishMessageEvent",
    0x04: "pldmPDRRepositoryChgEvent",
    0x05: "pldmMessagePollEvent",
    0x06: "heartbeatTimerElapsedEvent",
    0xFA: "OEMEvent_FA",  # Intel-style OEM commonly seen
    0xFE: "OEMEvent_FE",
    0xFF: "OEMEvent_FF",
}

TRANSFER_OP_NAMES = {0: "GetNextPart", 1: "GetFirstPart"}
TRANSFER_FLAG_NAMES = {
    0: "Start", 1: "Middle", 4: "End", 5: "StartAndEnd",
}

REPOSITORY_STATE_NAMES = {0: "available", 1: "updateInProgress", 2: "failed"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kv(label: str, value) -> str:
    return f"{label:<32}= {value}"


def _bytes_field(label: str, data: bytes) -> str:
    if not data:
        return _kv(label, "<empty>")
    return _kv(label, f"{to_hex(data)} ({len(data)} B)")


def _read_signed_value(r: ByteReader, data_size: int) -> int:
    """Read a value whose width is encoded by data_size (DSP0248 Table 70)."""
    if data_size == 0:  # uint8
        return r.read_u8()
    if data_size == 1:  # sint8
        return struct.unpack("<b", r.read(1))[0]
    if data_size == 2:  # uint16
        return r.read_u16_le()
    if data_size == 3:  # sint16
        return struct.unpack("<h", r.read(2))[0]
    if data_size == 4:  # uint32
        return r.read_u32_le()
    if data_size == 5:  # sint32
        return struct.unpack("<i", r.read(4))[0]
    raise ValueError(f"Unsupported sensor data size {data_size}")


def _name_or_unknown(table: Dict[int, str], value: int) -> str:
    return f"0x{value:02X} ({table.get(value, 'unknown')})"


# ---------------------------------------------------------------------------
# PLDM Base (DSP0240)
# ---------------------------------------------------------------------------

@dataclass
class SetTIDRequest:
    tid: int
    def describe(self) -> List[str]:
        return [_kv("TID", self.tid)]


@dataclass
class GetTIDResponse:
    tid: int
    def describe(self) -> List[str]:
        return [_kv("TID", self.tid)]


@dataclass
class GetPLDMVersionRequest:
    data_transfer_handle: int
    transfer_operation_flag: int
    pldm_type: int
    def describe(self) -> List[str]:
        return [
            _kv("data_transfer_handle", f"0x{self.data_transfer_handle:08X}"),
            _kv("transfer_operation_flag",
                _name_or_unknown(TRANSFER_OP_NAMES, self.transfer_operation_flag)),
            _kv("pldm_type", f"0x{self.pldm_type:02X}"),
        ]


@dataclass
class GetPLDMVersionResponse:
    next_data_transfer_handle: int
    transfer_flag: int
    version_data: bytes
    def describe(self) -> List[str]:
        out = [
            _kv("next_data_transfer_handle", f"0x{self.next_data_transfer_handle:08X}"),
            _kv("transfer_flag",
                _name_or_unknown(TRANSFER_FLAG_NAMES, self.transfer_flag)),
            _bytes_field("version_data", self.version_data),
        ]
        if len(self.version_data) >= 4:
            # PLDM version encoded as 4 BCD-ish bytes major.minor.update.alpha
            b = self.version_data[:4]
            out.append(_kv("version (best-effort)",
                           f"{b[0]:02X}.{b[1]:02X}.{b[2]:02X}.{b[3]:02X}"))
        return out


@dataclass
class GetPLDMTypesResponse:
    supported_types_bitmap: bytes  # 8 bytes -> 64 bits
    def describe(self) -> List[str]:
        bits = []
        for i, byte in enumerate(self.supported_types_bitmap):
            for b in range(8):
                if byte & (1 << b):
                    bits.append(i * 8 + b)
        return [
            _bytes_field("supported_types_bitmap", self.supported_types_bitmap),
            _kv("supported_types",
                ", ".join(f"0x{t:02X}" for t in bits) or "<none>"),
        ]


@dataclass
class GetPLDMCommandsRequest:
    pldm_type: int
    version: bytes  # 4 bytes
    def describe(self) -> List[str]:
        return [
            _kv("pldm_type", f"0x{self.pldm_type:02X}"),
            _bytes_field("version", self.version),
        ]


@dataclass
class GetPLDMCommandsResponse:
    supported_commands_bitmap: bytes  # 32 bytes -> 256 bits
    def describe(self) -> List[str]:
        bits = []
        for i, byte in enumerate(self.supported_commands_bitmap):
            for b in range(8):
                if byte & (1 << b):
                    bits.append(i * 8 + b)
        return [
            _bytes_field("supported_commands_bitmap", self.supported_commands_bitmap),
            _kv("supported_commands",
                ", ".join(f"0x{c:02X}" for c in bits) or "<none>"),
        ]


def _decode_set_tid_req(b: bytes) -> SetTIDRequest:
    r = ByteReader(b); return SetTIDRequest(tid=r.read_u8())

def _decode_get_tid_rsp(b: bytes) -> GetTIDResponse:
    r = ByteReader(b); return GetTIDResponse(tid=r.read_u8())

def _decode_get_pldm_version_req(b: bytes) -> GetPLDMVersionRequest:
    r = ByteReader(b)
    return GetPLDMVersionRequest(
        data_transfer_handle=r.read_u32_le(),
        transfer_operation_flag=r.read_u8(),
        pldm_type=r.read_u8(),
    )

def _decode_get_pldm_version_rsp(b: bytes) -> GetPLDMVersionResponse:
    r = ByteReader(b)
    next_h = r.read_u32_le()
    flag = r.read_u8()
    return GetPLDMVersionResponse(
        next_data_transfer_handle=next_h,
        transfer_flag=flag,
        version_data=r.read_rest(),
    )

def _decode_get_pldm_types_rsp(b: bytes) -> GetPLDMTypesResponse:
    return GetPLDMTypesResponse(supported_types_bitmap=b[:8])

def _decode_get_pldm_commands_req(b: bytes) -> GetPLDMCommandsRequest:
    r = ByteReader(b)
    ptype = r.read_u8()
    ver = r.read(min(4, r.remaining))
    return GetPLDMCommandsRequest(pldm_type=ptype, version=ver)

def _decode_get_pldm_commands_rsp(b: bytes) -> GetPLDMCommandsResponse:
    return GetPLDMCommandsResponse(supported_commands_bitmap=b[:32])


# ---------------------------------------------------------------------------
# Platform - Terminus (DSP0248 19.x)
# ---------------------------------------------------------------------------

@dataclass
class GetTerminusUIDResponse:
    uid: bytes  # 16 bytes UUID
    def describe(self) -> List[str]:
        u = self.uid
        formatted = "<invalid>"
        if len(u) == 16:
            formatted = (f"{u[3]:02X}{u[2]:02X}{u[1]:02X}{u[0]:02X}-"
                         f"{u[5]:02X}{u[4]:02X}-{u[7]:02X}{u[6]:02X}-"
                         f"{u[8]:02X}{u[9]:02X}-"
                         f"{u[10]:02X}{u[11]:02X}{u[12]:02X}"
                         f"{u[13]:02X}{u[14]:02X}{u[15]:02X}")
        return [_bytes_field("uid", u), _kv("uuid", formatted)]


@dataclass
class SetEventReceiverRequest:
    event_message_global_enable: int
    transport_protocol_type: int
    event_receiver_address_info: bytes
    heartbeat_timer: Optional[int]
    def describe(self) -> List[str]:
        out = [
            _kv("event_message_global_enable", self.event_message_global_enable),
            _kv("transport_protocol_type",
                _name_or_unknown(EVENT_RECEIVER_PROTOCOL,
                                 self.transport_protocol_type)),
            _bytes_field("event_receiver_address_info",
                         self.event_receiver_address_info),
        ]
        if self.heartbeat_timer is not None:
            out.append(_kv("heartbeat_timer (s)", self.heartbeat_timer))
        return out


@dataclass
class GetEventReceiverResponse(SetEventReceiverRequest):
    pass


@dataclass
class PlatformEventMessageRequest:
    format_version: int
    tid: int
    event_class: int
    event_data: bytes
    def describe(self) -> List[str]:
        return [
            _kv("format_version", self.format_version),
            _kv("tid", self.tid),
            _kv("event_class",
                _name_or_unknown(EVENT_CLASS_NAMES, self.event_class)),
            _bytes_field("event_data", self.event_data),
        ]


@dataclass
class PlatformEventMessageResponse:
    platform_event_status: int
    def describe(self) -> List[str]:
        return [_kv("platform_event_status",
                    f"0x{self.platform_event_status:02X}")]


@dataclass
class PollForPlatformEventMessageRequest:
    format_version: int
    transfer_operation_flag: int
    data_transfer_handle: int
    event_id_to_acknowledge: int
    def describe(self) -> List[str]:
        return [
            _kv("format_version", self.format_version),
            _kv("transfer_operation_flag",
                _name_or_unknown(TRANSFER_OP_NAMES, self.transfer_operation_flag)),
            _kv("data_transfer_handle", f"0x{self.data_transfer_handle:08X}"),
            _kv("event_id_to_acknowledge", f"0x{self.event_id_to_acknowledge:04X}"),
        ]


@dataclass
class PollForPlatformEventMessageResponse:
    tid: int
    event_id: int
    next_data_transfer_handle: int
    transfer_flag: int
    event_class: Optional[int]
    event_data_size: Optional[int]
    event_data: bytes
    event_data_checksum: Optional[int]
    def describe(self) -> List[str]:
        out = [
            _kv("tid", self.tid),
            _kv("event_id", f"0x{self.event_id:04X}"),
            _kv("next_data_transfer_handle",
                f"0x{self.next_data_transfer_handle:08X}"),
            _kv("transfer_flag",
                _name_or_unknown(TRANSFER_FLAG_NAMES, self.transfer_flag)),
        ]
        if self.event_class is not None:
            out.append(_kv("event_class",
                           _name_or_unknown(EVENT_CLASS_NAMES, self.event_class)))
        if self.event_data_size is not None:
            out.append(_kv("event_data_size", self.event_data_size))
        if self.event_data:
            out.append(_bytes_field("event_data", self.event_data))
        if self.event_data_checksum is not None:
            out.append(_kv("event_data_checksum",
                           f"0x{self.event_data_checksum:08X}"))
        return out


@dataclass
class EventMessageSupportedRequest:
    format_version: int
    def describe(self) -> List[str]:
        return [_kv("format_version", self.format_version)]


@dataclass
class EventMessageSupportedResponse:
    synchrony_configuration: int
    synchrony_configuration_supported: int
    number_event_class_returned: int
    event_classes: bytes
    def describe(self) -> List[str]:
        return [
            _kv("synchrony_configuration", self.synchrony_configuration),
            _kv("synchrony_configuration_supported",
                f"0x{self.synchrony_configuration_supported:02X}"),
            _kv("number_event_class_returned", self.number_event_class_returned),
            _bytes_field("event_classes", self.event_classes),
        ]


@dataclass
class EventMessageBufferSizeRequest:
    event_receiver_max_buffer_size: int
    def describe(self) -> List[str]:
        return [_kv("event_receiver_max_buffer_size",
                    self.event_receiver_max_buffer_size)]


@dataclass
class EventMessageBufferSizeResponse:
    terminus_max_buffer_size: int
    def describe(self) -> List[str]:
        return [_kv("terminus_max_buffer_size", self.terminus_max_buffer_size)]


def _decode_set_event_receiver_req(b: bytes) -> SetEventReceiverRequest:
    r = ByteReader(b)
    global_en = r.read_u8()
    proto = r.read_u8()
    # Address info is variable-length (per transport); assume rest until optional
    # heartbeat at end. We will treat the last 2 bytes as heartbeat if the
    # remaining is at least 3 bytes (typical MCTP encoding: 1B addr + 2B HB).
    rest = r.read_rest()
    if len(rest) >= 3:
        addr = rest[:-2]
        hb = struct.unpack("<H", rest[-2:])[0]
    else:
        addr = rest
        hb = None
    return SetEventReceiverRequest(global_en, proto, addr, hb)


def _decode_get_event_receiver_rsp(b: bytes) -> GetEventReceiverResponse:
    r = ByteReader(b)
    global_en = r.read_u8()
    proto = r.read_u8()
    rest = r.read_rest()
    if len(rest) >= 3:
        addr = rest[:-2]
        hb = struct.unpack("<H", rest[-2:])[0]
    else:
        addr = rest
        hb = None
    return GetEventReceiverResponse(global_en, proto, addr, hb)


def _decode_platform_event_msg_req(b: bytes) -> PlatformEventMessageRequest:
    r = ByteReader(b)
    return PlatformEventMessageRequest(
        format_version=r.read_u8(),
        tid=r.read_u8(),
        event_class=r.read_u8(),
        event_data=r.read_rest(),
    )


def _decode_platform_event_msg_rsp(b: bytes) -> PlatformEventMessageResponse:
    return PlatformEventMessageResponse(platform_event_status=b[0] if b else 0)


def _decode_poll_event_req(b: bytes) -> PollForPlatformEventMessageRequest:
    r = ByteReader(b)
    return PollForPlatformEventMessageRequest(
        format_version=r.read_u8(),
        transfer_operation_flag=r.read_u8(),
        data_transfer_handle=r.read_u32_le(),
        event_id_to_acknowledge=r.read_u16_le(),
    )


def _decode_poll_event_rsp(b: bytes) -> PollForPlatformEventMessageResponse:
    r = ByteReader(b)
    tid = r.read_u8()
    eid = r.read_u16_le()
    next_h = r.read_u32_le()
    flag = r.read_u8()
    event_class = None
    event_size = None
    event_data = b""
    crc = None
    # End / StartAndEnd carry full event class and checksum (per DSP0248 17.7)
    if flag in (0, 4, 5) and r.remaining >= 1:
        event_class = r.read_u8()
    if r.remaining >= 4:
        event_size = r.read_u32_le()
        size = min(event_size, r.remaining if flag in (0, 4, 5) else r.remaining - 4)
        if size > 0:
            event_data = r.read(min(size, r.remaining))
    if flag in (4, 5) and r.remaining >= 4:
        crc = r.read_u32_le()
    return PollForPlatformEventMessageResponse(
        tid, eid, next_h, flag, event_class, event_size, event_data, crc,
    )


def _decode_event_msg_supported_req(b: bytes) -> EventMessageSupportedRequest:
    r = ByteReader(b)
    return EventMessageSupportedRequest(format_version=r.read_u8())


def _decode_event_msg_supported_rsp(b: bytes) -> EventMessageSupportedResponse:
    r = ByteReader(b)
    sync = r.read_u8()
    sync_sup = r.read_u8()
    n = r.read_u8()
    classes = r.read(min(n, r.remaining))
    return EventMessageSupportedResponse(sync, sync_sup, n, classes)


def _decode_event_msg_buffer_size_req(b: bytes) -> EventMessageBufferSizeRequest:
    r = ByteReader(b)
    return EventMessageBufferSizeRequest(event_receiver_max_buffer_size=r.read_u16_le())


def _decode_event_msg_buffer_size_rsp(b: bytes) -> EventMessageBufferSizeResponse:
    r = ByteReader(b)
    return EventMessageBufferSizeResponse(terminus_max_buffer_size=r.read_u16_le())


# ---------------------------------------------------------------------------
# Platform - Numeric Sensor (DSP0248 20.x)
# ---------------------------------------------------------------------------

@dataclass
class SetNumericSensorEnableRequest:
    sensor_id: int
    sensor_operational_state: int
    sensor_event_message_enable: int
    def describe(self) -> List[str]:
        return [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("sensor_operational_state",
                _name_or_unknown(OP_STATE_NAMES, self.sensor_operational_state)),
            _kv("sensor_event_message_enable", self.sensor_event_message_enable),
        ]


@dataclass
class GetSensorReadingRequest:
    sensor_id: int
    rearm_event_state: int
    def describe(self) -> List[str]:
        return [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("rearm_event_state", self.rearm_event_state),
        ]


@dataclass
class GetSensorReadingResponse:
    sensor_data_size: int
    sensor_operational_state: int
    sensor_event_message_enable: int
    present_state: int
    previous_state: int
    event_state: int
    present_reading: Optional[int]
    def describe(self) -> List[str]:
        return [
            _kv("sensor_data_size",
                _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size)),
            _kv("sensor_operational_state",
                _name_or_unknown(OP_STATE_NAMES, self.sensor_operational_state)),
            _kv("sensor_event_message_enable", self.sensor_event_message_enable),
            _kv("present_state",
                _name_or_unknown(EVENT_STATE_NAMES, self.present_state)),
            _kv("previous_state",
                _name_or_unknown(EVENT_STATE_NAMES, self.previous_state)),
            _kv("event_state",
                _name_or_unknown(EVENT_STATE_NAMES, self.event_state)),
            _kv("present_reading", self.present_reading),
        ]


@dataclass
class _SensorIdOnlyRequest:
    sensor_id: int
    def describe(self) -> List[str]:
        return [_kv("sensor_id", f"0x{self.sensor_id:04X}")]


@dataclass
class GetSensorThresholdsResponse:
    sensor_data_size: int
    thresholds: List[int]  # up to 6 values per DSP0248 Table 78
    def describe(self) -> List[str]:
        names = ["upperThresholdWarning", "upperThresholdCritical",
                 "upperThresholdFatal", "lowerThresholdWarning",
                 "lowerThresholdCritical", "lowerThresholdFatal"]
        out = [_kv("sensor_data_size",
                   _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size))]
        for name, val in zip(names, self.thresholds):
            out.append(_kv(name, val))
        return out


@dataclass
class SetSensorThresholdsRequest:
    sensor_id: int
    sensor_data_size: int
    thresholds: List[int]
    def describe(self) -> List[str]:
        names = ["upperThresholdWarning", "upperThresholdCritical",
                 "upperThresholdFatal", "lowerThresholdWarning",
                 "lowerThresholdCritical", "lowerThresholdFatal"]
        out = [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("sensor_data_size",
                _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size)),
        ]
        for name, val in zip(names, self.thresholds):
            out.append(_kv(name, val))
        return out


@dataclass
class GetSensorHysteresisResponse:
    sensor_data_size: int
    hysteresis: int
    def describe(self) -> List[str]:
        return [
            _kv("sensor_data_size",
                _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size)),
            _kv("hysteresis", self.hysteresis),
        ]


@dataclass
class SetSensorHysteresisRequest:
    sensor_id: int
    sensor_data_size: int
    hysteresis: int
    def describe(self) -> List[str]:
        return [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("sensor_data_size",
                _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size)),
            _kv("hysteresis", self.hysteresis),
        ]


@dataclass
class InitNumericSensorRequest:
    sensor_id: int
    sensor_data_size: int
    raw: bytes
    def describe(self) -> List[str]:
        return [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("sensor_data_size",
                _name_or_unknown(SENSOR_DATA_SIZE_NAMES, self.sensor_data_size)),
            _bytes_field("init_params", self.raw),
        ]


def _decode_set_num_sensor_enable_req(b: bytes) -> SetNumericSensorEnableRequest:
    r = ByteReader(b)
    return SetNumericSensorEnableRequest(
        sensor_id=r.read_u16_le(),
        sensor_operational_state=r.read_u8(),
        sensor_event_message_enable=r.read_u8(),
    )


def _decode_get_sensor_reading_req(b: bytes) -> GetSensorReadingRequest:
    r = ByteReader(b)
    return GetSensorReadingRequest(
        sensor_id=r.read_u16_le(),
        rearm_event_state=r.read_u8(),
    )


def _decode_get_sensor_reading_rsp(b: bytes) -> GetSensorReadingResponse:
    r = ByteReader(b)
    data_size = r.read_u8()
    op_state = r.read_u8()
    em_en = r.read_u8()
    present = r.read_u8()
    previous = r.read_u8()
    event = r.read_u8()
    reading = None
    if r.remaining >= 1:
        try:
            reading = _read_signed_value(r, data_size)
        except (ValueError, IndexError):
            reading = None
    return GetSensorReadingResponse(
        data_size, op_state, em_en, present, previous, event, reading,
    )


def _decode_get_sensor_thresholds_req(b: bytes) -> _SensorIdOnlyRequest:
    r = ByteReader(b)
    return _SensorIdOnlyRequest(sensor_id=r.read_u16_le())


def _decode_get_sensor_thresholds_rsp(b: bytes) -> GetSensorThresholdsResponse:
    r = ByteReader(b)
    data_size = r.read_u8()
    thr: List[int] = []
    while r.remaining > 0:
        try:
            thr.append(_read_signed_value(r, data_size))
        except (ValueError, IndexError):
            break
    return GetSensorThresholdsResponse(data_size, thr)


def _decode_set_sensor_thresholds_req(b: bytes) -> SetSensorThresholdsRequest:
    r = ByteReader(b)
    sid = r.read_u16_le()
    data_size = r.read_u8()
    thr: List[int] = []
    while r.remaining > 0:
        try:
            thr.append(_read_signed_value(r, data_size))
        except (ValueError, IndexError):
            break
    return SetSensorThresholdsRequest(sid, data_size, thr)


def _decode_get_sensor_hysteresis_rsp(b: bytes) -> GetSensorHysteresisResponse:
    r = ByteReader(b)
    data_size = r.read_u8()
    return GetSensorHysteresisResponse(data_size, _read_signed_value(r, data_size))


def _decode_set_sensor_hysteresis_req(b: bytes) -> SetSensorHysteresisRequest:
    r = ByteReader(b)
    sid = r.read_u16_le()
    data_size = r.read_u8()
    return SetSensorHysteresisRequest(sid, data_size, _read_signed_value(r, data_size))


def _decode_init_numeric_sensor_req(b: bytes) -> InitNumericSensorRequest:
    r = ByteReader(b)
    sid = r.read_u16_le()
    ds = r.read_u8() if r.remaining else 0
    return InitNumericSensorRequest(sid, ds, r.read_rest())


# ---------------------------------------------------------------------------
# Platform - State Sensor (DSP0248 21.x)
# ---------------------------------------------------------------------------

@dataclass
class SetStateSensorEnablesRequest:
    sensor_id: int
    composite_sensor_count: int
    fields: List[Tuple[int, int]]  # (sensor_operational_state, event_message_enable)
    def describe(self) -> List[str]:
        out = [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("composite_sensor_count", self.composite_sensor_count),
        ]
        for i, (op, em) in enumerate(self.fields):
            out.append(_kv(f"  [{i}] sensor_op_state",
                           _name_or_unknown(OP_STATE_NAMES, op)))
            out.append(_kv(f"  [{i}] event_message_enable", em))
        return out


@dataclass
class GetStateSensorReadingsRequest:
    sensor_id: int
    sensor_rearm: int
    reserved: int
    def describe(self) -> List[str]:
        return [
            _kv("sensor_id", f"0x{self.sensor_id:04X}"),
            _kv("sensor_rearm", f"0x{self.sensor_rearm:02X}"),
            _kv("reserved", f"0x{self.reserved:02X}"),
        ]


@dataclass
class _StateField:
    sensor_op_state: int
    present_state: int
    previous_state: int
    event_state: int


@dataclass
class GetStateSensorReadingsResponse:
    composite_sensor_count: int
    fields: List[_StateField]
    def describe(self) -> List[str]:
        out = [_kv("composite_sensor_count", self.composite_sensor_count)]
        for i, f in enumerate(self.fields):
            out.append(_kv(f"  [{i}] sensor_op_state",
                           _name_or_unknown(OP_STATE_NAMES, f.sensor_op_state)))
            out.append(_kv(f"  [{i}] present_state", f.present_state))
            out.append(_kv(f"  [{i}] previous_state", f.previous_state))
            out.append(_kv(f"  [{i}] event_state",
                           _name_or_unknown(EVENT_STATE_NAMES, f.event_state)))
        return out


def _decode_set_state_sensor_enables_req(b: bytes) -> SetStateSensorEnablesRequest:
    r = ByteReader(b)
    sid = r.read_u16_le()
    n = r.read_u8()
    fields: List[Tuple[int, int]] = []
    for _ in range(min(n, r.remaining // 2)):
        op = r.read_u8()
        em = r.read_u8()
        fields.append((op, em))
    return SetStateSensorEnablesRequest(sid, n, fields)


def _decode_get_state_sensor_readings_req(b: bytes) -> GetStateSensorReadingsRequest:
    r = ByteReader(b)
    return GetStateSensorReadingsRequest(
        sensor_id=r.read_u16_le(),
        sensor_rearm=r.read_u8(),
        reserved=r.read_u8() if r.remaining else 0,
    )


def _decode_get_state_sensor_readings_rsp(b: bytes) -> GetStateSensorReadingsResponse:
    r = ByteReader(b)
    n = r.read_u8()
    fields: List[_StateField] = []
    for _ in range(min(n, r.remaining // 4)):
        fields.append(_StateField(
            sensor_op_state=r.read_u8(),
            present_state=r.read_u8(),
            previous_state=r.read_u8(),
            event_state=r.read_u8(),
        ))
    return GetStateSensorReadingsResponse(n, fields)


# ---------------------------------------------------------------------------
# Platform - Numeric Effecter (DSP0248 22.x)
# ---------------------------------------------------------------------------

@dataclass
class SetNumericEffecterEnableRequest:
    effecter_id: int
    effecter_operational_state: int
    def describe(self) -> List[str]:
        return [
            _kv("effecter_id", f"0x{self.effecter_id:04X}"),
            _kv("effecter_operational_state",
                _name_or_unknown(EFFECTER_OP_STATE_NAMES,
                                 self.effecter_operational_state)),
        ]


@dataclass
class SetNumericEffecterValueRequest:
    effecter_id: int
    effecter_data_size: int
    effecter_value: int
    def describe(self) -> List[str]:
        return [
            _kv("effecter_id", f"0x{self.effecter_id:04X}"),
            _kv("effecter_data_size",
                _name_or_unknown(EFFECTER_DATA_SIZE_NAMES, self.effecter_data_size)),
            _kv("effecter_value", self.effecter_value),
        ]


@dataclass
class GetNumericEffecterValueResponse:
    effecter_data_size: int
    effecter_operational_state: int
    pending_value: int
    present_value: int
    def describe(self) -> List[str]:
        return [
            _kv("effecter_data_size",
                _name_or_unknown(EFFECTER_DATA_SIZE_NAMES, self.effecter_data_size)),
            _kv("effecter_operational_state",
                _name_or_unknown(EFFECTER_OP_STATE_NAMES,
                                 self.effecter_operational_state)),
            _kv("pending_value", self.pending_value),
            _kv("present_value", self.present_value),
        ]


def _decode_set_numeric_effecter_enable_req(b: bytes) -> SetNumericEffecterEnableRequest:
    r = ByteReader(b)
    return SetNumericEffecterEnableRequest(
        effecter_id=r.read_u16_le(),
        effecter_operational_state=r.read_u8(),
    )


def _decode_set_numeric_effecter_value_req(b: bytes) -> SetNumericEffecterValueRequest:
    r = ByteReader(b)
    eid = r.read_u16_le()
    ds = r.read_u8()
    val = _read_signed_value(r, ds)
    return SetNumericEffecterValueRequest(eid, ds, val)


def _decode_get_numeric_effecter_value_req(b: bytes):
    r = ByteReader(b)
    return _SensorIdOnlyRequest(sensor_id=r.read_u16_le())  # reuse for effecter_id


def _decode_get_numeric_effecter_value_rsp(b: bytes) -> GetNumericEffecterValueResponse:
    r = ByteReader(b)
    ds = r.read_u8()
    op = r.read_u8()
    pending = _read_signed_value(r, ds)
    present = _read_signed_value(r, ds)
    return GetNumericEffecterValueResponse(ds, op, pending, present)


# ---------------------------------------------------------------------------
# Platform - State Effecter (DSP0248 23.x)
# ---------------------------------------------------------------------------

@dataclass
class SetStateEffecterEnablesRequest:
    effecter_id: int
    composite_effecter_count: int
    fields: List[Tuple[int, int]]  # (op_state, event_message_enable)
    def describe(self) -> List[str]:
        out = [
            _kv("effecter_id", f"0x{self.effecter_id:04X}"),
            _kv("composite_effecter_count", self.composite_effecter_count),
        ]
        for i, (op, em) in enumerate(self.fields):
            out.append(_kv(f"  [{i}] effecter_op_state",
                           _name_or_unknown(EFFECTER_OP_STATE_NAMES, op)))
            out.append(_kv(f"  [{i}] event_message_enable", em))
        return out


@dataclass
class SetStateEffecterStatesRequest:
    effecter_id: int
    composite_effecter_count: int
    fields: List[Tuple[int, int]]  # (set_request, effecter_state)
    def describe(self) -> List[str]:
        out = [
            _kv("effecter_id", f"0x{self.effecter_id:04X}"),
            _kv("composite_effecter_count", self.composite_effecter_count),
        ]
        for i, (sr, st) in enumerate(self.fields):
            out.append(_kv(f"  [{i}] set_request",
                           "noChange" if sr == 0 else "requestSet"))
            out.append(_kv(f"  [{i}] effecter_state", st))
        return out


@dataclass
class _EffStateField:
    op_state: int
    pending_state: int
    present_state: int


@dataclass
class GetStateEffecterStatesResponse:
    composite_effecter_count: int
    fields: List[_EffStateField]
    def describe(self) -> List[str]:
        out = [_kv("composite_effecter_count", self.composite_effecter_count)]
        for i, f in enumerate(self.fields):
            out.append(_kv(f"  [{i}] op_state",
                           _name_or_unknown(EFFECTER_OP_STATE_NAMES, f.op_state)))
            out.append(_kv(f"  [{i}] pending_state", f.pending_state))
            out.append(_kv(f"  [{i}] present_state", f.present_state))
        return out


def _decode_set_state_effecter_enables_req(b: bytes) -> SetStateEffecterEnablesRequest:
    r = ByteReader(b)
    eid = r.read_u16_le()
    n = r.read_u8()
    fields = []
    for _ in range(min(n, r.remaining // 2)):
        op = r.read_u8()
        em = r.read_u8()
        fields.append((op, em))
    return SetStateEffecterEnablesRequest(eid, n, fields)


def _decode_set_state_effecter_states_req(b: bytes) -> SetStateEffecterStatesRequest:
    r = ByteReader(b)
    eid = r.read_u16_le()
    n = r.read_u8()
    fields = []
    for _ in range(min(n, r.remaining // 2)):
        sr = r.read_u8()
        st = r.read_u8()
        fields.append((sr, st))
    return SetStateEffecterStatesRequest(eid, n, fields)


def _decode_get_state_effecter_states_req(b: bytes):
    r = ByteReader(b)
    return _SensorIdOnlyRequest(sensor_id=r.read_u16_le())  # reuses "id" formatting


def _decode_get_state_effecter_states_rsp(b: bytes) -> GetStateEffecterStatesResponse:
    r = ByteReader(b)
    n = r.read_u8()
    fields = []
    for _ in range(min(n, r.remaining // 3)):
        fields.append(_EffStateField(
            op_state=r.read_u8(),
            pending_state=r.read_u8(),
            present_state=r.read_u8(),
        ))
    return GetStateEffecterStatesResponse(n, fields)


# ---------------------------------------------------------------------------
# Platform - PDR repository (DSP0248 24.x)
# ---------------------------------------------------------------------------

@dataclass
class GetPDRRepositoryInfoResponse:
    repository_state: int
    update_time: bytes      # 13-byte PLDM Timestamp104
    oem_update_time: bytes  # 13-byte PLDM Timestamp104
    record_count: int
    repository_size: int
    largest_record_size: int
    data_transfer_handle_timeout: int
    def describe(self) -> List[str]:
        return [
            _kv("repository_state",
                _name_or_unknown(REPOSITORY_STATE_NAMES, self.repository_state)),
            _bytes_field("update_time (Timestamp104)", self.update_time),
            _bytes_field("oem_update_time (Timestamp104)", self.oem_update_time),
            _kv("record_count", self.record_count),
            _kv("repository_size (B)", self.repository_size),
            _kv("largest_record_size (B)", self.largest_record_size),
            _kv("data_transfer_handle_timeout (s)",
                self.data_transfer_handle_timeout),
        ]


@dataclass
class FindPDRRequest:
    raw: bytes
    def describe(self) -> List[str]:
        # FindPDR has a complex filter payload; show raw + length until we
        # implement structured decoding.
        return [_bytes_field("find_pdr_filter", self.raw)]


@dataclass
class FindPDRResponse:
    raw: bytes
    def describe(self) -> List[str]:
        return [_bytes_field("find_pdr_result", self.raw)]


@dataclass
class RunInitAgentRequest:
    init_agent_flag: int
    def describe(self) -> List[str]:
        return [_kv("init_agent_flag", self.init_agent_flag)]


@dataclass
class GetPDRRepositorySignatureResponse:
    signature: bytes
    def describe(self) -> List[str]:
        return [_bytes_field("signature", self.signature)]


def _decode_get_pdr_repo_info_rsp(b: bytes) -> GetPDRRepositoryInfoResponse:
    r = ByteReader(b)
    state = r.read_u8()
    upd = r.read(13)
    oem_upd = r.read(13)
    rc = r.read_u32_le()
    rs = r.read_u32_le()
    lrs = r.read_u32_le()
    dth_to = r.read_u8()
    return GetPDRRepositoryInfoResponse(state, upd, oem_upd, rc, rs, lrs, dth_to)


def _decode_find_pdr_req(b: bytes) -> FindPDRRequest:
    return FindPDRRequest(raw=b)


def _decode_find_pdr_rsp(b: bytes) -> FindPDRResponse:
    return FindPDRResponse(raw=b)


def _decode_run_init_agent_req(b: bytes) -> RunInitAgentRequest:
    r = ByteReader(b)
    return RunInitAgentRequest(init_agent_flag=r.read_u8())


def _decode_get_pdr_repo_signature_rsp(b: bytes) -> GetPDRRepositorySignatureResponse:
    return GetPDRRepositorySignatureResponse(signature=b)


# ---------------------------------------------------------------------------
# Dispatch registry
# ---------------------------------------------------------------------------

DecoderFn = Callable[[bytes], object]

# Key: (pldm_type, command, is_request)
COMMAND_DECODERS: Dict[Tuple[int, int, bool], DecoderFn] = {
    # ---- PLDM Base (DSP0240) ----
    (PLDM_TYPE_BASE, BASE_CMD_SET_TID, True): _decode_set_tid_req,
    (PLDM_TYPE_BASE, BASE_CMD_GET_TID, False): _decode_get_tid_rsp,
    (PLDM_TYPE_BASE, BASE_CMD_GET_PLDM_VERSION, True):  _decode_get_pldm_version_req,
    (PLDM_TYPE_BASE, BASE_CMD_GET_PLDM_VERSION, False): _decode_get_pldm_version_rsp,
    (PLDM_TYPE_BASE, BASE_CMD_GET_PLDM_TYPES, False):   _decode_get_pldm_types_rsp,
    (PLDM_TYPE_BASE, BASE_CMD_GET_PLDM_COMMANDS, True):  _decode_get_pldm_commands_req,
    (PLDM_TYPE_BASE, BASE_CMD_GET_PLDM_COMMANDS, False): _decode_get_pldm_commands_rsp,

    # ---- Platform - Terminus ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_TID, True): _decode_set_tid_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_TID, False): _decode_get_tid_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_TERMINUS_UID, False):
        lambda b: GetTerminusUIDResponse(uid=b[:16]),
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_EVENT_RECEIVER, True):
        _decode_set_event_receiver_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_EVENT_RECEIVER, False):
        _decode_get_event_receiver_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_PLATFORM_EVENT_MESSAGE, True):
        _decode_platform_event_msg_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_PLATFORM_EVENT_MESSAGE, False):
        _decode_platform_event_msg_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_POLL_FOR_PLATFORM_EVENT_MESSAGE, True):
        _decode_poll_event_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_POLL_FOR_PLATFORM_EVENT_MESSAGE, False):
        _decode_poll_event_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_EVENT_MESSAGE_SUPPORTED, True):
        _decode_event_msg_supported_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_EVENT_MESSAGE_SUPPORTED, False):
        _decode_event_msg_supported_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_EVENT_MESSAGE_BUFFER_SIZE, True):
        _decode_event_msg_buffer_size_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_EVENT_MESSAGE_BUFFER_SIZE, False):
        _decode_event_msg_buffer_size_rsp,

    # ---- Platform - Numeric Sensor ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_NUMERIC_SENSOR_ENABLE, True):
        _decode_set_num_sensor_enable_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_READING, True):
        _decode_get_sensor_reading_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_READING, False):
        _decode_get_sensor_reading_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_THRESHOLDS, True):
        _decode_get_sensor_thresholds_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_THRESHOLDS, False):
        _decode_get_sensor_thresholds_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_SENSOR_THRESHOLDS, True):
        _decode_set_sensor_thresholds_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_RESTORE_SENSOR_THRESHOLDS, True):
        _decode_get_sensor_thresholds_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_HYSTERESIS, True):
        _decode_get_sensor_thresholds_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_SENSOR_HYSTERESIS, False):
        _decode_get_sensor_hysteresis_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_SENSOR_HYSTERESIS, True):
        _decode_set_sensor_hysteresis_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_INIT_NUMERIC_SENSOR, True):
        _decode_init_numeric_sensor_req,

    # ---- Platform - State Sensor ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_STATE_SENSOR_ENABLES, True):
        _decode_set_state_sensor_enables_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_STATE_SENSOR_READINGS, True):
        _decode_get_state_sensor_readings_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_STATE_SENSOR_READINGS, False):
        _decode_get_state_sensor_readings_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_INIT_STATE_SENSOR, True):
        _decode_set_state_sensor_enables_req,  # same layout family

    # ---- Platform - Numeric Effecter ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_NUMERIC_EFFECTER_ENABLE, True):
        _decode_set_numeric_effecter_enable_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_NUMERIC_EFFECTER_VALUE, True):
        _decode_set_numeric_effecter_value_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_NUMERIC_EFFECTER_VALUE, True):
        _decode_get_numeric_effecter_value_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_NUMERIC_EFFECTER_VALUE, False):
        _decode_get_numeric_effecter_value_rsp,

    # ---- Platform - State Effecter ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_STATE_EFFECTER_ENABLES, True):
        _decode_set_state_effecter_enables_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_SET_STATE_EFFECTER_STATES, True):
        _decode_set_state_effecter_states_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_STATE_EFFECTER_STATES, True):
        _decode_get_state_effecter_states_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_STATE_EFFECTER_STATES, False):
        _decode_get_state_effecter_states_rsp,

    # ---- Platform - PDR Repository (GetPDR handled in pldm_platform.py) ----
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_PDR_REPOSITORY_INFO, False):
        _decode_get_pdr_repo_info_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_FIND_PDR, True):  _decode_find_pdr_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_FIND_PDR, False): _decode_find_pdr_rsp,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_RUN_INIT_AGENT, True):
        _decode_run_init_agent_req,
    (PLDM_TYPE_PLATFORM, PLATFORM_CMD_GET_PDR_REPOSITORY_SIGNATURE, False):
        _decode_get_pdr_repo_signature_rsp,
}


def find_decoder(pldm_type: int, command: int, is_request: bool) -> Optional[DecoderFn]:
    return COMMAND_DECODERS.get((pldm_type, command, is_request))
