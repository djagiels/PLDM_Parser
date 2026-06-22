"""Tests for DSP0240 Base and DSP0248 Platform command decoders."""

from pldm_parser import parse_frame
from pldm_parser.platform_commands import (
    GetTIDResponse,
    SetTIDRequest,
    GetPLDMTypesResponse,
    GetPLDMVersionRequest,
    GetTerminusUIDResponse,
    PlatformEventMessageRequest,
    PlatformEventMessageResponse,
    EventMessageBufferSizeResponse,
    GetSensorReadingRequest,
    GetSensorReadingResponse,
    GetStateSensorReadingsRequest,
    GetStateSensorReadingsResponse,
    SetNumericEffecterValueRequest,
    GetNumericEffecterValueResponse,
    SetStateEffecterStatesRequest,
    GetStateEffecterStatesResponse,
    GetPDRRepositoryInfoResponse,
)


def _mctp_pldm_req(instance: int, pldm_type: int, cmd: int, payload: bytes) -> bytes:
    # MCTP header: hdr_ver=1, dst=09, src=11, SOM|EOM|TO
    mctp = bytes([0x01, 0x09, 0x11, 0xC8])
    # PLDM msg type byte
    msg = bytes([0x01])
    # PLDM request header
    b0 = 0x80 | (instance & 0x1F)
    b1 = pldm_type & 0x3F
    hdr = bytes([b0, b1, cmd])
    return mctp + msg + hdr + payload


def _mctp_pldm_rsp(instance: int, pldm_type: int, cmd: int, cc: int, payload: bytes) -> bytes:
    mctp = bytes([0x01, 0x11, 0x09, 0xC0])  # response: TO=0
    msg = bytes([0x01])
    b0 = instance & 0x1F
    b1 = pldm_type & 0x3F
    hdr = bytes([b0, b1, cmd, cc])
    return mctp + msg + hdr + payload


# ---------------- Base ----------------

def test_set_tid_request():
    f = parse_frame(_mctp_pldm_req(1, 0x00, 0x01, bytes([0x55])),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, SetTIDRequest)
    assert f.pldm_payload.tid == 0x55


def test_get_tid_response():
    f = parse_frame(_mctp_pldm_rsp(1, 0x00, 0x02, 0x00, bytes([0x42])),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetTIDResponse)
    assert f.pldm_payload.tid == 0x42


def test_get_pldm_types_response():
    # Bitmap: types 0 (base), 2 (platform), 4 (FRU) supported -> 0x15 in byte 0.
    f = parse_frame(_mctp_pldm_rsp(1, 0x00, 0x04, 0x00,
                                   bytes([0x15, 0, 0, 0, 0, 0, 0, 0])),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetPLDMTypesResponse)
    desc = "\n".join(f.pldm_payload.describe())
    assert "0x00" in desc and "0x02" in desc and "0x04" in desc


def test_get_pldm_version_request():
    payload = bytes([0, 0, 0, 0, 1, 2])  # dth=0, op=GetFirstPart, type=Platform
    f = parse_frame(_mctp_pldm_req(1, 0x00, 0x03, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetPLDMVersionRequest)
    assert f.pldm_payload.transfer_operation_flag == 1
    assert f.pldm_payload.pldm_type == 2


# ---------------- Platform terminus ----------------

def test_get_terminus_uid_response():
    uid = bytes(range(16))
    f = parse_frame(_mctp_pldm_rsp(2, 0x02, 0x03, 0x00, uid),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetTerminusUIDResponse)
    assert f.pldm_payload.uid == uid
    assert "-" in "\n".join(f.pldm_payload.describe())  # formatted UUID


def test_platform_event_message_request_and_response():
    # request: format=1, tid=0x15, eventClass=0x00 (sensorEvent), data=4 bytes
    req = parse_frame(
        _mctp_pldm_req(3, 0x02, 0x0A,
                       bytes([0x01, 0x15, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])),
        has_intel_prefix=False,
    )
    assert isinstance(req.pldm_payload, PlatformEventMessageRequest)
    assert req.pldm_payload.event_class == 0
    assert req.pldm_payload.event_data == bytes([0xDE, 0xAD, 0xBE, 0xEF])

    rsp = parse_frame(
        _mctp_pldm_rsp(3, 0x02, 0x0A, 0x00, bytes([0x00])),
        has_intel_prefix=False,
    )
    assert isinstance(rsp.pldm_payload, PlatformEventMessageResponse)
    assert rsp.pldm_payload.platform_event_status == 0


def test_event_message_buffer_size_response():
    f = parse_frame(_mctp_pldm_rsp(4, 0x02, 0x0D, 0x00, bytes([0x00, 0x02])),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, EventMessageBufferSizeResponse)
    assert f.pldm_payload.terminus_max_buffer_size == 0x0200


# ---------------- Numeric sensor ----------------

def test_get_sensor_reading_request_and_response():
    req = parse_frame(
        _mctp_pldm_req(5, 0x02, 0x11, bytes([0x10, 0x00, 0x01])),
        has_intel_prefix=False,
    )
    assert isinstance(req.pldm_payload, GetSensorReadingRequest)
    assert req.pldm_payload.sensor_id == 0x10
    assert req.pldm_payload.rearm_event_state == 1

    # response: data_size=uint8, op=enabled, em=0, present=normal, prev=normal,
    # event=normal, reading=0x37
    rsp_payload = bytes([0, 0, 0, 1, 1, 1, 0x37])
    rsp = parse_frame(
        _mctp_pldm_rsp(5, 0x02, 0x11, 0x00, rsp_payload),
        has_intel_prefix=False,
    )
    assert isinstance(rsp.pldm_payload, GetSensorReadingResponse)
    assert rsp.pldm_payload.present_reading == 0x37
    assert rsp.pldm_payload.sensor_data_size == 0


def test_get_sensor_reading_response_sint16():
    # data_size=sint16 (3), reading -1 = 0xFF FF (LE)
    rsp_payload = bytes([3, 0, 0, 1, 1, 1, 0xFF, 0xFF])
    rsp = parse_frame(_mctp_pldm_rsp(5, 0x02, 0x11, 0x00, rsp_payload),
                      has_intel_prefix=False)
    assert isinstance(rsp.pldm_payload, GetSensorReadingResponse)
    assert rsp.pldm_payload.present_reading == -1


# ---------------- State sensor ----------------

def test_get_state_sensor_readings():
    # request: sensor_id=5, rearm=0xFF, reserved=0
    req = parse_frame(
        _mctp_pldm_req(6, 0x02, 0x21, bytes([0x05, 0x00, 0xFF, 0x00])),
        has_intel_prefix=False,
    )
    assert isinstance(req.pldm_payload, GetStateSensorReadingsRequest)
    assert req.pldm_payload.sensor_id == 5
    assert req.pldm_payload.sensor_rearm == 0xFF

    # response: 2 composite sensors
    rsp_payload = bytes([
        2,
        0, 1, 1, 1,  # field 0: enabled, normal, normal, normal
        0, 2, 1, 2,  # field 1: enabled, warning, normal, warning
    ])
    rsp = parse_frame(
        _mctp_pldm_rsp(6, 0x02, 0x21, 0x00, rsp_payload),
        has_intel_prefix=False,
    )
    assert isinstance(rsp.pldm_payload, GetStateSensorReadingsResponse)
    assert rsp.pldm_payload.composite_sensor_count == 2
    assert len(rsp.pldm_payload.fields) == 2
    assert rsp.pldm_payload.fields[1].event_state == 2


# ---------------- Numeric effecter ----------------

def test_set_numeric_effecter_value_request():
    # effecter_id=0x100, data_size=uint16, value=0x1234
    payload = bytes([0x00, 0x01, 2, 0x34, 0x12])
    f = parse_frame(_mctp_pldm_req(7, 0x02, 0x31, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, SetNumericEffecterValueRequest)
    assert f.pldm_payload.effecter_id == 0x100
    assert f.pldm_payload.effecter_data_size == 2
    assert f.pldm_payload.effecter_value == 0x1234


def test_get_numeric_effecter_value_response():
    # data_size=uint8, op=Enabled-noUpdatePending(1), pending=10, present=11
    payload = bytes([0, 1, 10, 11])
    f = parse_frame(_mctp_pldm_rsp(8, 0x02, 0x32, 0x00, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetNumericEffecterValueResponse)
    assert f.pldm_payload.pending_value == 10
    assert f.pldm_payload.present_value == 11


# ---------------- State effecter ----------------

def test_set_state_effecter_states_request():
    # effecter_id=0x200, 2 composite, [requestSet,5],[noChange,0]
    payload = bytes([0x00, 0x02, 2, 1, 5, 0, 0])
    f = parse_frame(_mctp_pldm_req(9, 0x02, 0x39, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, SetStateEffecterStatesRequest)
    assert f.pldm_payload.effecter_id == 0x200
    assert f.pldm_payload.fields == [(1, 5), (0, 0)]


def test_get_state_effecter_states_response():
    payload = bytes([
        2,
        1, 0, 5,
        0, 3, 3,
    ])
    f = parse_frame(_mctp_pldm_rsp(10, 0x02, 0x3A, 0x00, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetStateEffecterStatesResponse)
    assert f.pldm_payload.composite_effecter_count == 2
    assert f.pldm_payload.fields[0].present_state == 5
    assert f.pldm_payload.fields[1].pending_state == 3


# ---------------- PDR repository ----------------

def test_get_pdr_repository_info_response():
    payload = (
        bytes([0]) +                  # repository_state = available
        bytes(13) +                   # update_time
        bytes(13) +                   # oem_update_time
        (0x12).to_bytes(4, "little") +  # record_count
        (0x100).to_bytes(4, "little") + # repository_size
        (0x40).to_bytes(4, "little") +  # largest_record_size
        bytes([30])                    # dth timeout
    )
    f = parse_frame(_mctp_pldm_rsp(11, 0x02, 0x50, 0x00, payload),
                    has_intel_prefix=False)
    assert isinstance(f.pldm_payload, GetPDRRepositoryInfoResponse)
    assert f.pldm_payload.record_count == 0x12
    assert f.pldm_payload.repository_size == 0x100
    assert f.pldm_payload.largest_record_size == 0x40
    assert f.pldm_payload.data_transfer_handle_timeout == 30


# ---------------- Error / robustness ----------------

def test_non_success_completion_code_records_warning():
    # GetSensorReading response with CC = INVALID_SENSOR_ID (0x88), empty body
    f = parse_frame(_mctp_pldm_rsp(12, 0x02, 0x11, 0x88, b""),
                    has_intel_prefix=False)
    assert f.pldm_header.completion_code == 0x88
    assert any("non-success" in n.message.lower() or "non-zero" in n.message.lower()
               or "0x88" in n.message for n in f.notes)


def test_unknown_platform_command_kept_raw_with_note():
    # Make up command 0x99 in Platform type
    f = parse_frame(_mctp_pldm_req(13, 0x02, 0x99, b"\x01\x02\x03"),
                    has_intel_prefix=False)
    assert f.pldm_payload == b"\x01\x02\x03"
    assert any("no structured decoder" in n.message for n in f.notes)
