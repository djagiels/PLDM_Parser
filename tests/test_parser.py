"""Round-trip tests against the example GetPDR(record_handle=0) exchange."""

from pldm_parser import parse_frame
from pldm_parser.pldm_platform import (
    GetPdrRequest,
    GetPdrResponse,
    XFER_FLAG_START_AND_END,
    XFER_OP_GET_FIRST_PART,
)
from pldm_parser.pdr import (
    PDR_TYPE_TERMINUS_LOCATOR,
    TerminusLocatorPdr,
)


REQ_HEX = (
    "72:00:10:05:00:41:30:7F:00:40:1A:B4:01:09:11:C8:"
    "01:88:02:51:00:00:00:00:00:00:00:00:01:50:00:00:00"
)

RSP_HEX = (
    "72:00:00:09:00:40:10:7F:00:41:1A:B4:01:11:09:C0:"
    "01:08:02:51:00:02:00:00:00:00:00:00:00:05:13:00:"
    "01:00:00:00:01:01:00:00:09:00:01:00:01:15:00:00:"
    "01:01:08"
)


def test_parse_get_pdr_request():
    f = parse_frame(REQ_HEX)
    assert f.intel_prefix is not None
    assert f.mctp_header is not None
    assert f.mctp_header.dest_eid == 9
    assert f.mctp_header.src_eid == 17
    assert f.mctp_header.som and f.mctp_header.eom
    assert f.mctp_header.to is True
    assert f.mctp_msg_type.msg_type == 0x01

    assert f.pldm_header is not None
    assert f.pldm_header.is_request
    assert f.pldm_header.instance_id == 8
    assert f.pldm_header.pldm_type == 0x02
    assert f.pldm_header.command == 0x51

    assert isinstance(f.pldm_payload, GetPdrRequest)
    req: GetPdrRequest = f.pldm_payload
    assert req.record_handle == 0
    assert req.data_transfer_handle == 0
    assert req.transfer_operation_flag == XFER_OP_GET_FIRST_PART
    assert req.request_count == 0x0050
    assert req.record_change_number == 0


def test_parse_get_pdr_response():
    f = parse_frame(RSP_HEX)
    assert f.intel_prefix is not None
    assert f.mctp_header.dest_eid == 17
    assert f.mctp_header.src_eid == 9
    assert f.mctp_header.to is False  # response

    assert f.pldm_header is not None
    assert not f.pldm_header.is_request
    assert f.pldm_header.instance_id == 8
    assert f.pldm_header.command == 0x51
    assert f.pldm_header.completion_code == 0x00

    assert isinstance(f.pldm_payload, GetPdrResponse)
    rsp: GetPdrResponse = f.pldm_payload
    assert rsp.next_record_handle == 2
    assert rsp.next_data_transfer_handle == 0
    assert rsp.transfer_flag == XFER_FLAG_START_AND_END
    assert rsp.response_count == 19
    assert len(rsp.record_data) == 19

    assert rsp.pdr is not None
    assert rsp.pdr.header.record_handle == 1
    assert rsp.pdr.header.pdr_type == PDR_TYPE_TERMINUS_LOCATOR
    assert rsp.pdr.header.data_length == 9

    body = rsp.pdr.body
    assert isinstance(body, TerminusLocatorPdr)
    assert body.pldm_terminus_handle == 1
    assert body.validity == 1
    assert body.tid == 0x15
    assert body.container_id == 0
    assert body.locator_type == 0x01  # MCTP_EID
    assert body.locator_value == bytes([0x08])


def test_to_text_runs():
    # Smoke test: pretty-printer must not raise on either frame.
    parse_frame(REQ_HEX).to_text()
    parse_frame(RSP_HEX).to_text()
