import json
import socket

import pytest

from src.network.protocol import (
    HEADER_SIZE,
    MAX_FRAME_SIZE,
    ConnectionClosedError,
    FrameTooLargeError,
    ProtocolError,
    ProtocolMessage,
    create_request,
    create_response,
    deserialize_message,
    encode_frame,
    generate_request_id,
    receive_message,
    send_message,
    serialize_message,
)


def test_request_id_is_random():

    first = generate_request_id()
    second = generate_request_id()

    assert first != second

    assert len(first) == 32

    assert len(second) == 32


def test_create_request():

    request = create_request(
        "login_begin",
        {
            "username": "Alice",
        },
    )

    assert (
        request.kind
        == "request"
    )

    assert (
        request.operation
        == "login_begin"
    )

    assert (
        request.payload
        == {
            "username": "Alice",
        }
    )

    assert (
        request.success
        is None
    )


def test_create_response():

    request = create_request(
        "login_begin"
    )

    response = create_response(
        request,
        True,
        {
            "challenge": "abc",
        },
    )

    assert (
        response.kind
        == "response"
    )

    assert response.success

    assert (
        response.request_id
        == request.request_id
    )

    assert (
        response.operation
        == request.operation
    )


def test_message_round_trip():

    original = create_request(
        "upload",
        {
            "document_id": "doc-001",
            "owner": "Alice",
        },
        session_token="token-123",
    )

    encoded = serialize_message(
        original
    )

    decoded = deserialize_message(
        encoded
    )

    assert decoded == original


def test_binary_payload_round_trip():

    original = create_request(
        "upload",
        {
            "iv": b"\x01" * 16,
            "ciphertext": (
                b"\x02" * 64
            ),
            "nested": {
                "tag": b"\x03" * 32,
            },
            "items": [
                b"\x04\x05",
                "hello",
            ],
        },
    )

    decoded = deserialize_message(
        serialize_message(
            original
        )
    )

    assert decoded == original


def test_unicode_payload_round_trip():

    original = create_request(
        "upload",
        {
            "filename": (
                "تقرير-سري.pdf"
            ),
        },
    )

    decoded = deserialize_message(
        serialize_message(
            original
        )
    )

    assert decoded == original


def test_frame_contains_length_prefix():

    request = create_request(
        "test"
    )

    frame = encode_frame(
        request
    )

    length = int.from_bytes(
        frame[:HEADER_SIZE],
        "big",
    )

    assert length == (
        len(frame) - HEADER_SIZE
    )


def test_socket_round_trip():

    client, server = (
        socket.socketpair()
    )

    try:
        request = create_request(
            "public_keys",
            {
                "username": "Bob",
            },
            session_token="abc",
        )

        send_message(
            client,
            request,
        )

        received = receive_message(
            server
        )

        assert received == request

    finally:
        client.close()
        server.close()


def test_multiple_messages_over_same_socket():

    client, server = (
        socket.socketpair()
    )

    try:
        first = create_request(
            "first"
        )

        second = create_request(
            "second",
            {
                "data": b"abc",
            },
        )

        send_message(
            client,
            first,
        )

        send_message(
            client,
            second,
        )

        assert (
            receive_message(
                server
            )
            == first
        )

        assert (
            receive_message(
                server
            )
            == second
        )

    finally:
        client.close()
        server.close()


def test_partial_socket_receive():

    client, server = (
        socket.socketpair()
    )

    try:
        request = create_request(
            "upload",
            {
                "data": b"A" * 1000,
            },
        )

        frame = encode_frame(
            request
        )

        for index in range(
            0,
            len(frame),
            7,
        ):
            client.sendall(
                frame[
                    index:index + 7
                ]
            )

        received = receive_message(
            server
        )

        assert received == request

    finally:
        client.close()
        server.close()


def test_invalid_json_rejected():

    with pytest.raises(
        ProtocolError
    ):
        deserialize_message(
            b"{invalid-json"
        )


def test_wrong_version_rejected():

    data = json.dumps(
        {
            "version": 999,
            "kind": "request",
            "operation": "test",
            "request_id": "abc",
            "payload": {},
        }
    ).encode("utf-8")

    with pytest.raises(
        ProtocolError
    ):
        deserialize_message(
            data
        )


def test_missing_fields_rejected():

    data = json.dumps(
        {
            "version": 1,
            "kind": "request",
        }
    ).encode("utf-8")

    with pytest.raises(
        ProtocolError
    ):
        deserialize_message(
            data
        )


def test_invalid_message_kind_rejected():

    message = ProtocolMessage(
        kind="invalid",
        operation="test",
        request_id="abc",
        payload={},
    )

    with pytest.raises(
        ProtocolError
    ):
        serialize_message(
            message
        )


def test_request_success_field_rejected():

    message = ProtocolMessage(
        kind="request",
        operation="test",
        request_id="abc",
        payload={},
        success=True,
    )

    with pytest.raises(
        ProtocolError
    ):
        serialize_message(
            message
        )


def test_response_without_success_rejected():

    message = ProtocolMessage(
        kind="response",
        operation="test",
        request_id="abc",
        payload={},
    )

    with pytest.raises(
        ProtocolError
    ):
        serialize_message(
            message
        )


def test_unsupported_payload_type_rejected():

    request = create_request(
        "test",
        {
            "bad": object(),
        },
    )

    with pytest.raises(
        ProtocolError
    ):
        serialize_message(
            request
        )


def test_invalid_base64_rejected():

    data = json.dumps(
        {
            "version": 1,
            "kind": "request",
            "operation": "test",
            "request_id": "abc",
            "payload": {
                "data": {
                    "__securevault_bytes__":
                    "%%%INVALID%%%"
                }
            },
            "session_token": None,
            "success": None,
            "error_code": None,
            "error_message": None,
        }
    ).encode("utf-8")

    with pytest.raises(
        ProtocolError
    ):
        deserialize_message(
            data
        )


def test_zero_length_frame_rejected():

    client, server = (
        socket.socketpair()
    )

    try:
        client.sendall(
            b"\x00\x00\x00\x00"
        )

        with pytest.raises(
            ProtocolError
        ):
            receive_message(
                server
            )

    finally:
        client.close()
        server.close()


def test_oversized_frame_header_rejected():

    client, server = (
        socket.socketpair()
    )

    try:
        client.sendall(
            (
                MAX_FRAME_SIZE + 1
            ).to_bytes(
                4,
                "big",
            )
        )

        with pytest.raises(
            FrameTooLargeError
        ):
            receive_message(
                server
            )

    finally:
        client.close()
        server.close()


def test_connection_closed_mid_frame():

    client, server = (
        socket.socketpair()
    )

    try:
        client.sendall(
            (100).to_bytes(
                4,
                "big",
            )
        )

        client.sendall(
            b"short"
        )

        client.close()

        with pytest.raises(
            ConnectionClosedError
        ):
            receive_message(
                server
            )

    finally:
        server.close()