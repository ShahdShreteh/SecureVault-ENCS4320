import base64
import json
import secrets
import socket
from dataclasses import dataclass


PROTOCOL_VERSION = 1
HEADER_SIZE = 4
MAX_FRAME_SIZE = 8 * 1024 * 1024

VALID_KINDS = {
    "request",
    "response",
}

BYTES_MARKER = "__securevault_bytes__"


class ProtocolError(ValueError):
    pass


class FrameTooLargeError(ProtocolError):
    pass


class ConnectionClosedError(ProtocolError):
    pass


@dataclass(frozen=True)
class ProtocolMessage:
    kind: str
    operation: str
    request_id: str
    payload: dict
    session_token: str | None = None
    success: bool | None = None
    error_code: str | None = None
    error_message: str | None = None


def generate_request_id() -> str:
    return secrets.token_hex(16)


def _validate_text(
    value: str,
    name: str,
) -> None:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string"
        )

    if not value.strip():
        raise ProtocolError(
            f"{name} cannot be empty."
        )


def _encode_value(value):
    if isinstance(value, bytes):
        return {
            BYTES_MARKER: (
                base64.b64encode(
                    value
                ).decode("ascii")
            )
        }

    if isinstance(value, dict):
        return {
            key: _encode_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _encode_value(item)
            for item in value
        ]

    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ) or value is None:
        return value

    raise ProtocolError(
        f"Unsupported payload type: {type(value).__name__}"
    )


def _decode_value(value):
    if isinstance(value, list):
        return [
            _decode_value(item)
            for item in value
        ]

    if isinstance(value, dict):
        if (
            len(value) == 1
            and BYTES_MARKER in value
        ):
            encoded = value[
                BYTES_MARKER
            ]

            if not isinstance(
                encoded,
                str,
            ):
                raise ProtocolError(
                    "Invalid encoded bytes."
                )

            try:
                return base64.b64decode(
                    encoded,
                    validate=True,
                )

            except Exception as error:
                raise ProtocolError(
                    "Invalid base64 data."
                ) from error

        return {
            key: _decode_value(item)
            for key, item in value.items()
        }

    return value


def _validate_message(
    message: ProtocolMessage,
) -> None:
    if not isinstance(
        message,
        ProtocolMessage,
    ):
        raise TypeError(
            "message must be ProtocolMessage"
        )

    if message.kind not in VALID_KINDS:
        raise ProtocolError(
            "Invalid message kind."
        )

    _validate_text(
        message.operation,
        "operation",
    )

    _validate_text(
        message.request_id,
        "request_id",
    )

    if not isinstance(
        message.payload,
        dict,
    ):
        raise TypeError(
            "payload must be a dictionary"
        )

    if (
        message.session_token
        is not None
        and not isinstance(
            message.session_token,
            str,
        )
    ):
        raise TypeError(
            "session_token must be a string or None"
        )

    if message.kind == "request":
        if message.success is not None:
            raise ProtocolError(
                "Request cannot contain success status."
            )

    if message.kind == "response":
        if not isinstance(
            message.success,
            bool,
        ):
            raise ProtocolError(
                "Response must contain success status."
            )


def create_request(
    operation: str,
    payload: dict | None = None,
    session_token: str | None = None,
    request_id: str | None = None,
) -> ProtocolMessage:
    if request_id is None:
        request_id = (
            generate_request_id()
        )

    if payload is None:
        payload = {}

    message = ProtocolMessage(
        kind="request",
        operation=operation,
        request_id=request_id,
        payload=payload,
        session_token=session_token,
    )

    _validate_message(
        message
    )

    return message


def create_response(
    request: ProtocolMessage,
    success: bool,
    payload: dict | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
) -> ProtocolMessage:
    if not isinstance(
        request,
        ProtocolMessage,
    ):
        raise TypeError(
            "request must be ProtocolMessage"
        )

    if request.kind != "request":
        raise ProtocolError(
            "Response must reference a request."
        )

    if payload is None:
        payload = {}

    response = ProtocolMessage(
        kind="response",
        operation=request.operation,
        request_id=request.request_id,
        payload=payload,
        success=success,
        error_code=error_code,
        error_message=error_message,
    )

    _validate_message(
        response
    )

    return response


def serialize_message(
    message: ProtocolMessage,
) -> bytes:
    _validate_message(
        message
    )

    body = {
        "version": PROTOCOL_VERSION,
        "kind": message.kind,
        "operation": message.operation,
        "request_id": message.request_id,
        "payload": _encode_value(
            message.payload
        ),
        "session_token": (
            message.session_token
        ),
        "success": message.success,
        "error_code": (
            message.error_code
        ),
        "error_message": (
            message.error_message
        ),
    }

    try:
        encoded = json.dumps(
            body,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    except (
        TypeError,
        ValueError,
    ) as error:
        raise ProtocolError(
            "Message cannot be serialized."
        ) from error

    if len(encoded) > MAX_FRAME_SIZE:
        raise FrameTooLargeError(
            "Message exceeds maximum frame size."
        )

    return encoded


def deserialize_message(
    data: bytes,
) -> ProtocolMessage:
    if not isinstance(
        data,
        bytes,
    ):
        raise TypeError(
            "data must be bytes"
        )

    if len(data) == 0:
        raise ProtocolError(
            "Message cannot be empty."
        )

    if len(data) > MAX_FRAME_SIZE:
        raise FrameTooLargeError(
            "Message exceeds maximum frame size."
        )

    try:
        body = json.loads(
            data.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise ProtocolError(
            "Invalid protocol message."
        ) from error

    if not isinstance(
        body,
        dict,
    ):
        raise ProtocolError(
            "Protocol message must be an object."
        )

    if body.get("version") != (
        PROTOCOL_VERSION
    ):
        raise ProtocolError(
            "Unsupported protocol version."
        )

    required = {
        "kind",
        "operation",
        "request_id",
        "payload",
    }

    if not required.issubset(
        body
    ):
        raise ProtocolError(
            "Missing protocol fields."
        )

    payload = _decode_value(
        body["payload"]
    )

    message = ProtocolMessage(
        kind=body["kind"],
        operation=body["operation"],
        request_id=body["request_id"],
        payload=payload,
        session_token=body.get(
            "session_token"
        ),
        success=body.get(
            "success"
        ),
        error_code=body.get(
            "error_code"
        ),
        error_message=body.get(
            "error_message"
        ),
    )

    _validate_message(
        message
    )

    return message


def encode_frame(
    message: ProtocolMessage,
) -> bytes:
    body = serialize_message(
        message
    )

    header = len(body).to_bytes(
        HEADER_SIZE,
        "big",
    )

    return header + body


def _recv_exact(
    connection: socket.socket,
    length: int,
) -> bytes:
    if not isinstance(
        length,
        int,
    ):
        raise TypeError(
            "length must be an integer"
        )

    if length < 0:
        raise ProtocolError(
            "length cannot be negative."
        )

    result = bytearray()

    while len(result) < length:
        chunk = connection.recv(
            length - len(result)
        )

        if not chunk:
            raise ConnectionClosedError(
                "Connection closed before complete frame was received."
            )

        result.extend(
            chunk
        )

    return bytes(result)


def send_message(
    connection: socket.socket,
    message: ProtocolMessage,
) -> None:
    if not isinstance(
        connection,
        socket.socket,
    ):
        raise TypeError(
            "connection must be a socket"
        )

    frame = encode_frame(
        message
    )

    connection.sendall(
        frame
    )


def receive_message(
    connection: socket.socket,
) -> ProtocolMessage:
    if not isinstance(
        connection,
        socket.socket,
    ):
        raise TypeError(
            "connection must be a socket"
        )

    header = _recv_exact(
        connection,
        HEADER_SIZE,
    )

    length = int.from_bytes(
        header,
        "big",
    )

    if length <= 0:
        raise ProtocolError(
            "Invalid frame length."
        )

    if length > MAX_FRAME_SIZE:
        raise FrameTooLargeError(
            "Frame exceeds maximum size."
        )

    body = _recv_exact(
        connection,
        length,
    )

    return deserialize_message(
        body
    )