"""Threaded TCP transport for SecureVault protocol messages."""
from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from .protocol import ConnectionClosedError, ProtocolError, receive_message, send_message
from .request_handler import RequestHandler


class SecureVaultTCPServer:
    def __init__(self, handler: RequestHandler, host: str = "127.0.0.1", port: int = 0,
                 backlog: int = 64, workers: int = 16) -> None:
        self.handler = handler
        self.host = host
        self.port = port
        self.backlog = backlog
        self._socket: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="securevault")

    @property
    def address(self) -> tuple[str, int]:
        if self._socket is None:
            return self.host, self.port
        return self._socket.getsockname()[:2]

    def start(self) -> tuple[str, int]:
        if self._socket is not None:
            return self.address
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(self.backlog)
        self._socket.settimeout(0.25)
        self._thread = threading.Thread(target=self._serve, name="securevault-accept", daemon=True)
        self._thread.start()
        return self.address

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._pool.submit(self._connection_loop, connection)

    def _connection_loop(self, connection: socket.socket) -> None:
        with connection:
            while not self._stop.is_set():
                try:
                    request = receive_message(connection)
                except (ConnectionClosedError, OSError):
                    return
                except ProtocolError:
                    return
                response = self.handler.dispatch(request)
                try:
                    send_message(connection, response)
                except OSError:
                    return

    def close(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=1)
            self._thread = None
        self._pool.shutdown(wait=True, cancel_futures=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_args) -> None:
        self.close()


class SecureVaultTCPClient:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self._socket: socket.socket | None = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        if self._socket is None:
            self._socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self._socket.settimeout(self.timeout)

    def request(self, message):
        with self._lock:
            self.connect()
            try:
                send_message(self._socket, message)
                return receive_message(self._socket)
            except (OSError, ConnectionClosedError):
                self.close()
                raise

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_args) -> None:
        self.close()
