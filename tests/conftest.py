"""Test harness: fake Ghidra instances on loopback.

Every port used here lives in a private range far from the real Ghidra
instances (8080+), so a bridge that regained a habit of choosing for itself
still could not reach a real database from a test.
"""
import socket
import threading
import json
import http.server
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bridge_mcp_ghidra as bridge


def _free_block(size: int, start: int = 18080) -> int:
    """Find `size` consecutive free TCP ports, returning the first."""
    for base in range(start, start + 500, size):
        socks = []
        try:
            for i in range(size):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", base + i))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port block")


class FakeGhidra:
    """One Ghidra instance: answers /instances, records everything else."""

    def __init__(self, port, program, project="proj", file_id=None):
        self.port = port
        self.program = program
        self.project = project
        self.file_id = file_id
        self.requests = []            # (method, path, headers)
        self.answer_instances = True  # False -> /instances hangs
        self.refuse = False           # True -> answers 409, as the guard does
        self._release = threading.Event()
        self._release.set()
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)

            def _dispatch(self, method):
                self._body()
                path = self.path.split("?")[0]
                if path == "/instances":
                    if not fake.answer_instances:
                        fake._release.wait(timeout=30)
                    info = {"port": fake.port, "program": fake.program,
                            "project": fake.project}
                    if fake.file_id is not None:
                        info["file_id"] = fake.file_id
                    payload = json.dumps([info]).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                fake.requests.append((method, path, dict(self.headers)))
                if fake.refuse:
                    payload = (f"This instance holds {fake.program}; the request "
                               f"asked for another database.").encode()
                    self.send_response(409)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self._srv.daemon_threads = True
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    def go_silent(self):
        """Stop answering /instances, as a busy instance does."""
        self._release.clear()
        self.answer_instances = False

    def speak_again(self):
        self.answer_instances = True
        self._release.set()

    def shutdown(self):
        self._release.set()
        self._srv.shutdown()
        self._srv.server_close()


@pytest.fixture
def ghidra():
    """Factory for fake instances; cleans up and resets bridge state."""
    made = []
    base = _free_block(4)

    def make(offset, program, project="proj", file_id=None):
        inst = FakeGhidra(base + offset, program, project, file_id)
        made.append(inst)
        return inst

    make.base = base

    bridge.ghidra_request_timeout = 5
    bridge.active_instances = {}
    bridge.current_target = None
    bridge._discovery_base_port = base
    bridge._discovery_port_range = 4

    yield make

    for inst in made:
        try:
            inst.shutdown()
        except Exception:
            pass
    bridge.active_instances = {}
    bridge.current_target = None
