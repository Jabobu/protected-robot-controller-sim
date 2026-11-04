"""Tests for new transport gates, not simulator or supervisor acceptance."""
from threading import Event, Thread
from types import SimpleNamespace

import pytest
from protected_robot_controller.interface import MAX_REQUEST_BYTES
from protected_robot_controller.protocol import strict_decode
from tools.ros2_endpoint import MainThreadExchange, BUSY
from tools.ros2_fixture import RosFixture


def test_gate_serializes_hello_and_execute_during_execution():
    started, finish = Event(), Event()
    class Handler:
        def handle(self, data):
            started.set()
            assert finish.wait(timeout=2)
            return data
    exchange = MainThreadExchange(Handler())
    returned = []
    caller = Thread(target=lambda: returned.append(exchange.submit(b'first')))
    owner = Thread(target=lambda: exchange.pump_once(timeout=2))
    caller.start()
    owner.start()
    assert started.wait(timeout=2)
    assert exchange.submit(b'second') == BUSY
    finish.set()
    caller.join(timeout=2)
    owner.join(timeout=2)
    assert returned == [b'first']


def test_oversize_never_reaches_controller():
    class Handler:
        def handle(self, data):
            pytest.fail('oversize request reached controller')
    raw = MainThreadExchange(Handler()).submit(bytes(MAX_REQUEST_BYTES + 1))
    assert strict_decode(raw, 1024)['reason'] == 'SIZE'


def test_uncertain_dispatch_blocks_all_later_calls(tmp_path):
    class Request:
        request = None
    class Peer:
        def call_async(self, request):
            raise OSError('transport failed during dispatch')
    fixture = RosFixture.__new__(RosFixture)
    fixture._uncertain = False
    fixture.trace_dir = tmp_path
    fixture._request_count = 0
    fixture.Exchange = SimpleNamespace(Request=Request)
    fixture.peer = Peer()
    with pytest.raises(RuntimeError, match='UNKNOWN after possible dispatch'):
        fixture.handle(b'execute')
    with pytest.raises(RuntimeError, match='reinitialization required'):
        fixture.handle(b'hello')


def test_malformed_response_bytes_are_retained_before_decode(tmp_path):
    from tools.ros2_development_client import retain_response
    path = tmp_path / 'response.cbor'
    with pytest.raises(Exception):
        retain_response(SimpleNamespace(response=b'\xff'), path)
    assert path.read_bytes() == b'\xff'


def test_fixture_retains_malformed_response_and_latches_unknown(tmp_path):
    class Request:
        request = None
    class Future:
        def done(self):
            return True
        def result(self):
            return SimpleNamespace(response=b'\xff')
    class Peer:
        def call_async(self, request):
            return Future()
    fixture = RosFixture.__new__(RosFixture)
    fixture._uncertain = False
    fixture.trace_dir = tmp_path
    fixture._request_count = 0
    fixture.Exchange = SimpleNamespace(Request=Request)
    fixture.peer = Peer()
    fixture.client = object()
    fixture.rclpy = SimpleNamespace(spin_until_future_complete=lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError, match='UNKNOWN after possible dispatch'):
        fixture.handle(b'hello')
    assert (tmp_path / '000001.response.cbor').read_bytes() == b'\xff'
    with pytest.raises(RuntimeError, match='reinitialization required'):
        fixture.handle(b'hello')
