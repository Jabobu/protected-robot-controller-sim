"""ROS service adapter for the existing controller byte interface.

Construct a single instance in trusted setup, spin ROS in background threads,
then call pump_once from the thread owning the simulator. Never retry a request.
"""
from array import array
from concurrent.futures import Future
from queue import Queue, Empty
from threading import Lock

from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode

SERVICE_NAME = "/prc/controller/exchange"
BUSY = encode({"version": 1, "type": "REJECTED", "reason": "BUSY"})
UNAVAILABLE = encode({"version": 1, "type": "UNAVAILABLE", "reason": "EVIDENCE_UNAVAILABLE"})


class MainThreadExchange:
    """One admitted request across all clients; execution remains on owner thread."""

    def __init__(self, interface):
        self._interface = interface
        self._gate = Lock()
        self._queue = Queue(maxsize=1)
        self._failed = False

    def submit(self, data):
        if len(data) > MAX_REQUEST_BYTES:
            return encode({"version": 1, "type": "REJECTED", "reason": "SIZE"})
        if not self._gate.acquire(blocking=False):
            return BUSY
        try:
            if self._failed:
                return UNAVAILABLE
            result = Future()
            self._queue.put((bytes(data), result))
            return result.result()
        finally:
            self._gate.release()

    def pump_once(self, timeout=0.1):
        try:
            request, result = self._queue.get(timeout=timeout)
        except Empty:
            return False
        try:
            response = self._interface.handle(request)
            if type(response) is not bytes or len(response) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Invalid internal response")
        except BaseException as error:
            self._failed = True
            result.set_exception(error)
            raise
        else:
            result.set_result(response)
        return True


def make_service(node, exchange):
    from rclpy.callback_groups import ReentrantCallbackGroup
    from rclpy.qos import qos_profile_services_default
    from prc_interfaces.srv import Exchange

    def callback(request, response):
        # Length is checked before conversion to an independently owned bytes object.
        response.response = array('B', exchange.submit(request.request))
        return response

    return node.create_service(Exchange, SERVICE_NAME, callback,
                               qos_profile=qos_profile_services_default,
                               callback_group=ReentrantCallbackGroup())
