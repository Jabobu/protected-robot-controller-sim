"""Development-only ROS loopback client and owner-thread service harness."""
from array import array
from concurrent.futures import Future
from threading import Thread

from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from tools.ros2_endpoint import MainThreadExchange, make_service, SERVICE_NAME


class RosFixture:
    def __init__(self, interface, trace_dir):
        import rclpy
        from rclpy.executors import MultiThreadedExecutor
        from prc_interfaces.srv import Exchange
        import os
        import sys
        if sys.version_info[:2] != (3, 12):
            raise RuntimeError("ROS fixture requires Python 3.12")
        self.rclpy, self.Exchange = rclpy, Exchange
        self.runtime = {'ros_distro': os.environ.get('ROS_DISTRO'),
                        'rmw_implementation': rclpy.get_rmw_implementation_identifier(),
                        'ros_domain_id': os.environ.get('ROS_DOMAIN_ID', '0'),
                        'fastdds_builtin_transports': os.environ.get('FASTDDS_BUILTIN_TRANSPORTS')}
        if (self.runtime['ros_distro'] != 'jazzy' or self.runtime['rmw_implementation'] != 'rmw_fastrtps_cpp'
                or self.runtime['fastdds_builtin_transports'] != 'UDPv4'):
            raise RuntimeError('ROS 2 Jazzy, rmw_fastrtps_cpp and UDPv4 are required')
        self._uncertain = False
        from pathlib import Path
        self.trace_dir = Path(trace_dir)
        self.trace_dir.mkdir(parents=True, exist_ok=False)
        self._request_count = 0
        rclpy.init(args=[])
        self.server = rclpy.create_node('prc_fixture_server')
        self.client = rclpy.create_node('prc_fixture_client')
        self.exchange = MainThreadExchange(interface)
        self.service = make_service(self.server, self.exchange)
        self.executor = MultiThreadedExecutor(num_threads=2)
        self.executor.add_node(self.server)
        self.thread = Thread(target=self.executor.spin, daemon=True)
        self.thread.start()
        self.peer = self.client.create_client(Exchange, SERVICE_NAME)
        if not self.peer.wait_for_service(timeout_sec=15):
            raise RuntimeError('ROS service unavailable before dispatch')

    def handle(self, data):
        if self._uncertain:
            raise RuntimeError('UNKNOWN is latched; trusted reinitialization required')
        if type(data) is not bytes or len(data) > MAX_REQUEST_BYTES:
            raise ValueError('Unsupported request size before dispatch')
        self._request_count += 1
        prefix = f'{self._request_count:06d}'
        (self.trace_dir / (prefix + '.request.cbor')).write_bytes(data)
        request = self.Exchange.Request()
        request.request = array('B', data)
        try:
            future = self.peer.call_async(request)
            self.rclpy.spin_until_future_complete(self.client, future, timeout_sec=180)
            if not future.done():
                raise TimeoutError('response timeout')
            response = future.result()
            if response is None or len(response.response) > MAX_RESPONSE_BYTES:
                raise RuntimeError('invalid response')
            raw = bytes(response.response)
            (self.trace_dir / (prefix + '.response.cbor')).write_bytes(raw)
            from protected_robot_controller.protocol import strict_decode
            decoded = strict_decode(raw, MAX_RESPONSE_BYTES)
            if not isinstance(decoded, dict) or decoded.get('type') not in ('HELLO', 'EVIDENCE', 'REJECTED', 'UNAVAILABLE'):
                raise RuntimeError('malformed response')
            if decoded['type'] == 'UNAVAILABLE':
                self._uncertain = True
            return raw
        except BaseException as exc:
            self._uncertain = True
            raise RuntimeError('UNKNOWN after possible dispatch; trusted reinitialization required') from exc

    def on_owner_thread(self, fn):
        result = Future()
        def invoke():
            try:
                result.set_result(fn())
            except BaseException as exc:
                result.set_exception(exc)
        worker = Thread(target=invoke, daemon=True)
        worker.start()
        while not result.done():
            self.exchange.pump_once(timeout=0.05)
        worker.join()
        return result.result()

    def close(self):
        self.executor.shutdown(timeout_sec=5)
        self.thread.join(timeout=5)
        self.client.destroy_node()
        self.server.destroy_node()
        self.rclpy.shutdown()


def invalid_command_probe(transport, store, observed, authority, program):
    """Send an altered signed command; retain bytes and real write observations."""
    import json
    from tools.controller_fixture import command_for, sign_command
    from protected_robot_controller.protocol import encode, strict_decode
    hello = transport.handle(encode({'version': 1, 'type': 'HELLO'}))
    ready = strict_decode(hello, MAX_RESPONSE_BYTES)
    command = command_for(ready, program['initial_target'] + [program['initial_target'][-1]],
                          [program['initial_target']])
    wire = sign_command(command, authority)
    wire = wire[:-1] + bytes([wire[-1] ^ 1])
    request = encode({'version': 1, 'type': 'EXECUTE', 'command': wire})
    before = {'drives': observed.drive_writes, 'writes': len(observed.target_writes),
              'steps': observed.backend._steps, 'samples': len(observed.joints)}
    response = transport.handle(request)
    after = {'drives': observed.drive_writes, 'writes': len(observed.target_writes),
             'steps': observed.backend._steps, 'samples': len(observed.joints)}
    for name, value in (('hello', hello), ('command', wire), ('request', request), ('response', response)):
        (store.directory / ('ros2-invalid-' + name + '.cbor')).write_bytes(value)
    decoded = strict_decode(response, MAX_RESPONSE_BYTES)
    result = {'before': before, 'after': after, 'response': decoded}
    (store.directory / 'ros2-invalid.json').write_text(json.dumps(result, indent=2))
    store.record['ros2_invalid_probe'] = result
    if before != after or decoded != {'version': 1, 'type': 'REJECTED', 'reason': 'SIGNATURE'}:
        raise RuntimeError('Altered command rejection or no-write invariant failed')
