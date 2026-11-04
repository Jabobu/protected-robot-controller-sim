"""Exercise simultaneous ROS service clients against one owner-thread adapter.

This is a transport-only diagnostic, not a robot, security or supervisor test.
Middleware may queue a request, so BUSY is not a universal arrival guarantee.
"""
from array import array
from concurrent.futures import Future
from threading import Barrier, Lock, Thread
import time

import rclpy
from rclpy.executors import MultiThreadedExecutor, SingleThreadedExecutor
from prc_interfaces.srv import Exchange
from protected_robot_controller.protocol import encode, strict_decode
from tools.ros2_endpoint import MainThreadExchange, make_service, SERVICE_NAME


class ObservedInterface:
    def __init__(self):
        self.lock = Lock()
        self.active = self.peak = self.calls = 0

    def handle(self, request):
        with self.lock:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.3)
        with self.lock:
            self.active -= 1
        return request


def main():
    rclpy.init(args=[])
    server = rclpy.create_node('prc_concurrency_probe_server')
    handler = ObservedInterface()
    exchange = MainThreadExchange(handler)
    service = make_service(server, exchange)
    executor = MultiThreadedExecutor(num_threads=2)
    executor.add_node(server)
    spin = Thread(target=executor.spin, daemon=True)
    spin.start()
    barrier = Barrier(3)
    results = [Future() for _ in range(3)]
    def client(index):
        node = rclpy.create_node(f'prc_concurrency_probe_client_{index}')
        local_executor = SingleThreadedExecutor()
        local_executor.add_node(node)
        try:
            peer = node.create_client(Exchange, SERVICE_NAME)
            if not peer.wait_for_service(timeout_sec=15):
                raise RuntimeError('service unavailable')
            request = Exchange.Request()
            request.request = array('B', encode({'version': 1, 'type': 'HELLO', 'probe': index}))
            barrier.wait(timeout=15)
            future = peer.call_async(request)
            local_executor.spin_until_future_complete(future, timeout_sec=20)
            if not future.done():
                raise RuntimeError('response timeout')
            results[index].set_result(strict_decode(bytes(future.result().response), 1024))
        except BaseException as error:
            results[index].set_exception(error)
        finally:
            local_executor.shutdown()
            node.destroy_node()
    workers = [Thread(target=client, args=(i,), daemon=True) for i in range(3)]
    try:
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 30
        while not all(result.done() for result in results):
            if time.monotonic() >= deadline:
                raise TimeoutError('probe did not finish')
            exchange.pump_once(timeout=0.05)
        values = [result.result() for result in results]
        busy = sum(value == {'version': 1, 'type': 'REJECTED', 'reason': 'BUSY'} for value in values)
        normal = [value for value in values if value.get('type') == 'HELLO']
        if handler.peak != 1 or not busy or len(normal) + busy != 3:
            raise AssertionError(f'Unexpected serialization result: {values!r}, peak={handler.peak}')
        print(f'ROS_BURST_OK clients=3 busy={busy} handled={handler.calls} peak={handler.peak}')
    finally:
        executor.shutdown(timeout_sec=5)
        spin.join(timeout=5)
        server.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
