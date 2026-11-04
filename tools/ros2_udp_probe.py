import sys, time
from array import array
from threading import Thread
import rclpy
from rclpy.executors import MultiThreadedExecutor
from prc_interfaces.srv import Exchange

rclpy.init(args=[])
node=rclpy.create_node('prc_udp_' + sys.argv[1])
if sys.argv[1]=='server':
    def answer(request, response):
        assert bytes(request.request) == b'x' * 55141
        response.response = array('B', b'y' * 152742)
        print('SERVER_HANDLED', flush=True)
        return response
    service=node.create_service(Exchange, '/prc/udp_transport_probe', answer)
    print('SERVER_READY', flush=True)
    rclpy.spin(node)
else:
    client=node.create_client(Exchange, '/prc/udp_transport_probe')
    assert client.wait_for_service(timeout_sec=15)
    request=Exchange.Request()
    request.request=array('B', b'x' * 55141)
    future=client.call_async(request)
    rclpy.spin_until_future_complete(node, future, timeout_sec=20)
    assert future.done() and bytes(future.result().response)==b'y'*152742
    print('CROSS_CONTAINER_UDP_OK 55141 152742', flush=True)
node.destroy_node()
rclpy.shutdown()
