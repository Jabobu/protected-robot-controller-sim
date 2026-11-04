"""Trusted, persistent Isaac PRC ROS service; all keys and faults are local setup."""
import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback
from threading import Thread
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from tools.scene_fixture import ManipulationScene, read_configuration, execution_guard, write_json
from tools.run_scene_examples import ExampleBackend, observe_hold
from protected_robot_controller.controller import Controller
from protected_robot_controller.interface import ControllerInterface
from protected_robot_controller.protocol import public_bytes
from tools.ros2_endpoint import MainThreadExchange, make_service


class RecordingInterface:
    """Trusted local observation only; responses and captured bytes stay unchanged."""
    def __init__(self, interface, controller, observed, output, scenario, acquisition):
        self.interface, self.controller, self.observed, self.output = interface, controller, observed, output
        self.scenario, self.acquisition = scenario, acquisition
        self.count = 0
        self.hold_observed = False

    def handle(self, request):
        self.count += 1
        directory = self.output / f'request-{self.count:06d}'
        directory.mkdir()
        (directory / 'request.cbor').write_bytes(request)
        j, o, w = len(self.observed.joints), len(self.observed.objects), len(self.observed.target_writes)
        response = self.interface.handle(request)
        (directory / 'response.cbor').write_bytes(response)
        if self.scenario == 'incomplete' and self.controller.state == 'ABORTED' and not self.hold_observed:
            # Restore only the independent getter after the original signed response
            # is retained. This window is unsigned and never changes that report.
            self.acquisition.__exit__(None, None, None)
            self.hold_observed = True
            hold_path = directory / 'post-stop-hold.json'
            hold = observe_hold(self.observed.backend, self.observed, self.observed.scene,
                                self.controller, hold_path)
            write_json(hold_path, hold)
        write_json(directory / 'joints.json', self.observed.joints[j:])
        write_json(directory / 'objects.json', self.observed.objects[o:])
        write_json(directory / 'target_writes.json', self.observed.target_writes[w:])
        write_json(directory / 'state.json', {'controller_state': self.controller.state,
                   'physics_steps': self.observed.backend._steps,
                   'drive_writes': self.observed.drive_writes,
                   'request_sha256': sha256(request).hexdigest(),
                   'response_sha256': sha256(response).hexdigest()})
        return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-public-der', required=True)
    parser.add_argument('--evidence-private-pem', required=True)
    parser.add_argument('--output', required=True, help='New local evidence directory')
    parser.add_argument('--scenario', choices=('normal', 'missed_grasp', 'obstructed', 'incomplete'), default='normal')
    args = parser.parse_args()
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    with open(args.authority_public_der, 'rb') as stream:
        authority = load_der_public_key(stream.read())
    with open(args.evidence_private_pem, 'rb') as stream:
        evidence = load_pem_private_key(stream.read(), password=None)
    argv, sys.argv = sys.argv, [sys.argv[0]]
    from isaacsim import SimulationApp
    app = SimulationApp({'headless': True, 'fast_shutdown': True, 'multi_gpu': False,
                         'disable_viewport_updates': True, 'enable_crashreporter': False})
    sys.argv = argv
    backend = node = executor = thread = None
    code = 1
    try:
        from isaacsim.core.version import get_version
        from tools.runtime_provenance import current_runtime
        runtime_identity = current_runtime()
        isaac_version = list(get_version())
        if (not isaac_version or isaac_version[0].split("-")[0].split("+")[0] != "6.0.0"
                or sys.version_info[:2] != (3, 12)):
            raise RuntimeError(f"Isaac Sim 6.0.0 with Python 3.12 required; observed {isaac_version}, {sys.version}")
        from protected_robot_controller.simulation._backend import _IsaacRobotBackend
        from tools.scene_faults import constrain_arm_joint, NativeAcquisitionInterruption
        import rclpy
        from rclpy.executors import MultiThreadedExecutor
        rmw = rclpy.get_rmw_implementation_identifier()
        if (os.environ.get('ROS_DISTRO') != 'jazzy' or rmw != 'rmw_fastrtps_cpp'
            or os.environ.get('FASTDDS_BUILTIN_TRANSPORTS') != 'UDPv4'):
            raise RuntimeError('ROS 2 Jazzy, rmw_fastrtps_cpp and UDPv4 are required')
        profile, _ = read_configuration()
        scene = ManipulationScene(profile, camera=False, empty_grasp=args.scenario == 'missed_grasp')
        backend = _IsaacRobotBackend(setup_scene=scene.build)
        fault = {'scenario': args.scenario}
        if args.scenario == 'obstructed':
            fault['constraint'] = constrain_arm_joint(backend)
        with ExitStack() as stack:
            acquisition = None
            if args.scenario == 'incomplete':
                acquisition = NativeAcquisitionInterruption(backend)
                stack.enter_context(acquisition)
            observed = ExampleBackend(backend, scene, acquisition)
            original_write = backend._write_targets
            def write_targets(target):
                original_write(target)
                observed.target_writes.append({'physics_step': int(backend._world.current_time_step_index),
                                               'targets': list(target)})
            stack.enter_context(execution_guard(backend, scene))
            stack.enter_context(patch.object(backend, '_write_targets', write_targets))
            controller = Controller(authority, evidence, observed)
            interface = RecordingInterface(ControllerInterface(controller), controller, observed, output, args.scenario, acquisition)
            exchange = MainThreadExchange(interface)
            rclpy.init(args=[])
            node = rclpy.create_node('prc_controller')
            service = make_service(node, exchange)
            executor = MultiThreadedExecutor(num_threads=2)
            executor.add_node(node)
            thread = Thread(target=executor.spin, daemon=True)
            thread.start()
            write_json(output / 'setup.json', {'fault': fault, 'profile': profile,
                'authority_public_der_sha256': sha256(public_bytes(authority)).hexdigest(),
                'evidence_public_der_sha256': sha256(public_bytes(evidence.public_key())).hexdigest(),
                'ros_distro': os.environ.get('ROS_DISTRO'), 'rmw_implementation': rmw,
                'isaac_version': isaac_version, 'python_version': sys.version,
                'runtime_identity': runtime_identity,
                'fastdds_builtin_transports': os.environ.get('FASTDDS_BUILTIN_TRANSPORTS'),
                'ros_domain_id': os.environ.get('ROS_DOMAIN_ID', '0')})
            print('PRC_ROS_READY /prc/controller/exchange', flush=True)
            while rclpy.ok():
                exchange.pump_once()
            code = 0
    except KeyboardInterrupt:
        code = 0
    except BaseException:
        traceback.print_exc()
    finally:
        if executor is not None:
            executor.shutdown(timeout_sec=5)
        if thread is not None:
            thread.join(timeout=5)
        if node is not None:
            node.destroy_node()
        if 'rclpy' in locals() and rclpy.ok():
            rclpy.shutdown()
        if backend is not None:
            backend.close()
        app.close(wait_for_replicator=False, skip_cleanup=False, exit_code=code)


if __name__ == '__main__':
    main()
