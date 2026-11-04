"""Independent development-only ROS client for the persistent scene server.

Private development keys are local lab fixtures, never TA keys or acceptance.
No automatic retry or recovery after an uncertain result is provided.
"""
import argparse
from array import array
from hashlib import sha256
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key
from protected_robot_controller import limits as L
from protected_robot_controller.interface import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import PROFILE, encode, key_id, strict_decode
from tools.controller_fixture import command_for, sign_command
from tools.scene_fixture import expand_operation, read_configuration
from tools.scene_check import SceneChecker, expected_segment, load_policy
from tools.scene_evidence import scenario_operation_plan, segment_binding
from tools.prc_security import security_config_digest
from tools.ros2_endpoint import SERVICE_NAME


def retain_response(response, path):
    """Retain received raw bytes before interpreting an unauthenticated response."""
    if response is None or len(response.response) > MAX_RESPONSE_BYTES:
        raise RuntimeError('invalid response size')
    raw = bytes(response.response)
    Path(path).write_bytes(raw)
    decoded = strict_decode(raw, MAX_RESPONSE_BYTES)
    if not isinstance(decoded, dict):
        raise ValueError('invalid response map')
    return raw, decoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-private-pem', required=True)
    parser.add_argument('--evidence-public-der', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--scenario', choices=('normal', 'missed_grasp', 'obstructed', 'incomplete'), default='normal')
    args = parser.parse_args()
    output = Path(args.output).absolute()
    output.mkdir(parents=True, exist_ok=False)
    with open(args.authority_private_pem, 'rb') as stream:
        authority = load_pem_private_key(stream.read(), password=None)
    with open(args.evidence_public_der, 'rb') as stream:
        evidence_key = load_der_public_key(stream.read())
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("ROS client requires Python 3.12")
    import rclpy
    from prc_interfaces.srv import Exchange
    rmw = rclpy.get_rmw_implementation_identifier()
    if (os.environ.get('ROS_DISTRO') != 'jazzy' or rmw != 'rmw_fastrtps_cpp'
            or os.environ.get('FASTDDS_BUILTIN_TRANSPORTS') != 'UDPv4'):
        raise RuntimeError('ROS 2 Jazzy, rmw_fastrtps_cpp and UDPv4 are required')
    rclpy.init(args=[])
    node = rclpy.create_node('prc_development_client')
    client = node.create_client(Exchange, SERVICE_NAME)
    try:
        if not client.wait_for_service(timeout_sec=15):
            raise RuntimeError('Service unavailable before dispatch')
        def call(data, response_path):
            if len(data) > MAX_REQUEST_BYTES:
                raise ValueError('Local request size exceeds limit before dispatch')
            request = Exchange.Request()
            request.request = array('B', data)
            try:
                result = client.call_async(request)
                rclpy.spin_until_future_complete(node, result, timeout_sec=180)
                if not result.done() or result.result() is None:
                    raise TimeoutError('No response')
                raw, response = retain_response(result.result(), response_path)
            except BaseException as error:
                raise RuntimeError('UNKNOWN after possible dispatch; stop and reinitialize in lab') from error
            if response.get('type') == 'UNAVAILABLE':
                raise RuntimeError('UNKNOWN: evidence unavailable; stop and reinitialize in lab')
            return raw, response
        profile, program = read_configuration()
        policy = load_policy()
        checker = SceneChecker(authority.public_key(), evidence_key, policy)
        run_id = args.scenario + '-' + uuid4().hex
        plan = scenario_operation_plan(program, args.scenario)
        binding_record = {'run_id': run_id, 'scenario': args.scenario,
            'security_config_sha256': security_config_digest(profile, policy),
            'model_sha256': profile['model']['sha256'],
            'operation_plan_sha256': sha256(encode(plan)).hexdigest(), 'required_operations': plan}
        results = []
        for index, operation in enumerate(program['operations'][:2 if args.scenario == 'normal' else 1]):
            name = f'{index + 1:02d}'
            hello_request = encode({'version': 1, 'type': 'HELLO'})
            (output / (name + '.hello.request.cbor')).write_bytes(hello_request)
            hello_raw, hello = call(hello_request, output / (name + '.hello.cbor'))
            expected_identity = {'type': 'HELLO', 'version': 1, 'profile': PROFILE, 'robot_id': L.ROBOT_ID,
                                 'controller_id': L.CONTROLLER_ID, 'config_digest': L.CONFIG_DIGEST,
                                 'evidence_key_id': key_id(evidence_key)}
            if any(hello.get(k) != v for k, v in expected_identity.items()):
                raise RuntimeError('Untrusted HELLO identity/configuration')
            trajectory, _ = expand_operation(program, operation)
            command = command_for(hello, program['initial_target'] + [program['initial_target'][-1]], trajectory,
                                  hold_steps=program['hold_steps'])
            command['initial_tolerance'] = program['initial_tolerance']
            binding = segment_binding(binding_record, index)
            command['authorization_context_digest'] = sha256(encode(binding)).digest()
            wire = sign_command(command, authority)
            request = encode({'version': 1, 'type': 'EXECUTE', 'command': wire})
            (output / (name + '.command.cbor')).write_bytes(wire)
            (output / (name + '.request.cbor')).write_bytes(request)
            raw, response = call(request, output / (name + '.response.cbor'))
            if response.get('type') != 'EVIDENCE':
                raise RuntimeError(f'No evidence; unsigned response is diagnostic: {response}')
            report = response['evidence']
            (output / (name + '.report.cbor')).write_bytes(report)
            result = checker.assess_segment(wire, report, expected_segment(program, index, binding, hello))
            results.append({'operation': index, 'binding': binding, 'assessment': result,
                            'command_bytes': len(wire), 'report_bytes': len(report),
                            'command_sha256': sha256(wire).hexdigest(), 'report_sha256': sha256(report).hexdigest()})
            (output / (name + '.assessment.json')).write_text(json.dumps(results[-1], indent=2))
            if result['evidence_validation'] != 'VALID' or (args.scenario == 'normal' and result['motion_verdict'] != 'CONFORMANT'):
                raise RuntimeError('Unexpected evidence or motion assessment; stop')
        (output / 'summary.json').write_text(json.dumps({'run_id': run_id, 'ros_distro': os.environ.get('ROS_DISTRO'),
            'rmw_implementation': rmw, 'fastdds_builtin_transports': os.environ.get('FASTDDS_BUILTIN_TRANSPORTS'),
                'ros_domain_id': os.environ.get('ROS_DOMAIN_ID', '0'), 'results': results}, indent=2))
        print(json.dumps(results, indent=2))
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
