"""Synthetic v2 policy vectors. These are not execution or physics evidence."""
from copy import deepcopy
from hashlib import sha256
import json
import subprocess
import sys
from pathlib import Path

import pytest

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import PROFILE, encode, key_id, cose_private
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message
from tools.controller_fixture import _CONTEXT_FIELDS, command_for, development_keys, sign_command
from tools.prc_security import security_config_digest
from tools.scene_check import SceneChecker, expected_segment, load_policy
from tools.scene_evidence import scenario_operation_plan, segment_binding
from tools.scene_fixture import expand_operation
from tools.scene_objects import assess_objects

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def reference():
    profile = json.loads((ROOT / 'scenes/manipulation/profile.json').read_bytes())
    policy = load_policy()
    program = json.loads((ROOT / 'scenes/manipulation/trajectories.json').read_bytes())
    authority, evidence_key = development_keys()
    plan = scenario_operation_plan(program, 'normal')
    record = {'run_id': 'normal-' + '01' * 16, 'scenario': 'normal',
        'security_config_sha256': security_config_digest(profile, policy),
        'model_sha256': L.MODEL_MANIFEST_SHA256, 'operation_plan_sha256': sha256(encode(plan)).hexdigest(),
        'required_operations': plan}
    return profile, policy, program, authority, evidence_key, record


def vector(ref, index=0):
    _, _, program, authority, evidence_key, record = ref
    hello = {'version': 1, 'type': 'HELLO', 'profile': PROFILE, 'robot_id': L.ROBOT_ID,
        'controller_id': L.CONTROLLER_ID, 'config_digest': L.CONFIG_DIGEST, 'boot_id': b'b' * 32,
        'challenge': bytes([index + 1]) * 32, 'sequence_floor': index, 'expires_ns': 10**12,
        'evidence_key_id': key_id(evidence_key.public_key())}
    binding = segment_binding(record, index)
    trajectory, _ = expand_operation(program, program['operations'][index])
    initial = program['initial_target'] + [program['initial_target'][-1]]
    command = command_for(hello, initial, trajectory, hold_steps=program['hold_steps'])
    command['initial_tolerance'] = program['initial_tolerance']
    command['authorization_context_digest'] = sha256(encode(binding)).digest()
    wire = sign_command(command, authority)
    positions = [initial] + [row + [row[-1]] for row in trajectory] + [trajectory[-1] + [trajectory[-1][-1]]] * program['hold_steps']
    offset = index * (len(positions) - 1)
    rows = [[i, i + offset, i + offset, round((i + offset) * 1_000_000_000 / 120), i * 1000, list(q), [True] * 8]
            for i, q in enumerate(positions)]
    report = {key: deepcopy(command[key]) for key in _CONTEXT_FIELDS}
    report.update(version=1, type='EVIDENCE', evidence_key_id=key_id(evidence_key.public_key()),
        command_digest=sha256(wire).digest(), samples=rows, sample_count=len(rows),
        expected_sample_count=len(rows), terminal_state='COMPLETE', partial=False, reason='NONE')
    expectation = expected_segment(program, index, binding, hello, segment_index=index)
    return command, wire, report, expectation


def sign_report(report, key):
    return Sign1Message(phdr={Algorithm: Es256, KID: key_id(key.public_key())},
                        uhdr={}, payload=encode(report), key=cose_private(key)).encode(tag=True)


def checker(ref):
    return SceneChecker(ref[3].public_key(), ref[4].public_key(), ref[1])


def assess(ref, wire, report, expected):
    return checker(ref).assess_segment(wire, sign_report(report, ref[4]), expected)


def test_v2_reference_and_signed_bytes_roundtrip(reference):
    command, wire, report, expected = vector(reference)
    result = assess(reference, wire, report, expected)
    assert result['evidence_validation'] == 'VALID' and result['motion_verdict'] == 'CONFORMANT'
    assert result['coverage']['captured_samples'] == 2365
    assert all(row[4] == row[5] == 0 for row in command['trajectory'])
    assert command['trajectory'][-1] == reference[2]['initial_target']


def test_changed_signature_key_and_binding_rejected(reference):
    _, wire, report, expected = vector(reference)
    signed = sign_report(report, reference[4])
    for bad_command, bad_report in ((wire[:-1] + bytes([wire[-1] ^ 1]), signed),
                                    (wire, signed[:-1] + bytes([signed[-1] ^ 1]))):
        assert checker(reference).assess_segment(bad_command, bad_report, expected)['evidence_validation'] == 'REJECTED_EVIDENCE'
    wrong = deepcopy(expected)
    wrong['command_fields']['authorization_context_digest'] = b'\0' * 32
    assert checker(reference).assess_segment(wire, signed, wrong)['evidence_validation'] == 'REJECTED_EVIDENCE'
    other = development_keys()[1]
    assert SceneChecker(reference[3].public_key(), other.public_key(), reference[1]).assess_segment(
        wire, signed, expected)['evidence_validation'] == 'REJECTED_EVIDENCE'


def test_missing_coverage_reordered_duplicate_and_partial(reference):
    _, wire, report, expected = vector(reference)
    instance = checker(reference)
    assert instance.assess_segment(wire, None, expected)['motion_verdict'] == 'UNKNOWN'
    partial = deepcopy(report)
    partial['samples'][100][5][4] += 100000
    partial['samples'] = partial['samples'][:150]
    partial.update(sample_count=150, terminal_state='ABORTED', partial=True, reason='SENSOR')
    result = assess(reference, wire, partial, expected)
    assert result['motion_verdict'] == 'UNKNOWN' and result['captured_tracking_deviation']
    segment = {'segment_index': 0, 'command': wire, 'report': sign_report(report, reference[4])}
    assert checker(reference).assess_operation([], [expected])['motion_verdict'] == 'UNKNOWN'
    assert checker(reference).assess_operation([segment, segment], [expected])['evidence_validation'] == 'REJECTED_EVIDENCE'
    _, wire2, report2, expected2 = vector(reference, 1)
    second = {'segment_index': 1, 'command': wire2, 'report': sign_report(report2, reference[4])}
    assert checker(reference).assess_operation([segment, second], [expected, expected2])['motion_verdict'] == 'CONFORMANT'
    assert checker(reference).assess_operation([segment], [expected, expected2])['motion_verdict'] == 'UNKNOWN'
    assert checker(reference).assess_operation([second, segment], [expected, expected2])['evidence_validation'] == 'REJECTED_EVIDENCE'
    altered = dict(second, report=second['report'][:-1] + bytes([second['report'][-1] ^ 1]))
    assert checker(reference).assess_operation([segment, altered], [expected, expected2])['evidence_validation'] == 'REJECTED_EVIDENCE'


def test_complete_capture_can_be_deviated(reference):
    _, wire, report, expected = vector(reference)
    report['samples'][1100][5][4] += 2 * reference[1]['motion']['tracking_tolerance'][4]
    result = assess(reference, wire, report, expected)
    assert result['evidence_validation'] == 'VALID' and result['motion_verdict'] == 'DEVIATED'


@pytest.mark.parametrize('fault', ['counter', 'physics_step', 'simulation_time', 'acquisition_time', 'channel', 'validity', 'count', 'hold'])
def test_complete_capture_requires_every_valid_timed_sample(reference, fault):
    _, wire, report, expected = vector(reference)
    row = report['samples'][1200]
    if fault == 'counter': row[1] += 2
    elif fault == 'physics_step': row[2] += 2
    elif fault == 'simulation_time': row[3] += 100
    elif fault == 'acquisition_time': row[4] = L.MAX_RUN_NS + 1
    elif fault == 'channel': row[5].pop()
    elif fault == 'validity': row[6][7] = False
    elif fault == 'count': report['expected_sample_count'] -= 1
    else:
        report['samples'].pop(); report['sample_count'] -= 1
    result = assess(reference, wire, report, expected)
    assert result['evidence_validation'] == 'VALID' and result['motion_verdict'] == 'UNKNOWN'


def object_rows(profile):
    pos = [*profile['regions']['A']['center_xy_m'],
           profile['work_surface']['top_z_m'] + profile['objects'][0]['dimensions_m'][2] / 2]
    state = {'position': pos, 'orientation_wxyz': [1, 0, 0, 0], 'linear_velocity': [0, 0, 0],
             'angular_velocity': [0, 0, 0], 'finger_forces_n': [[0, 0, 0], [0, 0, 0]]}
    return [{'physics_step': i, 'simulation_time_ns': round(i * 1_000_000_000 / 120),
             'objects': {'R1': deepcopy(state)}} for i in range(121)]


@pytest.mark.parametrize('fault,verdict', [('none', 'DELIVERED'), ('contact', 'NOT_DELIVERED'),
    ('speed', 'NOT_DELIVERED'), ('corner', 'NOT_DELIVERED'), ('height', 'NOT_DELIVERED'),
    ('gap', 'UNKNOWN'), ('invalid', 'UNKNOWN'), ('missing-end', 'UNKNOWN')])
def test_unsigned_object_predicate_and_coverage(reference, fault, verdict):
    profile, policy, *_ = reference
    rows = object_rows(profile)
    end_step, end_time = rows[-1]['physics_step'], rows[-1]['simulation_time_ns']
    state = rows[60]['objects']['R1']
    if fault == 'contact': state['finger_forces_n'][1] = [0.02, 0, 0]
    elif fault == 'speed': state['linear_velocity'] = [0.021, 0, 0]
    elif fault == 'corner': state['position'][0] += 0.04
    elif fault == 'height': state['position'][2] += 0.01
    elif fault == 'gap': rows[60]['physics_step'] += 1
    elif fault == 'invalid': state['orientation_wxyz'] = [0, 0, 0, 0]
    elif fault == 'missing-end': rows.pop()
    result = assess_objects(rows, 'R1', 'A', profile, policy, end_step=end_step, end_time_ns=end_time)
    assert result['object_verdict'] == verdict and result['sensor_authenticated'] is False


def test_verifier_imports_without_simulator():
    code = """import importlib.abc, sys
class NoSimulator(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('isaacsim', 'omni', 'pxr', 'carb') or fullname.startswith('protected_robot_controller.simulation'):
            raise RuntimeError('Simulator import forbidden: ' + fullname)
sys.meta_path.insert(0, NoSimulator())
from tools.scene_check import SceneChecker
assert not any(n.split('.')[0] in ('isaacsim', 'omni', 'pxr', 'carb') for n in sys.modules)
"""
    subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT, check=True, timeout=30)


def test_malformed_signed_command_rejects_cleanly(reference):
    _, _, report, expected = vector(reference)
    malformed = sign_command([1, 2], reference[3])
    result = checker(reference).assess_segment(malformed, sign_report(report, reference[4]), expected)
    assert result['evidence_validation'] == 'REJECTED_EVIDENCE' and result['motion_verdict'] is None


def test_signed_v2_and_v3_context_relabel_rejected(reference):
    """A new metadata hash and schema cannot be substituted for signed bytes."""
    ref = list(reference)
    legacy_record = deepcopy(ref[-1])
    _, legacy_wire, legacy_report, legacy_expected = vector(ref)
    assert assess(ref, legacy_wire, legacy_report, legacy_expected)['evidence_validation'] == 'VALID'
    ref[-1] = deepcopy(legacy_record)
    ref[-1].update(runtime_identity={'kind': 'native'}, runtime_metadata_sha256='a' * 64)
    _, v3_wire, v3_report, v3_expected = vector(ref)
    assert assess(ref, v3_wire, v3_report, v3_expected)['evidence_validation'] == 'VALID'
    assert assess(ref, legacy_wire, legacy_report, v3_expected)['evidence_validation'] == 'REJECTED_EVIDENCE'
    assert assess(ref, v3_wire, v3_report, legacy_expected)['evidence_validation'] == 'REJECTED_EVIDENCE'
    ref[-1]['runtime_metadata_sha256'] = 'b' * 64
    binding = segment_binding(ref[-1], 0)
    relabeled = expected_segment(ref[2], 0, binding, v3_expected['hello'])
    assert assess(ref, v3_wire, v3_report, relabeled)['evidence_validation'] == 'REJECTED_EVIDENCE'
