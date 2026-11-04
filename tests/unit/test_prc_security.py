"""Independent requirements for semantic authorization binding, without Isaac."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import struct

import pytest

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import encode, strict_decode
from tools.prc_security import security_config, security_config_digest
from tools.scene_evidence import scenario_operation_plan, segment_binding

ROOT = Path(__file__).resolve().parents[2]


def inputs():
    profile = json.loads((ROOT / 'scenes/manipulation/profile.json').read_bytes())
    policy = json.loads((ROOT / 'scenes/manipulation/evidence_policy.json').read_bytes())
    program = json.loads((ROOT / 'scenes/manipulation/trajectories.json').read_bytes())
    return profile, policy, program


def test_binary64_cbor_vector_and_complete_config_roundtrip():
    vector = {'schema_version': 2, 'physics_dt_seconds': struct.pack('>d', 1 / 120),
              'limits': [65536, 262144, 4096], 'enabled': True}
    raw = encode(vector)
    assert raw.hex() == ('a4666c696d697473831a000100001a0004000019100067656e61626c6564f5'
                         '6e736368656d615f76657273696f6e0272706879736963735f64745f7365636f6e6473483f81111111111111')
    assert sha256(raw).hexdigest() == '94de44406824df535a98506bf5c2214247b14491a8a6033f15bc26e64156ea2a'
    profile, policy, _ = inputs()
    config = security_config(profile, policy)
    assert strict_decode(encode(config), 65536) == config
    assert config['controller_configuration'] == L.configuration()
    assert config['scene_semantics']['physics']['gravity_m_s2'] == struct.pack('>d', profile['physics']['gravity_m_s2'])


def test_display_metadata_does_not_change_security_digest():
    profile, policy, _ = inputs()
    baseline = security_config_digest(profile, policy)
    profile['objects'][0]['color_rgb'] = [0.1, 0.2, 0.3]
    profile['candidate_policy']['semantics'] = 'Different explanatory text'
    profile['runtime']['container_image_digest'] = 'other release metadata'
    policy['notes'] = ['Different explanation']
    assert security_config_digest(profile, policy) == baseline


@pytest.mark.parametrize('group,field', [
    ('physics', 'gravity_m_s2'), ('physics', 'object_solver_position_iterations'),
    ('work_surface', 'top_z_m'), ('empty_grasp_setup', 'position_m'),
    ('candidate_policy', 'minimum_lift_m'), ('mapping', 'velocity_limits'),
])
def test_changed_scene_semantics_change_digest(group, field):
    profile, policy, _ = inputs()
    baseline = security_config_digest(profile, policy)
    value = profile[group][field]
    if type(value) is list:
        value[0] += 1
    else:
        profile[group][field] += 1
    assert security_config_digest(profile, policy) != baseline


def test_assessment_and_model_identity_fail_closed():
    profile, policy, _ = inputs()
    baseline = security_config_digest(profile, policy)
    changed = deepcopy(policy)
    changed['motion']['tracking_tolerance'][0] += 1
    assert security_config_digest(profile, changed) != baseline
    profile['model']['sha256'] = '0' * 64
    with pytest.raises(ValueError, match='Model manifest'):
        security_config(profile, policy)


@pytest.mark.parametrize('bad', [True, '0.1', float('nan'), float('inf')])
def test_numeric_fields_reject_wrong_types_and_nonfinite(bad):
    profile, policy, _ = inputs()
    profile['physics']['dt_seconds'] = bad
    with pytest.raises(ValueError):
        security_config(profile, policy)


def test_missing_or_unknown_selected_field_rejected():
    profile, policy, _ = inputs()
    del profile['physics']['gravity_m_s2']
    with pytest.raises(ValueError):
        security_config(profile, policy)
    profile, policy, _ = inputs()
    profile['physics']['new_unreviewed_physics_property'] = 1
    with pytest.raises(ValueError):
        security_config(profile, policy)


def test_v2_binding_uses_semantics_not_release_provenance():
    profile, policy, program = inputs()
    plan = scenario_operation_plan(program, 'normal')
    record = {'run_id': 'normal-0123456789abcdef0123456789abcdef', 'scenario': 'normal',
              'security_config_sha256': security_config_digest(profile, policy),
              'model_sha256': L.MODEL_MANIFEST_SHA256, 'operation_plan_sha256': sha256(encode(plan)).hexdigest(),
              'required_operations': plan, 'source_fingerprint': '1' * 64, 'runtime_metadata_sha256': '2' * 64}
    first = segment_binding(record, 0)
    assert set(first) == {'schema_version', 'run_id', 'scenario', 'security_config_sha256', 'model_sha256',
        'operation_plan_sha256', 'operation_count', 'operation_index', 'object_id', 'destination',
        'segment_index', 'segment_count', 'global_segment_index'}
    assert first['schema_version'] == 2
    record['source_fingerprint'] = '3' * 64
    record['runtime_metadata_sha256'] = '4' * 64
    assert segment_binding(record, 0) == first
    record['security_config_sha256'] = 'a' * 64
    assert segment_binding(record, 0) != first
    with pytest.raises(ValueError):
        segment_binding(record, True)
