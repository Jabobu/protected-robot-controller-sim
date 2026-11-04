"""Canonical semantic authorization configuration, independent of release provenance.

The identifiers select a reviewed contract; they do not attest running code.
Decimal JSON numbers are encoded as binary64 byte strings because protocol CBOR
intentionally forbids floats. Raw model manifest identity remains unchanged.
"""
from hashlib import sha256
import math
import struct

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import MAX_COMMAND_BYTES, MAX_EVIDENCE_BYTES, MAX_ROWS, encode

ENFORCEMENT_ID = 'PRC-B601-ENFORCEMENT-2'
ASSESSMENT_ID = 'PRC-B601-ASSESSMENT-2'


def _map(value, required, *, allowed_extra=()):
    if type(value) is not dict or not set(required) <= set(value) or set(value) - set(required) - set(allowed_extra):
        raise ValueError('Unexpected semantic map fields')
    return {name: fn(value[name]) for name, fn in required.items()}


def _text(value):
    if type(value) is not str or not value:
        raise ValueError('Expected nonempty text')
    return value


def _bool(value):
    if type(value) is not bool:
        raise ValueError('Expected boolean')
    return value


def _integer(value):
    if type(value) is not int:
        raise ValueError('Expected integer')
    return value


def _number(value):
    if type(value) is int:
        return value
    if type(value) is not float or not math.isfinite(value):
        raise ValueError('Expected finite JSON number')
    raw = struct.pack('>d', value)
    if struct.unpack('>d', raw)[0] != value:
        raise ValueError('Number is not binary64 round-trippable')
    return raw


def _array(value, item, length=None):
    if type(value) is not list or (length is not None and len(value) != length) or not value:
        raise ValueError('Unexpected semantic array')
    return [item(v) for v in value]


def _num_array(value, length=None):
    return _array(value, _number, length)


def _strings(value, length=None):
    return _array(value, _text, length)


def _geometry(value):
    return _map(value, {'center_xy_m': lambda v: _num_array(v, 2),
                        'half_extents_xy_m': lambda v: _num_array(v, 2)})


def _material(value):
    return _map(value, {key: _number for key in ('static_friction', 'dynamic_friction', 'restitution')})


def _object(value):
    return _map(value, {'id': _text, 'prim': _text, 'shape': _text,
                        'dimensions_m': lambda v: _num_array(v, 3), 'mass_kg': _number,
                        'position_m': lambda v: _num_array(v, 3),
                        'orientation_wxyz': lambda v: _num_array(v, 4)}, allowed_extra=('color_rgb',))


def _candidate_policy(value):
    required = {'tracking_tolerance': lambda v: _array(v, _integer, 8), 'settling_steps': _integer,
                'position_margin_m': _number, 'linear_speed_max_m_s': _number,
                'angular_speed_max_rad_s': _number, 'release_contact_max_n': _number,
                'contact_observation_min_n': _number, 'minimum_lift_m': _number,
                'minimum_transport_m': _number, 'minimum_contact_steps': _integer,
                'minimum_airborne_contact_steps': _integer}
    return _map(value, required, allowed_extra=('semantics', 'tracking_tolerance_basis'))


def security_config(profile, evidence_policy):
    """Select the exact reviewed security semantics; release/docs stay separate."""
    if type(profile) is not dict or type(evidence_policy) is not dict:
        raise ValueError('Profile and evidence policy must be maps')
    if profile['model'].get('sha256') != L.MODEL_MANIFEST_SHA256:
        raise ValueError('Model manifest identity differs from controller configuration')
    model = _map(profile['model'], {'root_pose': lambda v: _map(v, {
        'position_m': lambda x: _num_array(x, 3), 'orientation_wxyz': lambda x: _num_array(x, 4)})},
        allowed_extra=('manifest', 'sha256', 'entrypoint', 'source'))
    coupling = {'driver': _text, 'follower': _text, 'schema': _text, 'gearing': _number,
                'offset': _number, 'reference_axis': _text, 'independent_actuators': _integer,
                'observed_outputs': _integer, 'follower_drive_enabled': _bool}
    mapping = _map(profile['mapping'], {'actuators': lambda v: _strings(v, 7),
        'outputs': lambda v: _strings(v, 8), 'units': lambda v: _strings(v, 8),
        'position_limits': lambda v: _array(v, lambda x: _num_array(x, 2), 8),
        'velocity_limits': lambda v: _num_array(v, 7), 'effort_limits': lambda v: _num_array(v, 7),
        'gripper_coupling': lambda v: _map(v, coupling,
            allowed_extra=('equation', 'command_unit', 'command_meaning', 'authoring_note'))})
    physics_schema = {key: _number for key in ('dt_seconds', 'gravity_m_s2', 'object_sleep_threshold',
        'object_contact_offset_m', 'object_rest_offset_m', 'object_linear_damping', 'object_angular_damping')}
    physics_schema.update({'solver': _text, 'device': _text, 'object_solver_position_iterations': _integer,
        'object_solver_velocity_iterations': _integer, 'grasp_material': _material, 'table_material': _material,
        'self_collision_enabled': _bool})
    regions = profile['regions']
    if type(regions) is not dict or not regions or any(type(k) is not str or not k for k in regions):
        raise ValueError('Invalid scene regions')
    semantics = {'model': model, 'mapping': mapping,
        'runtime': _map(profile['runtime'], {'physics_dt_seconds': _number}, allowed_extra=(
            'isaac_sim', 'python', 'physics_engine', 'device', 'container_image_digest', 'nvidia_base_image_digest')),
        'physics': _map(profile['physics'], physics_schema, allowed_extra=('robot_geometry_and_drive_limits',)),
        'work_surface': _map(profile['work_surface'], {'prim': _text, 'center_m': lambda v: _num_array(v, 3),
            'dimensions_m': lambda v: _num_array(v, 3), 'top_z_m': _number, 'fixed': _bool}),
        'source_area': _geometry(profile['source_area']),
        'regions': {key: _geometry(value) for key, value in regions.items()},
        'objects': _array(profile['objects'], _object),
        'empty_grasp_setup': _map(profile['empty_grasp_setup'], {'object_id': _text,
            'position_m': lambda v: _num_array(v, 3)}, allowed_extra=('timing',)),
        'seed': _integer(profile['seed']), 'candidate_policy': _candidate_policy(profile['candidate_policy'])}
    motion = _map(evidence_policy['motion'], {'outputs': lambda v: _strings(v, 8),
        'units': lambda v: _strings(v, 8), 'physics_hz': _integer, 'simulation_time_tolerance_ns': _integer,
        'tracking_tolerance': lambda v: _array(v, _integer, 8), 'minimum_endpoint_displacement': _integer,
        'incomplete_verdict': _text}, allowed_extra=('interpolation',))
    objects = _map(evidence_policy['objects'], {'angular_speed_max_rad_s': _number,
        'linear_speed_max_m_s': _number, 'position_margin_m': _number, 'release_contact_max_n': _number,
        'settling_intervals': _integer, 'simulation_time_tolerance_ns': _integer})
    config = L.configuration()
    if sha256(encode(config)).digest() != L.CONFIG_DIGEST:
        raise ValueError('Controller configuration digest mismatch')
    return {'schema_version': 2, 'enforcement_id': ENFORCEMENT_ID, 'assessment_id': ASSESSMENT_ID,
        'controller_configuration': config,
        'protocol_limits': {'controller_command_bytes': MAX_COMMAND_BYTES,
            'controller_evidence_bytes': MAX_EVIDENCE_BYTES, 'controller_max_rows': MAX_ROWS,
            'ta_command_bytes': 65536, 'ta_report_bytes': 262144, 'ta_context_bytes': 4096},
        'assessment_motion': motion, 'assessment_objects': objects, 'scene_semantics': semantics}


def security_config_digest(profile, evidence_policy):
    return sha256(encode(security_config(profile, evidence_policy))).hexdigest()
