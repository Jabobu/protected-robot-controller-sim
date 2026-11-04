"""Synthetic archive coverage; no physics or live freshness is asserted."""
from hashlib import sha256
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import encode
from tools.controller_fixture import development_keys
from tools.prc_security import security_config_digest
from tools.scene_check import load_policy, replay_run
from tools.scene_evidence import scenario_operation_plan

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def archive(tmp_path):
    directory = tmp_path / 'artifacts/scene-work/synthetic'
    directory.mkdir(parents=True)
    profile_raw = (ROOT / 'scenes/manipulation/profile.json').read_bytes()
    program_raw = (ROOT / 'scenes/manipulation/trajectories.json').read_bytes()
    model_raw = (ROOT / 'artifacts/model_manifest.json').read_bytes()
    profile, program, policy = json.loads(profile_raw), json.loads(program_raw), load_policy()
    plan = scenario_operation_plan(program, 'missed_grasp')
    authority, evidence = development_keys()
    public = lambda key: key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()
    run = {'run_id': 'missed_grasp-' + '01' * 16, 'scenario': 'missed_grasp', 'files': {},
        'security_config_sha256': security_config_digest(profile, policy),
        'profile_sha256': sha256(profile_raw).hexdigest(), 'trajectory_sha256': sha256(program_raw).hexdigest(),
        'model_sha256': L.MODEL_MANIFEST_SHA256, 'runtime_image': profile['runtime_image'],
        'source_files_sha256': sha256(encode({})).hexdigest(), 'required_operations': plan,
        'operation_plan_sha256': sha256(encode(plan)).hexdigest(), 'operations': [],
        'authority_public_der_hex': public(authority), 'evidence_public_der_hex': public(evidence),
        'config_digest_hex': L.CONFIG_DIGEST.hex(), 'public_inputs': {}}
    for name, raw in [('profile', profile_raw), ('program', program_raw), ('model', model_raw),
                      ('source_files', b'{}'), ('runtime', json.dumps({'runtime_image': profile['runtime_image']}).encode()),
                      ('operation_plan', json.dumps(plan).encode())]:
        path = directory / (name + '.json')
        path.write_bytes(raw)
        relative = str(path.relative_to(tmp_path))
        run['files'][relative] = sha256(raw).hexdigest()
        run['public_inputs'][name] = relative
    run['runtime_metadata_sha256'] = run['files'][run['public_inputs']['runtime']]
    manifest = directory / 'run.json'
    def save(): manifest.write_text(json.dumps(run))
    save()
    return tmp_path, manifest, run, save


def test_missing_operation_remains_unknown(archive):
    root, manifest, _, _ = archive
    result = replay_run(manifest, root=root)
    assert result['evidence_validation'] == 'VALID'
    assert result['motion_verdict'] == 'UNKNOWN'
    assert result['operations'][0]['object_verdict'] == 'UNKNOWN'


@pytest.mark.parametrize('fault', ['source_digest', 'semantic_digest', 'model_digest', 'plan_digest', 'pinned_key', 'profile_bytes', 'unsafe_path', 'symlink'])
def test_archive_metadata_and_paths_fail_closed(archive, fault):
    root, manifest, run, save = archive
    if fault == 'source_digest': run['source_files_sha256'] = '0' * 64
    elif fault == 'semantic_digest': run['security_config_sha256'] = '0' * 64
    elif fault == 'model_digest': run['model_sha256'] = '0' * 64
    elif fault == 'plan_digest': run['operation_plan_sha256'] = '0' * 64
    elif fault == 'profile_bytes': (root / run['public_inputs']['profile']).write_bytes(b'{}')
    elif fault == 'unsafe_path': run['public_inputs']['profile'] = '../elsewhere'
    elif fault == 'symlink':
        path = root / run['public_inputs']['profile']
        saved = path.with_name('elsewhere.json')
        path.rename(saved)
        path.symlink_to(saved.name)
    save()
    kwargs = {'authority_public_der_hex': '00'} if fault == 'pinned_key' else {}
    result = replay_run(manifest, root=root, **kwargs)
    assert result['evidence_validation'] == 'REJECTED_EVIDENCE'
    assert result['motion_verdict'] is None and result['object_verdict'] == 'UNKNOWN'


@pytest.mark.parametrize("bad", [[], None, "container", 17])
def test_malformed_runtime_metadata_rejects(archive, bad):
    root, manifest, run, save = archive
    path = root / run['public_inputs']['runtime']
    raw = json.dumps(bad).encode()
    path.write_bytes(raw)
    digest = sha256(raw).hexdigest()
    run['files'][run['public_inputs']['runtime']] = digest
    run['runtime_metadata_sha256'] = digest
    save()
    assert replay_run(manifest, root=root)['evidence_validation'] == 'REJECTED_EVIDENCE'

@pytest.mark.parametrize('new_runtime', [False, True])
def test_signed_archive_relabel_cannot_rebind_context(archive, new_runtime):
    """Synthetic but genuinely signed legacy/v3 archives resist a rehashed relabel."""
    from copy import deepcopy
    from protected_robot_controller.protocol import PROFILE, key_id, public_bytes
    from tools.scene_evidence import segment_binding
    from test_scene_replay_v2 import vector, sign_report

    root, manifest, run, save = archive
    profile = json.loads((root / run['public_inputs']['profile']).read_bytes())
    program = json.loads((root / run['public_inputs']['program']).read_bytes())
    authority, evidence = development_keys()
    run['authority_public_der_hex'] = public_bytes(authority.public_key()).hex()
    run['evidence_public_der_hex'] = public_bytes(evidence.public_key()).hex()
    image = 'sha256:' + 'b' * 64

    def update_runtime(kind):
        if kind == 'legacy':
            run.pop('runtime_identity', None)
            run['runtime_image'] = profile['runtime_image']
            runtime = {'runtime_image': run['runtime_image'], 'isaac_version': ['6.0.0']}
        else:
            ident = {'schema_version': 1, 'kind': kind,
                     'image_id': image if kind == 'container' else None,
                     'identity_source': 'trusted_launcher' if kind == 'container' else 'local_process',
                     'python_executable': '/test/python'}
            run['runtime_identity'] = ident
            run['runtime_image'] = ident['image_id']
            runtime = {'runtime_image': ident['image_id'], 'runtime_identity': ident, 'isaac_version': ['6.0.0']}
        raw = json.dumps(runtime).encode()
        rel = run['public_inputs']['runtime']
        (root / rel).write_bytes(raw)
        run['runtime_metadata_sha256'] = run['files'][rel] = sha256(raw).hexdigest()

    def retain(name, raw):
        target = manifest.parent / name
        target.write_bytes(raw)
        rel = str(target.relative_to(root))
        run['files'][rel] = sha256(raw).hexdigest()
        return rel

    update_runtime('native' if new_runtime else 'legacy')
    ref = [profile, load_policy(), program, authority, evidence, run]
    command, wire, report, expectation = vector(ref)
    bundle = sign_report(report, evidence)
    binding = segment_binding(run, 0)
    hello = {'version': 1, 'type': 'HELLO', 'profile': PROFILE, 'robot_id': L.ROBOT_ID,
             'controller_id': L.CONTROLLER_ID, 'config_digest': L.CONFIG_DIGEST, 'boot_id': b'b' * 32,
             'challenge': b'\x01' * 32, 'sequence_floor': 0, 'expires_ns': 10**12,
             'evidence_key_id': key_id(evidence.public_key())}
    phases = expectation['phases']
    context = {'schema_version': 1, 'authority_public_der_hex': run['authority_public_der_hex'],
               'evidence_public_der_hex': run['evidence_public_der_hex'],
               'authority_key_id': key_id(authority.public_key()).hex(),
               'evidence_key_id': key_id(evidence.public_key()).hex(),
               'config_cbor_hex': encode(L.configuration()).hex(), 'config_digest_hex': L.CONFIG_DIGEST.hex(),
               'profile_sha256': run['profile_sha256'], 'trajectory_sha256': run['trajectory_sha256'],
               'command_sha256': sha256(wire).hexdigest(), 'report_sha256': sha256(bundle).hexdigest(),
               'candidate_tolerance': load_policy()['motion']['tracking_tolerance'], 'phases': phases,
               'binding': binding, 'outputs': list(L.OUTPUTS), 'units': list(L.UNITS)}
    reference = {'trajectory': command['trajectory'], 'phases': phases,
                 'hold_steps': command['hold_steps'], 'initial_target': program['initial_target']}
    segment = {'operation_index': 0, 'segment_index': 0, 'global_segment_index': 0,
               'required_segment_count': 1, 'command_sha256': sha256(wire).hexdigest(),
               'report_sha256': sha256(bundle).hexdigest(), 'command_bytes': len(wire), 'report_bytes': len(bundle),
               'boot_id': command['boot_id'].hex(), 'execution_id': command['execution_id'].hex(),
               'sequence': command['sequence'], 'outputs': list(L.OUTPUTS), 'units': list(L.UNITS),
               'config_digest_hex': L.CONFIG_DIGEST.hex(), 'phases': phases,
               'reference_trajectory_sha256': sha256(encode(command['trajectory'])).hexdigest(),
               'public_context': retain('context.json', json.dumps(context).encode()),
               'reference': retain('reference.json', json.dumps(reference).encode()),
               'hello': retain('hello.cbor', encode(hello)), 'command': retain('command.cbor', wire),
               'report': retain('report.cbor', bundle)}
    run['operations'] = [{'object_id': run['required_operations'][0]['object_id'],
                          'destination': run['required_operations'][0]['destination'], 'segments': [segment]}]
    save()
    expected = 'native' if new_runtime else profile['runtime_image']
    original = replay_run(manifest, root=root, expected_runtime=expected)
    assert original['evidence_validation'] == 'VALID', original

    # Rewrite runtime plus every manifest/context digest while retaining the
    # authenticated command/report bytes. This changes the expected binding.
    update_runtime('container' if new_runtime else 'native')
    context['binding'] = segment_binding(run, 0)
    raw = json.dumps(context).encode()
    (root / segment['public_context']).write_bytes(raw)
    run['files'][segment['public_context']] = sha256(raw).hexdigest()
    save()
    changed = replay_run(manifest, root=root, expected_runtime=image if new_runtime else 'native')
    assert changed['evidence_validation'] == 'REJECTED_EVIDENCE', changed
