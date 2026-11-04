"""Run one real signed visual fault probe; not a release or physical test.

Execute with Isaac 6 python.sh and the native dependency environment. Each
invocation retains a new attempt; it never retries an uncertain command.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback
from unittest.mock import patch

from tools.scene_fixture import ROOT
from tools.controller_fixture import authenticated_evidence, development_keys
from tools.run_scene_examples import run_example
from tools.scene_visual import VisualGuard, configure_viewport, visual_experience, visual_metadata
from tools.scene_check import replay_run
from tools.scene_evidence import verify_run
from protected_robot_controller.protocol import public_bytes, verify_sign1
from protected_robot_controller.simulation._backend import _IsaacRobotBackend


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('fault', choices=('seek_restore', 'stage_edit', 'dynamic_stage_edit', 'dynamic_joint_edit', 'target_tensor_edit', 'target_tensor_ulp', 'viewport_close', 'window_close'))
    args = parser.parse_args()
    argv, sys.argv = sys.argv, [sys.argv[0]]
    app = viewport = None
    exit_code = 1
    triggered = False
    injection_completed = False
    guard_errors = []
    requested_after_trigger = []
    trigger_step = 50
    try:
        from isaacsim import SimulationApp
        with visual_experience() as experience:
            metadata = visual_metadata(experience)
            app = SimulationApp({'headless': False, 'fast_shutdown': True, 'multi_gpu': False,
                                 'disable_viewport_updates': False, 'width': 1200, 'height': 900,
                                 'enable_crashreporter': False}, experience=str(experience))
            viewport = configure_viewport()
            keys = development_keys()
            original_pump, original_drive = VisualGuard.pump, _IsaacRobotBackend.drive

            def drive(backend, *drive_args, **kwargs):
                if triggered:
                    requested_after_trigger.append(int(backend._steps))
                    raise RuntimeError('Probe stopped an unexpected requested drive after injection')
                return original_drive(backend, *drive_args, **kwargs)

            def pump(guard, expected_steps):
                nonlocal triggered, injection_completed
                if triggered or expected_steps != trigger_step:
                    return original_pump(guard, expected_steps)
                original_render = guard.backend._world.render

                def inject_then_render():
                    nonlocal triggered, injection_completed
                    triggered = True
                    if args.fault == 'seek_restore':
                        timeline = guard._timeline
                        old = timeline.get_current_time()
                        timeline.set_current_time(old + 1.0)
                        timeline.commit()
                        assert abs(timeline.get_current_time() - (old + 1.0)) < 1e-9, 'seek did not take effect'
                        timeline.set_current_time(old)
                        timeline.commit()
                        assert abs(timeline.get_current_time() - old) < 1e-9, 'seek restore did not take effect'
                        injection_completed = True
                    elif args.fault in ('stage_edit', 'dynamic_stage_edit'):
                        from pxr import Gf
                        path = '/Manipulation/WorkSurface' if args.fault == 'stage_edit' else '/Manipulation/Objects/R1'
                        prim = guard._stage.GetPrimAtPath(path)
                        attr = prim.GetAttribute('xformOp:translate')
                        assert attr, f'missing edit target: {path}'
                        old = attr.Get()
                        new = old + Gf.Vec3d(.01, 0, 0)
                        assert attr.Set(new), 'stage Set failed'
                        assert attr.Get() == new and attr.Get() != old, 'stage edit did not take effect'
                        injection_completed = True
                    elif args.fault == 'dynamic_joint_edit':
                        attr = guard._stage.GetPrimAtPath('/B601/Physics/joint1').GetAttribute('state:angular:physics:position')
                        assert attr, 'missing joint state attribute'
                        old = float(attr.Get())
                        assert attr.Set(old + 1.0), 'joint Set failed'
                        assert abs(float(attr.Get()) - old) > .5, 'joint edit did not take effect'
                        injection_completed = True
                    elif args.fault in ('target_tensor_edit', 'target_tensor_ulp'):
                        np = guard.backend._np
                        view = guard.backend._robot._articulation_view._physics_view
                        targets = np.array(view.get_dof_position_targets(), dtype=np.float32, copy=True)
                        index = int(guard.backend._drive_indices[1 if args.fault == 'target_tensor_ulp' else 0])
                        old = float(targets[0, index])
                        targets[0, index] = (np.nextafter(targets[0, index], np.float32(np.inf))
                                             if args.fault == 'target_tensor_ulp' else old + .05)
                        view.set_dof_position_targets(targets, np.array([0], dtype=np.uint32))
                        actual = np.array(view.get_dof_position_targets(), dtype=float, copy=True)
                        assert float(actual[0, index]) != old, 'tensor target edit did not take effect'
                        injection_completed = True
                    elif args.fault == 'viewport_close':
                        viewport.visible = False
                        assert viewport.visible is False, 'viewport close did not take effect'
                        injection_completed = True
                    else:
                        import omni.kit.app
                        omni.kit.app.get_app().post_quit()
                    result = original_render()
                    if args.fault == 'window_close':
                        assert not app.is_running(), 'application close did not take effect'
                        injection_completed = True
                    return result

                with patch.object(guard.backend._world, 'render', inject_then_render):
                    try:
                        return original_pump(guard, expected_steps)
                    except BaseException as error:
                        guard_errors.append(repr(error))
                        raise

            with patch.object(VisualGuard, 'pump', pump), patch.object(_IsaacRobotBackend, 'drive', drive):
                run = run_example('normal', app=app, keys=keys, record=False, visual=True,
                                  viewport=viewport, visual_runtime=metadata)
            assert triggered, 'fault injection did not run'
            assert injection_completed, 'fault injection did not complete successfully'
            expected_error = {
                'seek_restore': 'Timeline changed during guarded execution',
                'stage_edit': 'Unexpected stage change',
                'dynamic_stage_edit': 'Physics state or clock changed during visual update',
                'dynamic_joint_edit': 'Physics state or clock changed during visual update',
                'target_tensor_edit': 'PhysX drive targets differ from controller targets',
                'target_tensor_ulp': 'PhysX drive targets differ from controller targets',
                'viewport_close': 'Visual viewport closed',
                'window_close': 'Visual window closed',
            }[args.fault]
            assert any(expected_error in error for error in guard_errors), guard_errors
            assert not requested_after_trigger, f'requested drives after fault: {requested_after_trigger}'
            assert run['status'] == 'EXECUTION_FAILED', run
            assert len(run['operations']) == 1, 'unexpected next operation or missing retained partial'
            operation = run['operations'][0]
            assert operation['evidence_validation'] == 'VALID' and operation['motion_verdict'] == 'UNKNOWN', operation
            segment = operation['segments'][0]
            wire, report = ((ROOT / segment[k]).read_bytes() for k in ('command', 'report'))
            command = verify_sign1(wire, keys[0].public_key())
            evidence = authenticated_evidence(report, keys[1].public_key())
            assert evidence['command_digest'] == sha256(wire).digest()
            assert evidence['execution_id'] == command['execution_id']
            assert evidence['partial'] is True and evidence['terminal_state'] == 'ABORTED'
            assert evidence['sample_count'] < evidence['expected_sample_count']
            manifest = ROOT / 'artifacts' / 'scene-work' / 'examples' / run['run_id'] / 'run.json'
            pins = {'expected_runtime': 'native', 'authority_public_der_hex': public_bytes(keys[0].public_key()).hex(),
                    'evidence_public_der_hex': public_bytes(keys[1].public_key()).hex()}
            replay = replay_run(manifest, **pins)
            assert replay['evidence_validation'] == 'VALID' and replay['motion_verdict'] == 'UNKNOWN', replay
            try:
                verify_run(manifest, **pins)
            except ValueError as error:
                assert 'Missing or extra operation' in str(error), error
            else:
                raise AssertionError('Incomplete run incorrectly passed full-coverage verification')
            print(json.dumps({'fault': args.fault, 'status': 'PASS', 'run_id': run['run_id'],
                              'sample_count': evidence['sample_count'],
                              'expected_sample_count': evidence['expected_sample_count'],
                              'termination_reason': evidence['reason'], 'guard_errors': guard_errors,
                              'requested_drives_after_trigger': len(requested_after_trigger),
                              'scope': 'trusted-host injected test, not physical evidence'}), flush=True)
            exit_code = 0
    except BaseException:
        traceback.print_exc()
    finally:
        sys.argv = argv
        if viewport is not None:
            try:
                viewport.destroy()
            except BaseException:
                traceback.print_exc()
                exit_code = 1
        if app is not None:
            app.close(wait_for_replicator=False, skip_cleanup=False, exit_code=exit_code)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
