"""S6-04 controlled, recorded PhysX examples through the existing signed bytes.

Requires Isaac Sim 6.0.0 and an explicitly declared runtime identity. No retries, policy adjustment,
synthetic sensor values, or evidence-file faults. Every attempt has a unique
directory, including failures. Task semantics remain in these fixture tools.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from hashlib import sha256
import json
import os
import sys
import time
import traceback
from unittest.mock import patch
from uuid import uuid4

# Import the pinned crypto stack before SimulationApp can shadow its packages.
from tools.scene_fixture import (
    ROOT, OUTPUT, PROFILE_PATH, TRAJECTORY_PATH, ManipulationScene, _ObservedBackend,
    read_configuration, protocol_runtime, expand_operation, execution_guard,
    contact_diagnostics, contact_requirements_met, digest, write_json, utc_now,
)
from protected_robot_controller import limits as L
from protected_robot_controller.controller import Controller
from protected_robot_controller.interface import ControllerInterface, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode, strict_decode, public_bytes
from tools.controller_fixture import development_keys, command_for, sign_command, authenticated_evidence
from tools.integrated_fixture import _compare_observations
from tools.scene_evidence import prepare_run, segment_binding, complete_segment
from tools.scene_check import SceneChecker, expected_segment, load_policy, POLICY
from tools.scene_objects import assess_objects, in_destination
from tools.runtime_provenance import current_runtime

SCENARIOS = ("normal", "missed_grasp", "obstructed", "incomplete")
INTERRUPT_AFTER_SAMPLES = 121  # Initial reading plus 120 completed physics steps.
HOLD_OBSERVATION_STEPS = 120
REPRODUCTION = "<Isaac Sim python.sh> -m tools.run_scene_examples"


def relative(path):
    return str(path.relative_to(ROOT))


class ExampleStore:
    def __init__(self, profile, scenario, record, *, visual=False, run_id=None, directory=None, metadata=None):
        # The campaign supplies its preassigned slot and append-only store.
        # Ordinary S6-04 callers retain exactly their original storage behavior.
        self.run_id = run_id or scenario + "-" + uuid4().hex
        self.directory = directory or OUTPUT / "examples" / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)
        runtime_identity = current_runtime()
        self.record = {
            "schema_version": 1, "stage": "S6-04", "kind": "EXAMPLE_NOT_CAMPAIGN",
            "run_id": self.run_id, "scenario": scenario, "status": "STARTED",
            "started_at_utc": utc_now(), "profile_sha256": digest(PROFILE_PATH),
            "trajectory_sha256": digest(TRAJECTORY_PATH), "policy_sha256": digest(POLICY),
            "source_fingerprint": os.environ.get("PRC_SCENE_SOURCE_FINGERPRINT"),
            "runtime_image": runtime_identity["image_id"], "runtime_identity": runtime_identity,
            "model_sha256": profile["model"]["sha256"],
            "seed": profile["seed"], "camera_enabled": record or visual, "recording_enabled": record,
            "operations": [], "recordings": [], "persistence_observed": False,
            "reproduction_command": REPRODUCTION + " --scenario " + scenario + ("" if record else " --no-record") + (" --visual" if visual else ""),
            "scope": "Trusted-host simulation; object/hold/image observations unsigned; no physical attestation",
            "reasons": ["Attempt started; no outcome established"],
        }
        self.record.update(metadata or {})
        write_json(self.directory / "start.json", self.record)
        self.publish("start.json")

    def publish(self, filename):
        path = OUTPUT / "examples.json"
        summary = json.loads(path.read_bytes()) if path.exists() else {"runs": []}
        entry = {"run_id": self.run_id, "scenario": self.record["scenario"],
                 "manifest": relative(self.directory / filename),
                 "sha256": digest(self.directory / filename), "status": self.record["status"],
                 "reasons": self.record["reasons"]}
        summary.update(schema_version=1, stage="S6-04", status="RETAINED_ATTEMPTS",
                       acceptance="EXTERNAL_SUPERVISOR_ONLY", campaign_frozen=False,
                       reasons=["Each entry links actual retained files, including failed attempts; this index is not gate acceptance"])
        # Update only this newly created attempt; never substitute for another run.
        summary["runs"] = [r for r in summary.get("runs", []) if r["run_id"] != self.run_id] + [entry]
        write_json(path, summary)

    def finish(self):
        self.record["completed_at_utc"] = utc_now()
        self.record["files"] = {relative(p): digest(p) for p in sorted(self.directory.rglob("*"))
                                if p.is_file() and p.name != "run.json"}
        write_json(self.directory / "run.json", self.record)
        self.publish("run.json")


def independent_state(backend, scene):
    """Copy actual current PhysX output and object arrays, never drive targets."""
    return {
        "physics_step": int(backend._world.current_time_step_index),
        "simulation_time_ns": round(float(backend._world.current_time) * 1e9),
        "positions": list(backend._read_vector(backend._robot.get_joint_positions)),
        "velocities": list(backend._read_vector(backend._robot.get_joint_velocities)),
        "objects": scene.observe(),
    }


class ExampleBackend(_ObservedBackend):
    """Trusted test instrumentation; controller receives only native readings."""
    def __init__(self, backend, scene, acquisition=None):
        super().__init__(backend, scene)
        self.acquisition = acquisition
        self.stop_calls = []
        self.target_writes = []

    def sample_outputs(self):
        if self.acquisition is not None and self.backend._steps == INTERRUPT_AFTER_SAMPLES:
            # The next step really occurred. Revoke the native sensor view before
            # its reading, not an already signed sample or a serialized report.
            self.acquisition.interrupt()
        return super().sample_outputs()

    def stop_or_hold(self, reason):
        call = {"reason": reason, "physics_step": int(self.backend._world.current_time_step_index),
                "target_writes_before": len(self.target_writes), "returned": False}
        self.stop_calls.append(call)
        try:
            super().stop_or_hold(reason)
            call["returned"] = True
        finally:
            call.update(target_writes_after=len(self.target_writes), backend_faulted=self.backend._faulted)


def observe_hold(backend, observed, scene, controller, path):
    """Observe dynamics under the controller's last actual hold write.

    These extra steps are OUTSIDE the finished/aborted signed execution. There
    are no new actuator commands, resets, sensor samples for signing, or recovery
    of the aborted backend. No frozen simulator is called a stopped robot.
    """
    record = {
        "scope": "Unsigned independent post-command PhysX diagnostics; never appended to signed evidence",
        "controller_state": controller.state, "backend_faulted": backend._faulted,
        "stop_calls": observed.stop_calls, "drive_writes_before": observed.drive_writes,
        "target_writes_before": len(observed.target_writes), "rows": [],
        "requested_intervals": HOLD_OBSERVATION_STEPS,
        "stationary_velocity_thresholds": [.01] * 6 + [.001] * 2,
        "stationary_window_intervals": 30,
    }
    try:
        if not backend._world.is_playing():
            raise RuntimeError("Independent hold observation requires advancing physics, not a paused scene")
        record["rows"].append(independent_state(backend, scene))
        for _ in range(HOLD_OBSERVATION_STEPS):
            backend._world.step(render=False)
            state = independent_state(backend, scene)
            previous = record["rows"][-1]
            record["rows"].append(state)
            if (state["physics_step"] != previous["physics_step"] + 1
                    or abs((state["simulation_time_ns"] - previous["simulation_time_ns"]) * L.HZ
                           - 1_000_000_000) > 5 * L.HZ):
                raise RuntimeError("Post-stop physics did not advance by one fixed step")
    except BaseException:
        record["error"] = traceback.format_exc()
        raise
    finally:
        # Preserve a diagnostic prefix even when a later independent read fails.
        write_json(path, record)
    record.update(drive_writes_after=observed.drive_writes, target_writes_after=len(observed.target_writes),
                  max_abs_displacement=[max(abs(r["positions"][i] - record["rows"][0]["positions"][i])
                                            for r in record["rows"]) for i in range(8)],
                  final_positions=record["rows"][-1]["positions"],
                  final_velocities=record["rows"][-1]["velocities"])
    record["stationary_last_30_intervals"] = all(
        abs(v) <= threshold for row in record["rows"][-31:]
        for v, threshold in zip(row["velocities"], record["stationary_velocity_thresholds"]))
    record["no_additional_drive_writes"] = (record["drive_writes_before"] == record["drive_writes_after"]
                                             and record["target_writes_before"] == record["target_writes_after"])
    return record


def execute_operation(store, program, profile, policy, index, interface, observed, authority, evidence_key, checker):
    """Retain original byte traffic before authenticating or classifying it."""
    operation = program["operations"][index]
    name = f"{index+1:02d}-{operation['object_id']}-{operation['destination']}"
    reference, phases = expand_operation(program, operation)
    write_json(store.directory / (name + ".reference.json"),
               {"trajectory": reference, "phases": phases, "hold_steps": program["hold_steps"],
                "initial_target": program["initial_target"]})
    hello_raw = interface.handle(encode({"version": 1, "type": "HELLO"}))
    (store.directory / (name + ".hello.cbor")).write_bytes(hello_raw)
    hello = strict_decode(hello_raw, MAX_RESPONSE_BYTES)
    command = command_for(hello, program["initial_target"] + [program["initial_target"][-1]],
                          reference, hold_steps=program["hold_steps"])
    command["initial_tolerance"] = program["initial_tolerance"]
    binding = segment_binding(store.record, index)
    command["authorization_context_digest"] = sha256(encode(binding)).digest()
    wire = sign_command(command, authority)
    request = encode({"version": 1, "type": "EXECUTE", "command": wire})
    for suffix, raw in (("command.cbor", wire), ("request.cbor", request)):
        (store.directory / (name + "." + suffix)).write_bytes(raw)
    context = {
        "authority_public_der_hex": public_bytes(authority.public_key()).hex(),
        "evidence_public_der_hex": public_bytes(evidence_key.public_key()).hex(),
        "config_cbor_hex": encode(L.configuration()).hex(),
        "profile_sha256": store.record["profile_sha256"], "trajectory_sha256": store.record["trajectory_sha256"],
        "command_sha256": sha256(wire).hexdigest(), "candidate_tolerance": policy["motion"]["tracking_tolerance"],
        "phases": phases, "binding": binding,
    }
    write_json(store.directory / (name + ".public.json"), context)
    joint_start, object_start = len(observed.joints), len(observed.objects)
    started = time.perf_counter()
    response_raw = interface.handle(request)
    elapsed = time.perf_counter() - started
    (store.directory / (name + ".response.cbor")).write_bytes(response_raw)
    response = strict_decode(response_raw, MAX_RESPONSE_BYTES)
    joints, objects = observed.joints[joint_start:], observed.objects[object_start:]
    write_json(store.directory / (name + ".joints.json"), joints)
    write_json(store.directory / (name + ".acquired-objects.json"), objects)
    write_json(store.directory / (name + ".objects.json"), objects)
    if response.get("type") != "EVIDENCE":
        raise RuntimeError(f"Command did not return evidence: {response}")
    bundle = response["evidence"]
    (store.directory / (name + ".report.cbor")).write_bytes(bundle)
    checking_started = time.perf_counter()
    evidence = authenticated_evidence(bundle, evidence_key.public_key())
    segment = {
        "boot_id": command["boot_id"].hex(), "execution_id": command["execution_id"].hex(),
        "sequence": command["sequence"], "command_bytes": len(wire), "report_bytes": len(bundle),
        "execution_seconds": elapsed, "checking_seconds": 0.0, "phases": phases,
        "reference_trajectory_sha256": sha256(encode(reference)).hexdigest(),
        "physics_step_first": objects[0]["physics_step"] if objects else None,
        "physics_step_last": objects[-1]["physics_step"] if objects else None,
        **{field: relative(store.directory / (name + "." + suffix)) for field, suffix in (
            ("command", "command.cbor"), ("report", "report.cbor"), ("public_context", "public.json"),
            ("joint_observations", "joints.json"), ("object_observations", "objects.json"),
            ("acquired_object_observations", "acquired-objects.json"), ("reference", "reference.json"))},
    }
    complete_segment(store, index, name, segment, context, wire, bundle, command, evidence)
    result = checker.assess_operation(
        [{"segment_index": 0, "command": wire, "report": bundle}],
        [expected_segment(program, index, binding, hello)])
    _compare_observations(evidence, joints)
    object_result = assess_objects(objects, operation["object_id"], operation["destination"], profile, policy,
                                   end_step=objects[-1]["physics_step"], end_time_ns=objects[-1]["simulation_time_ns"]) if objects else {
                                       "object_verdict": "UNKNOWN", "reasons": ["No independent object observations"]}
    diagnostic = contact_diagnostics(objects, operation["object_id"], phases, profile) if objects else None
    segment["checking_seconds"] = time.perf_counter() - checking_started
    write_json(store.directory / (name + ".segment.json"), segment)
    op = {"object_id": operation["object_id"], "destination": operation["destination"],
          "evidence_validation": result["evidence_validation"], "motion_verdict": result["motion_verdict"],
          "object_verdict": object_result["object_verdict"], "reasons": result["reasons"] + object_result["reasons"],
          "motion_diagnostics": result, "object_diagnostics": object_result,
          "contact_diagnostics": diagnostic, "contact_requirements_met": contact_requirements_met(diagnostic, profile),
          "segments": [segment]}
    store.record["operations"].append(op)
    write_json(store.directory / (name + ".assessment.json"), op)
    return op, evidence, objects


def requirements_observed(run, fault):
    """Compare observed results to the example requirements, never set verdicts."""
    operations, scenario = run["operations"], run["scenario"]
    count = 2 if scenario == "normal" else 1
    if len(operations) != count or any(o["evidence_validation"] != "VALID" for o in operations):
        return False
    expected_motion = {"normal": "CONFORMANT", "missed_grasp": "CONFORMANT", "obstructed": "DEVIATED", "incomplete": "UNKNOWN"}[scenario]
    if any(o["motion_verdict"] != expected_motion for o in operations):
        return False
    if scenario == "normal":
        return run["persistence_observed"] and all(o["object_verdict"] == "DELIVERED" and o["contact_requirements_met"] for o in operations)
    if scenario == "missed_grasp":
        return operations[0]["object_verdict"] == "NOT_DELIVERED"
    if scenario == "incomplete":
        segment = operations[0]["segments"][0]
        acquisition = fault.get("acquisition", {})
        return (segment["partial"] and segment["captured_sample_count"] == INTERRUPT_AFTER_SAMPLES
                and segment["termination_reason"] == "BACKEND"
                and not operations[0]["motion_diagnostics"]["captured_tracking_deviation"]
                and all(acquisition.get(k) is True for k in (
                    "triggered", "native_read_failed", "source_valid_before", "independent_view_live",
                    "physics_still_playing", "scheduled_step_match", "getter_restored"))
                and acquisition.get("source_valid_after") is False
                and acquisition.get("source_valid_after_restore") is False)
    return True


def run_example(scenario, *, app, keys=None, record=True, store=None, ros2=False, visual=False, viewport=None, visual_runtime=None):
    """One attempt, with fresh scene only before the run and no automatic retry."""
    if scenario not in SCENARIOS:
        raise ValueError("Unknown controlled example")
    if visual and (record or ros2 or viewport is None or not isinstance(visual_runtime, dict)):
        raise ValueError("Visual mode requires a standalone viewport, no recording, and no ROS service")
    profile, program = read_configuration()
    policy = load_policy()
    store = ExampleStore(profile, scenario, record, visual=visual) if store is None else store
    if store.record["scenario"] != scenario or store.record["profile_sha256"] != digest(PROFILE_PATH):
        raise ValueError("Supplied fixture store does not match this scenario/profile")
    backend = observed = recorder = acquisition = visual_guard = None
    all_objects = []
    fault = {"kind": {"normal": "NONE", "missed_grasp": "OBJECT_RELOCATED_BEFORE_RUN",
                       "obstructed": "PHYSX_ARM_JOINT_LIMIT", "incomplete": "NATIVE_ACQUISITION_INVALIDATION"}[scenario],
             "schedule": "Trusted setup before execution" if scenario != "incomplete" else
                         "After step 121, before acquisition; initial plus first 120 readings retained",
             "policy_changed": False, "trajectory_changed": False}
    if scenario == "missed_grasp":
        fault.update(profile["empty_grasp_setup"])
    if scenario == "incomplete":
        fault.update(interrupt_after_captured_samples=INTERRUPT_AFTER_SAMPLES,
                     interrupted_physics_step=INTERRUPT_AFTER_SAMPLES)
    if scenario == "obstructed":
        fault.update(actuator="joint1", half_width_rad=1e-5, required_phases=["approach", "transport"])
    write_json(store.directory / "fault_parameters.json", fault)
    store.record["fault_parameters"] = relative(store.directory / "fault_parameters.json")
    try:
        if store.record["profile_sha256"] != policy["profile_sha256"] or store.record["trajectory_sha256"] != policy["trajectory_sha256"]:
            raise RuntimeError("Scene profile/program differs from frozen assessment policy")
        store.record["protocol_runtime"] = protocol_runtime()
        write_json(store.directory / "protocol_runtime.json", store.record["protocol_runtime"])
        from isaacsim.core.version import get_version
        from protected_robot_controller.simulation._backend import _IsaacRobotBackend
        from tools.scene_faults import constrain_arm_joint, NativeAcquisitionInterruption
        from tools.scene_recording import SceneRecorder

        version = list(get_version())
        if version[0].split("-")[0].split("+")[0] != "6.0.0":
            raise RuntimeError(f"Pinned Isaac 6.0.0 required; observed {version}")
        store.record["isaac_version"] = version
        scene = ManipulationScene(profile, camera=record or visual, empty_grasp=scenario == "missed_grasp")
        backend = _IsaacRobotBackend(setup_scene=scene.build)
        store.record["geometry"] = scene.describe(backend)
        write_json(store.directory / "geometry.json", store.record["geometry"])
        backend._stage.GetRootLayer().Export(str(store.directory / "scene.usda"))
        if scenario == "obstructed":
            fault["constraint"] = constrain_arm_joint(backend)
        if visual:
            from isaacsim.core.utils.viewports import set_camera_view
            from tools.scene_visual import VisualGuard
            set_camera_view(eye=profile["camera"]["eye_m"], target=profile["camera"]["target_m"])
            visual_guard = VisualGuard(app, backend, scene, viewport)
            backend._visual_guard = visual_guard
            store.record["visual_runtime"] = dict(visual_runtime)
            # Shader/view warmup is outside HELLO and command deadlines. No
            # physics, drive target or sensor data may change during a pump.
            for _ in range(30):
                visual_guard.pump(backend._steps)
        authority, evidence_key = development_keys() if keys is None else keys
        prepare_run(store, program, authority.public_key(), evidence_key.public_key())
        (store.directory / "policy.snapshot.json").write_bytes(POLICY.read_bytes())
        all_objects.append(scene.observe())
        with execution_guard(backend, scene) as guard, ExitStack() as stack:
            store.record["execution_guard"] = guard
            if record:
                recorder = SceneRecorder(app, backend, scene, store.directory / "recordings")
                store.record["recording_index"] = relative(recorder.index_path)
                recorder.capture("setup")  # Shader warmup before controller time limits.
            if scenario == "incomplete":
                acquisition = NativeAcquisitionInterruption(backend)
                stack.enter_context(acquisition)
                fault["acquisition"] = acquisition.record
            observed = ExampleBackend(backend, scene, acquisition)
            original_write = backend._write_targets
            def write_targets(target):
                # Observe the real private writer, including terminal hold. Do
                # not change its arguments, return value, bounds or behavior.
                original_write(target)
                observed.target_writes.append({"physics_step": int(backend._world.current_time_step_index),
                                               "targets": list(target)})
            stack.enter_context(patch.object(backend, "_write_targets", write_targets))
            controller = Controller(authority.public_key(), evidence_key, observed)
            interface = ControllerInterface(controller)
            if ros2:
                from tools.ros2_fixture import RosFixture, invalid_command_probe
                ros = RosFixture(interface, store.directory / "ros2-transport")
                stack.callback(ros.close)
                interface = ros
                store.record["transport"] = {"type": "ROS2", **ros.runtime}
                ros.on_owner_thread(lambda: invalid_command_probe(ros, store, observed, authority, program))
            checker = SceneChecker(authority.public_key(), evidence_key.public_key(), policy)
            for index in range(len(store.record["required_operations"])):
                if visual_guard is not None:
                    # No command is pending here. Process a queued close or
                    # prohibited GUI event before issuing the next HELLO.
                    visual_guard.pump(backend._steps)
                operation = lambda: execute_operation(store, program, profile, policy, index,
                                                      interface, observed, authority, evidence_key, checker)
                op, evidence, objects = ros.on_owner_thread(operation) if ros2 else operation()
                all_objects.extend(r for r in objects if r["physics_step"] > all_objects[-1]["physics_step"])
                if acquisition is not None:
                    # The controller already signed and returned the real partial
                    # prefix. Restore only the independent raw getter, never the
                    # invalidated source, backend state, report or sample count.
                    acquisition.__exit__(None, None, None)
                    fault["acquisition"] = acquisition.record
                if index == 1:
                    store.record["persistence_observed"] = bool(objects) and all(
                        in_destination(r, "R1", "A", profile, policy) for r in objects)
                    store.record["persistence_samples"] = len(objects)
                if recorder is not None:
                    recorder.capture(f"operation-{index+1}-returned")
                if op["evidence_validation"] != "VALID":
                    raise RuntimeError("Rejected evidence retained; cannot continue this example")
                if evidence["terminal_state"] != "COMPLETE" and scenario != "incomplete":
                    raise RuntimeError("Unexpected partial operation retained; cannot continue")
            store.record["controller_state_after_command"] = controller.state
            store.record["physics_steps_measured"] = backend._steps
            store.record["requested_drive_writes"] = observed.drive_writes
            store.record["stop_hold_observations"] = relative(store.directory / "stop_hold_observations.json")
            hold = observe_hold(backend, observed, scene, controller, store.directory / "stop_hold_observations.json")
            write_json(store.directory / "stop_hold_observations.json", hold)
            all_objects.extend(r["objects"] for r in hold["rows"] if r["physics_step"] > all_objects[-1]["physics_step"])
            if scenario == "incomplete":
                op = store.record["operations"][0]
                segment = op["segments"][0]
                # Keep the original acquired-object prefix file as well. The
                # separate final object window includes real unsigned post-stop
                # observations, never replacement joint evidence.
                final_objects = objects + [r["objects"] for r in hold["rows"]
                                           if r["physics_step"] > objects[-1]["physics_step"]]
                write_json(ROOT / segment["object_observations"], final_objects)
                segment["physics_step_last"] = final_objects[-1]["physics_step"]
                result = assess_objects(final_objects, "R1", "A", profile, policy,
                                        end_step=final_objects[-1]["physics_step"], end_time_ns=final_objects[-1]["simulation_time_ns"])
                op.update(object_verdict=result["object_verdict"], object_diagnostics=result,
                          reasons=op["motion_diagnostics"]["reasons"] + result["reasons"])
                write_json(store.directory / "01-R1-A.segment.json", segment)
                write_json(store.directory / "01-R1-A.assessment.json", op)
            if recorder is not None:
                recorder.capture("post-hold")
            store.record["geometry_after"] = scene.describe(backend)
            observed_ok = requirements_observed(store.record, fault)
            store.record["status"] = "OBSERVED_EXPECTED" if observed_ok else "OBSERVED_MISMATCH"
            store.record["reasons"] = ["Frozen checks observed the required scenario outcomes" if observed_ok else
                                       "Observed outcome differs from scenario requirements; retain actual verdicts and diagnostics"]
    except BaseException as error:
        store.record["status"] = "EXECUTION_FAILED"
        store.record["reasons"] = [repr(error)]
        write_json(store.directory / "error.json", {"traceback": traceback.format_exc()})
    finally:
        if acquisition is not None:
            fault["acquisition"] = acquisition.record
        write_json(store.directory / "fault_parameters.json", fault)
        if observed is not None:
            write_json(store.directory / "all_joint_observations.json", observed.joints)
            write_json(store.directory / "all_acquired_object_observations.json", observed.objects)
            write_json(store.directory / "target_writes.json", observed.target_writes)
            write_json(store.directory / "stop_calls.json", observed.stop_calls)
            store.record["target_writes"] = relative(store.directory / "target_writes.json")
        write_json(store.directory / "object_observations.json", all_objects)
        store.record["object_observations"] = relative(store.directory / "object_observations.json")
        if visual_guard is not None:
            try:
                visual_guard.close()
                if backend is not None:
                    backend._visual_guard = None
            except BaseException as error:
                store.record.setdefault("cleanup_errors", []).append(repr(error))
                store.record.update(status="EXECUTION_FAILED", reasons=["Visual cleanup failed; see retained errors"])
        for resource in (recorder, backend):
            if resource is not None:
                try:
                    resource.close()
                except BaseException as error:
                    store.record.setdefault("cleanup_errors", []).append(repr(error))
                    store.record.update(status="EXECUTION_FAILED", reasons=["Cleanup failed; see retained errors"])
        if recorder is not None:
            store.record["recordings"] = [r["image_path"] for r in recorder.records if r["status"] == "CAPTURED"]
        store.finish()
    # Return the published JSON representation: native scene metadata can
    # contain tuples (for example gravity), which JSON stores as arrays. The
    # caller and offline replay must see the same manifest, including failures.
    return json.loads((store.directory / "run.json").read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="all")
    parser.add_argument("--no-record", action="store_true", help="Do not capture separate observation-camera recordings")
    parser.add_argument("--ros2", action="store_true", help="Use the development ROS 2 byte service")
    parser.add_argument("--visual", action="store_true", help="Open a new, restricted standalone Isaac window")
    args = parser.parse_args()
    if args.visual and (not args.no_record or args.ros2):
        parser.error("--visual requires --no-record and cannot be combined with --ros2")
    if args.visual and (os.environ.get("PRC_RUNTIME_KIND") != "native" or not os.environ.get("DISPLAY")):
        parser.error("--visual requires the native launcher and a local display")
    argv = sys.argv
    sys.argv = [argv[0]]
    app = viewport = None
    code = 1
    try:
        from isaacsim import SimulationApp
        with ExitStack() as startup:
            options = {"headless": not args.visual, "fast_shutdown": True, "multi_gpu": False,
                       "disable_viewport_updates": not args.visual, "width": 1200, "height": 900,
                       "enable_crashreporter": False}
            if args.visual:
                from tools.scene_visual import visual_experience, configure_viewport, visual_metadata
                experience = startup.enter_context(visual_experience())
                visual_runtime = visual_metadata(experience)
                app = SimulationApp(options, experience=str(experience))
                viewport = configure_viewport()
            else:
                visual_runtime = None
                app = SimulationApp(options)
            sys.argv = argv
            keys = development_keys()
            scenarios = SCENARIOS if args.scenario == "all" else (args.scenario,)
            runs = []
            for scenario in scenarios:
                if args.visual:
                    # Between scenes there is no live backend or command. Pump
                    # queued close events before any new setup drive can occur.
                    app.update()
                    if not app.is_running() or not viewport.visible:
                        break
                run = run_example(scenario, app=app, keys=keys, record=not args.no_record, ros2=args.ros2,
                                  visual=args.visual, viewport=viewport, visual_runtime=visual_runtime)
                runs.append(run)
                if args.visual and run["status"] != "OBSERVED_EXPECTED":
                    break
            print(json.dumps([{k: r[k] for k in ("run_id", "scenario", "status", "reasons")} for r in runs], indent=2), flush=True)
            code = 0 if len(runs) == len(scenarios) and all(r["status"] == "OBSERVED_EXPECTED" for r in runs) else 1
    except BaseException:
        traceback.print_exc()
    finally:
        sys.argv = argv
        if viewport is not None:
            try:
                viewport.destroy()
            except BaseException:
                traceback.print_exc()
                code = 1
        if app is not None:
            app.close(wait_for_replicator=False, skip_cleanup=False, exit_code=code)


if __name__ == "__main__":
    main()
