"""S6-01 trusted manipulation fixture; task semantics never enter the controller.

Requires Isaac Sim 6.0.0 and an explicitly declared runtime identity. Configuration is read-only;
all outputs, including failed attempts, live in unique scene-work directories.
No planning, camera or object-outcome code is imported by the controller.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
from hashlib import sha256
from importlib.metadata import version as package_version
import json
import math
import os
from pathlib import Path
import sys
import time
import traceback
from unittest.mock import patch
from uuid import uuid4

# Load the provisioned wire/crypto stack BEFORE SimulationApp adds extension
# bundles to sys.path. The accepted S6 integrated fixture uses this same order.
# A late import can select Kit's older cbor2, which cannot implement the strict
# decoder contract (allow_indefinite/allow_duplicate_keys). Do not reload or
# patch that decoder, drop its options, or relax the protocol to accommodate it.
import cbor2
from protected_robot_controller import limits as L
from protected_robot_controller.controller import Controller
from protected_robot_controller.interface import ControllerInterface, MAX_RESPONSE_BYTES
from protected_robot_controller.protocol import encode, strict_decode, public_bytes
from tools.controller_fixture import development_keys, command_for, sign_command, authenticated_evidence
from tools.integrated_fixture import _compare_observations
from tools.scene_calibration_check import CalibrationChecker, assess_objects, in_destination

_WIRE_PACKAGES = {name: package_version(name) for name in ("cbor2", "pycose", "cryptography")}

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "scenes/manipulation/profile.json"
TRAJECTORY_PATH = ROOT / "scenes/manipulation/trajectories.json"
OUTPUT = ROOT / "artifacts/scene-work"
FINGER_ROOT = "/B601/Geometry/base_link/link1/link2/link3/link4/link5/link6/gripper_end"
FINGERS = [FINGER_ROOT + "/gripper_left", FINGER_ROOT + "/gripper_right"]
REPRODUCTION = "<Isaac Sim python.sh> -m tools.scene_fixture"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def read_configuration():
    profile = json.loads(PROFILE_PATH.read_text())
    program = json.loads(TRAJECTORY_PATH.read_text())
    if program["profile_id"] != profile["id"] or program["sample_hz"] != 120:
        raise ValueError("Wrong scene/trajectory association or sample rate")
    if digest(ROOT / profile["model"]["manifest"]) != profile["model"]["sha256"]:
        raise ValueError("Pinned S6 model manifest changed")
    return profile, program


def protocol_runtime():
    """Fail closed on dependency shadowing before constructing the scene.

    This checks parsing capability only, never execution or physics. Retain the
    selected module and import-time distribution versions for external diagnosis.
    No replacement decoder or fallback dependencies are installed by this tool.
    """
    if _WIRE_PACKAGES["cbor2"] != "6.1.5":
        raise RuntimeError(f"Provisioned cbor2 6.1.5 required; loaded {_WIRE_PACKAGES['cbor2']}")
    probe = {"version": 1, "type": "HELLO"}
    try:
        decoded = strict_decode(encode(probe), MAX_RESPONSE_BYTES)
    except Exception as error:
        raise RuntimeError(
            f"Strict wire decoder unavailable at {cbor2.__file__}; import tools.scene_fixture "
            "before starting SimulationApp in the pinned container"
        ) from error
    if decoded != probe:
        raise RuntimeError("Strict wire decoder roundtrip disagrees")
    return {"packages_at_import": dict(_WIRE_PACKAGES), "cbor2_module": cbor2.__file__,
            "strict_decode_probe": "OK", "protocol_modified": False}


def expand_operation(program, operation):
    """Deterministic authored joint-space program; no simulator or feedback.

    Integer target rows are distinct from measurements. Retain inclusive
    1-based row boundaries for each recognizable phase in the reference file.
    """
    previous = list(program["initial_target"])
    rows, phases = [], []
    for phase in operation["phases"]:
        count, target = phase["steps"], phase["target"]
        if type(count) is not int or count <= 0 or len(target) != 7:
            raise ValueError("Malformed bounded phase")
        start = len(rows) + 1
        for step in range(1, count + 1):
            u = step / count
            alpha = u * u * (3 - 2 * u)
            row = [round(a + (b - a) * alpha) for a, b in zip(previous, target)]
            rows.append(row)
        phases.append({"name": phase["name"], "first_row": start, "last_row": len(rows)})
        previous = list(target)
    if len(rows) + program["hold_steps"] > L.MAX_DURATION_STEPS:
        raise ValueError("Program exceeds the unchanged controller duration")
    previous = program["initial_target"]
    for row in rows:
        if any(not lo <= q <= hi or abs(q - old) * L.HZ > speed
               for q, old, lo, hi, speed in zip(row, previous, L.LOWER, L.UPPER, L.VELOCITY)):
            raise ValueError("Program exceeds the unchanged controller position/slew bounds")
        previous = row
    phases.append({"name": "settle", "first_row": len(rows) + 1,
                   "last_row": len(rows) + program["hold_steps"]})
    return rows, phases


class ManipulationScene:
    """Trusted construction and independent read-only object observations."""

    def __init__(self, profile, *, camera=False, empty_grasp=False):
        self.profile, self.camera_enabled, self.empty_grasp = profile, camera, empty_grasp
        self.presentation = json.loads((ROOT / "scenes/manipulation/presentation.json").read_text())
        self.views = {}
        self.setup_calls = 0

    def build(self, world, stage):
        from isaacsim.core.prims import RigidPrim
        from pxr import Gf, PhysxSchema, UsdGeom, UsdPhysics, UsdShade

        if self.setup_calls:
            raise RuntimeError("Scene construction is permitted once per independent run")
        self.setup_calls += 1
        self.world, self.stage = world, stage
        p = self.profile
        physics = world.get_physics_context()
        physics.set_solver_type(p["physics"]["solver"])
        physics.set_gravity(p["physics"]["gravity_m_s2"])
        UsdGeom.Xform.Define(stage, "/Manipulation")

        def material(name, values):
            mat = UsdShade.Material.Define(stage, "/Manipulation/Materials/" + name)
            api = UsdPhysics.MaterialAPI.Apply(mat.GetPrim())
            api.CreateStaticFrictionAttr(values["static_friction"])
            api.CreateDynamicFrictionAttr(values["dynamic_friction"])
            api.CreateRestitutionAttr(values["restitution"])
            return mat

        grasp_mat = material("Grasp", p["physics"]["grasp_material"])
        table_mat = material("Table", p["physics"]["table_material"])

        def bind(prim, mat):
            UsdShade.MaterialBindingAPI.Apply(prim).Bind(
                mat, bindingStrength=UsdShade.Tokens.strongerThanDescendants,
                materialPurpose="physics")

        def cube(path, center, dimensions, color, *, collision=False, orientation=None):
            geom = UsdGeom.Cube.Define(stage, path)
            geom.CreateSizeAttr(1.0)
            geom.AddTranslateOp().Set(Gf.Vec3d(*center))
            if orientation is not None:
                geom.AddOrientOp().Set(Gf.Quatf(orientation[0], Gf.Vec3f(*orientation[1:])))
            geom.AddScaleOp().Set(Gf.Vec3f(*dimensions))
            geom.CreateDisplayColorAttr([Gf.Vec3f(*color)])
            if collision:
                UsdPhysics.CollisionAPI.Apply(geom.GetPrim())
                contact = PhysxSchema.PhysxCollisionAPI.Apply(geom.GetPrim())
                contact.CreateContactOffsetAttr(p["physics"]["object_contact_offset_m"])
                contact.CreateRestOffsetAttr(p["physics"]["object_rest_offset_m"])
            return geom.GetPrim()

        surface = p["work_surface"]
        table = cube(surface["prim"], surface["center_m"], surface["dimensions_m"],
                     [.32, .34, .36], collision=True)
        bind(table, table_mat)
        # Flat paint only: no collision APIs or rigid bodies on markings/labels.
        colors = {"R1": [.65, .015, .01], "B1": [.01, .08, .65]}
        half = self.presentation["start_square_half_extent_m"]
        squares = [(obj["id"], {"center_xy_m": obj["position_m"][:2],
                    "half_extents_xy_m": [half, half]}, colors[obj["id"]])
                   for obj in p["objects"]]
        squares += [("A", p["regions"]["A"], colors["R1"]),
                    ("B", p["regions"]["B"], colors["B1"])]
        width = self.presentation["outline_width_m"]
        for name, region, color in squares:
            cx, cy = region["center_xy_m"]
            hx, hy = region["half_extents_xy_m"]
            for suffix, xy, size in (
                ("left", [cx-hx, cy], [width, 2*hy, .0002]),
                ("right", [cx+hx, cy], [width, 2*hy, .0002]),
                ("near", [cx, cy-hy], [2*hx, width, .0002]),
                ("far", [cx, cy+hy], [2*hx, width, .0002]),
            ):
                cube(f"/Manipulation/Regions/{name}/{suffix}",
                     xy + [surface["top_z_m"]+.0003], size, color)
            self._paint_label(name, cx+hx+.028, cy, surface["top_z_m"]+.0005, color)
        for path in FINGERS:
            bind(stage.GetPrimAtPath(path), grasp_mat)
        for obj in p["objects"]:
            position = obj["position_m"]
            if self.empty_grasp and obj["id"] == p["empty_grasp_setup"]["object_id"]:
                position = p["empty_grasp_setup"]["position_m"]
            body = cube(obj["prim"], position, obj["dimensions_m"], obj["color_rgb"],
                        collision=True, orientation=obj["orientation_wxyz"])
            body.SetCustomDataByKey("scene_object_id", obj["id"])
            UsdPhysics.RigidBodyAPI.Apply(body)
            UsdPhysics.MassAPI.Apply(body).CreateMassAttr(obj["mass_kg"])
            physx = PhysxSchema.PhysxRigidBodyAPI.Apply(body)
            physx.CreateSolverPositionIterationCountAttr(p["physics"]["object_solver_position_iterations"])
            physx.CreateSolverVelocityIterationCountAttr(p["physics"]["object_solver_velocity_iterations"])
            physx.CreateSleepThresholdAttr(p["physics"]["object_sleep_threshold"])
            physx.CreateLinearDampingAttr(p["physics"]["object_linear_damping"])
            physx.CreateAngularDampingAttr(p["physics"]["object_angular_damping"])
            bind(body, grasp_mat)
            # Each view has one known object and two separate finger filters.
            view = RigidPrim(prim_paths_expr=obj["prim"], name="scene_" + obj["id"],
                             reset_xform_properties=False,
                             contact_filter_prim_paths_expr=FINGERS,
                             max_contact_count=64, disable_stablization=False)
            world.scene.add(view)
            self.views[obj["id"]] = view
        if self.camera_enabled:
            self._build_camera()

    def _paint_label(self, text, x, y, z, color):
        """Small planar stroke glyphs; labels are geometry with no physics."""
        from pxr import Gf, UsdGeom
        glyphs = {
            "A": [[(0, 0), (.5, 1), (1, 0)], [(.25, .5), (.75, .5)]],
            "B": [[(0, 0), (0, 1), (.7, 1), (1, .75), (.7, .5), (0, .5)],
                  [(.7, .5), (1, .25), (.7, 0), (0, 0)]],
            "R": [[(0, 0), (0, 1), (.7, 1), (1, .75), (.7, .5), (0, .5)],
                  [(.55, .5), (1, 0)]],
            "1": [[(.2, .75), (.5, 1), (.5, 0)], [(.15, 0), (.85, 0)]],
        }
        points, counts, indices = [], [], []
        for i, char in enumerate(text):
            for stroke in glyphs[char]:
                for a, b in zip(stroke, stroke[1:]):
                    # Text reads along +Y, with its top toward -X (toward the camera view).
                    ax, ay = x-a[1]*.014, y-len(text)*.006+(i*1.3+a[0])*.009
                    bx, by = x-b[1]*.014, y-len(text)*.006+(i*1.3+b[0])*.009
                    length = math.hypot(bx-ax, by-ay)
                    dx, dy = -(by-ay)*.0007/length, (bx-ax)*.0007/length
                    indices.extend(range(len(points), len(points)+4)); counts.append(4)
                    points.extend([(ax+dx, ay+dy, z), (ax-dx, ay-dy, z),
                                   (bx-dx, by-dy, z), (bx+dx, by+dy, z)])
        mesh = UsdGeom.Mesh.Define(self.stage, "/Manipulation/Labels/" + text)
        mesh.CreatePointsAttr([Gf.Vec3f(*point) for point in points])
        mesh.CreateFaceVertexCountsAttr(counts)
        mesh.CreateFaceVertexIndicesAttr(indices)
        mesh.CreateSubdivisionSchemeAttr("none")
        mesh.CreateDoubleSidedAttr(True)
        mesh.CreateDisplayColorAttr([Gf.Vec3f(*color)])

    def _build_camera(self):
        from pxr import Gf, UsdGeom, UsdLux
        c = {**self.profile["camera"], **self.presentation["camera"]}
        camera = UsdGeom.Camera.Define(self.stage, c["prim"])
        camera.CreateFocalLengthAttr(c["focal_length_mm"])
        camera.CreateHorizontalApertureAttr(c["horizontal_aperture_mm"])
        camera.CreateVerticalApertureAttr(c["vertical_aperture_mm"])
        camera.CreateClippingRangeAttr(Gf.Vec2f(*c["clipping_m"]))
        view = Gf.Matrix4d().SetLookAt(Gf.Vec3d(*c["eye_m"]), Gf.Vec3d(*c["target_m"]), Gf.Vec3d(*c["up"]))
        UsdGeom.Xformable(camera).AddTransformOp().Set(view.GetInverse())
        UsdLux.DomeLight.Define(self.stage, "/Manipulation/Fill").CreateIntensityAttr(1000)
        light = UsdLux.DistantLight.Define(self.stage, "/Manipulation/Key")
        light.CreateIntensityAttr(2000)
        UsdGeom.Xformable(light).AddRotateXYZOp().Set(Gf.Vec3f(-35, 25, 35))

    def observe(self):
        import numpy as np
        result = {"physics_step": int(self.world.current_time_step_index),
                  "simulation_time_ns": round(float(self.world.current_time) * 1e9), "objects": {}}
        for oid, view in self.views.items():
            if not view.is_physics_handle_valid():
                raise RuntimeError("Object physics handle missing")
            positions, rotations = view.get_world_poses(clone=True)
            position = np.array(positions, dtype=float, copy=True).reshape(1, 3)[0]
            rotation = np.array(rotations, dtype=float, copy=True).reshape(1, 4)[0]
            velocities = np.array(view.get_velocities(clone=True), dtype=float, copy=True).reshape(1, 6)[0]
            forces = np.array(view.get_contact_force_matrix(clone=True, dt=1/120), dtype=float, copy=True).reshape(1, 2, 3)[0]
            if not all(np.isfinite(v).all() for v in (position, rotation, velocities, forces)):
                raise RuntimeError("Nonfinite object/contact observation")
            result["objects"][oid] = {"position": position.tolist(), "orientation_wxyz": rotation.tolist(),
                                      "linear_velocity": velocities[:3].tolist(),
                                      "angular_velocity": velocities[3:].tolist(),
                                      "finger_forces_n": forces.tolist()}
        return result

    def describe(self, backend):
        from pxr import Usd, UsdGeom, UsdPhysics
        stage = self.stage
        prims = list(Usd.PrimRange.Stage(stage, Usd.TraverseInstanceProxies()))
        robot_bodies = [str(p.GetPath()) for p in prims
                        if str(p.GetPath()).startswith("/B601/") and p.HasAPI(UsdPhysics.RigidBodyAPI)]
        joints = [str(p.GetPath()) for p in prims if p.IsA(UsdPhysics.Joint)]
        table = stage.GetPrimAtPath(self.profile["work_surface"]["prim"])
        props = backend._robot.dof_properties
        return {"robot_bodies": robot_bodies, "joints": joints,
                "table_fixed": table.HasAPI(UsdPhysics.CollisionAPI) and not table.HasAPI(UsdPhysics.RigidBodyAPI),
                "table_dimensions_m": list(UsdGeom.Xformable(table).GetOrderedXformOps()[-1].Get()),
                "output_order": backend._manifest["output_order"],
                "runtime_output_names": list(backend._robot.dof_names), "output_indices": backend._indices,
                "effort_caps": [float(props["maxEffort"][i]) for i in backend._indices],
                "velocity_caps": [float(props["maxVelocity"][i]) for i in backend._indices],
                "physics_dt_seconds": float(self.world.get_physics_dt()),
                "solver": self.world.get_physics_context().get_solver_type(),
                "gravity": self.world.get_physics_context().get_gravity(),
                "object_ids": sorted(self.views),
                "object_dimensions_m": {o["id"]: list(UsdGeom.Xformable(stage.GetPrimAtPath(o["prim"])).GetOrderedXformOps()[-1].Get()) for o in self.profile["objects"]},
                "object_mass_kg": {o["id"]: float(UsdPhysics.MassAPI(stage.GetPrimAtPath(o["prim"])).GetMassAttr().Get()) for o in self.profile["objects"]},
                "camera_present": bool(stage.GetPrimAtPath(self.profile["camera"]["prim"])),
                "setup_calls": self.setup_calls, "initial_objects": self.observe()}


@contextmanager
def execution_guard(backend, scene):
    """Fail on high-level and tensor state assignment throughout BOTH operations."""
    forbidden_calls = []
    def forbid(*args, **kwargs):
        forbidden_calls.append("state assignment, reset or external force")
        raise AssertionError("State assignment/reset/external force during measured scene execution")
    robot = backend._robot
    guarded = [
        (robot, ("set_joint_positions", "set_joint_velocities", "set_world_pose", "post_reset")),
        (robot._articulation_view, ("set_joint_positions", "set_joint_velocities", "set_world_poses")),
        (robot._articulation_view._physics_view, ("set_dof_positions", "set_dof_velocities", "set_root_transforms", "set_root_velocities", "set_dof_actuation_forces")),
        (backend._world, ("reset", "reset_async")),
    ]
    for view in scene.views.values():
        guarded.extend([
            (view, ("set_world_poses", "set_local_poses", "set_velocities", "set_linear_velocities", "set_angular_velocities", "post_reset", "apply_forces", "apply_forces_and_torques_at_pos")),
            (view._physics_view, ("set_transforms", "set_velocities", "apply_forces", "apply_forces_and_torques_at_position", "set_kinematic_targets")),
        ])
    names = []
    with ExitStack() as stack:
        for obj, methods in guarded:
            for name in methods:
                if hasattr(obj, name):
                    stack.enter_context(patch.object(obj, name, forbid))
                    names.append(type(obj).__name__ + "." + name)
        yield {"guarded_methods": names, "forbidden_calls": forbidden_calls,
               "covers": "entire measured interval including both operations and their boundary"}


class _ObservedBackend:
    """Test observer around the SAME S6 private backend; returns unchanged samples."""
    def __init__(self, backend, scene):
        self.backend, self.scene = backend, scene
        self.joints, self.objects = [], []
        self.drive_writes = 0

    def _observe(self, sample):
        import numpy as np
        raw = np.array(self.backend._robot.get_joint_positions(), dtype=float, copy=True)
        positions = [float(raw[i]) for i in self.backend._indices]
        observation = {"counter": sample.counter, "physics_step": int(self.backend._world.current_time_step_index),
                       "simulation_time_ns": round(float(self.backend._world.current_time) * 1e9),
                       "monotonic_time_ns": sample.monotonic_time_ns,
                       "positions": positions, "valid": list(sample.valid)}
        self.joints.append(observation)
        self.objects.append(self.scene.observe())
        if (tuple(positions) != sample.positions or observation["physics_step"] != sample.physics_step
                or observation["simulation_time_ns"] != sample.simulation_time_ns):
            raise RuntimeError("Independent post-physics joint acquisition disagrees")
        return sample

    def read_initial(self):
        return self._observe(self.backend.read_initial())

    def sample_outputs(self):
        return self._observe(self.backend.sample_outputs())

    def drive(self, targets, **kwargs):
        self.backend.drive(targets, **kwargs)
        self.drive_writes += 1

    def step_physics(self, **kwargs):
        self.backend.step_physics(**kwargs)

    def stop_or_hold(self, reason):
        self.backend.stop_or_hold(reason)


class RunStore:
    def __init__(self, profile, scenario, camera, *, signed=False):
        self.signed = signed
        self.run_id = scenario + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:12]
        self.directory = OUTPUT / ("signed" if signed else "calibration") / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)
        from tools.runtime_provenance import current_runtime
        runtime_identity = current_runtime()
        self.record = {"schema_version": 1, "run_id": self.run_id, "scenario": scenario,
                       "stage": "S6-02" if signed else "S6-01", "kind": "CALIBRATION_NOT_CAMPAIGN", "status": "STARTED",
                       "profile_sha256": digest(PROFILE_PATH), "trajectory_sha256": digest(TRAJECTORY_PATH),
                       "source_fingerprint": os.environ.get("PRC_SCENE_SOURCE_FINGERPRINT"),
                       "runtime_image": runtime_identity["image_id"], "runtime_identity": runtime_identity,
                       "model_sha256": profile["model"]["sha256"],
                       "seed": profile["seed"], "started_at_utc": utc_now(),
                       "camera_enabled": camera, "operations": [], "persistence_observed": False,
                       "reproduction_command": REPRODUCTION + " --scenario " + scenario + (" --camera" if camera else "") + (" --signed" if signed else ""),
                       "scope": "Trusted-host Isaac simulation; unsigned object observations; no physical attestation",
                       "reasons": ["Real physics execution has not yet completed"]}
        write_json(self.directory / "start.json", self.record)
        self.publish("start.json")

    def publish(self, filename):
        # Keep every unique run, including startup failures and unsuccessful
        # calibration. Replacing this index never replaces any earlier run file.
        path = OUTPUT / ("signed.json" if self.signed else "normal.json")
        summary = json.loads(path.read_text()) if path.exists() else {"runs": []}
        summary.update(schema_version=1, stage=self.record["stage"], acceptance="EXTERNAL_SUPERVISOR_ONLY",
                       status="CALIBRATION_OBSERVATIONS", campaign_frozen=False,
                       reasons=["Run entries retain actual observations and failures with immutable per-run files; this index is not gate acceptance"],
                       current_profile_sha256=self.record["profile_sha256"],
                       current_trajectory_sha256=self.record["trajectory_sha256"])
        entry = {"run_id": self.run_id, "scenario": self.record["scenario"],
                 "manifest": str((self.directory / filename).relative_to(ROOT)),
                 "sha256": digest(self.directory / filename), "status": self.record["status"],
                 "reasons": self.record["reasons"]}
        summary["runs"] = [r for r in summary.get("runs", []) if r["run_id"] != self.run_id] + [entry]
        write_json(path, summary)

    def finish(self):
        self.record["completed_at_utc"] = utc_now()
        self.record["files"] = {str(p.relative_to(ROOT)): digest(p)
                                for p in sorted(self.directory.rglob("*")) if p.is_file() and p.name != "run.json"}
        write_json(self.directory / "run.json", self.record)
        self.publish("run.json")


def contact_diagnostics(rows, object_id, phases, profile):
    """Observe forces AND actual lift/transport; no requested-state shortcut."""
    policy = profile["candidate_policy"]
    initial = rows[0]["objects"][object_id]["position"]
    phase_by_name = {p["name"]: p for p in phases}
    counts, airborne = {}, {}
    lifts, distances = [], []
    for i, row in enumerate(rows):
        state = row["objects"][object_id]
        p = state["position"]
        rise = p[2] - initial[2]
        distance = math.hypot(p[0]-initial[0], p[1]-initial[1])
        lifts.append(rise)
        distances.append(distance)
        two_finger_contact = all(math.sqrt(sum(x*x for x in f)) > policy["contact_observation_min_n"]
                                 for f in state["finger_forces_n"])
        for name, phase in phase_by_name.items():
            if phase["first_row"] <= i <= phase["last_row"] and two_finger_contact:
                counts[name] = counts.get(name, 0) + 1
                if rise >= policy["minimum_lift_m"]:
                    airborne[name] = airborne.get(name, 0) + 1
    return {"two_finger_contact_steps": counts, "airborne_two_finger_contact_steps": airborne,
            "maximum_lift_m": max(lifts), "maximum_xy_displacement_m": max(distances),
            "initial_position_m": initial, "final_position_m": rows[-1]["objects"][object_id]["position"],
            "method": "Copied PhysX rigid-body transforms and per-object/per-finger contact forces after each step"}


def contact_requirements_met(diagnostics, profile):
    """Grasp and airborne transport must accompany a normal placement label."""
    policy = profile["candidate_policy"]
    return bool(diagnostics) and (
        diagnostics["two_finger_contact_steps"].get("grasp_hold", 0) >= policy["minimum_contact_steps"]
        and diagnostics["airborne_two_finger_contact_steps"].get("transport", 0) >= policy["minimum_airborne_contact_steps"]
        and diagnostics["maximum_lift_m"] >= policy["minimum_lift_m"]
        and diagnostics["maximum_xy_displacement_m"] >= policy["minimum_transport_m"])


def run_calibration(*, scenario="normal", camera=False, keys=None, signed=False):
    """One independent scene. No reset, retry or feedback planning within a run."""
    if scenario not in ("normal", "empty_grasp"):
        raise ValueError("S6-01 implements only normal calibration and its empty-grasp feasibility probe")
    if signed and scenario != "normal":
        raise ValueError("S6-02 covers the persistent normal sequence only")
    profile, program = read_configuration()
    store = RunStore(profile, scenario, camera, signed=signed)
    backend = None
    observed = None
    object_rows = []
    error = None
    try:
        store.record["protocol_runtime"] = protocol_runtime()
        write_json(store.directory / "protocol_runtime.json", store.record["protocol_runtime"])
        from isaacsim.core.version import get_version
        from protected_robot_controller.simulation._backend import _IsaacRobotBackend

        version = list(get_version())
        if version[0].split("-")[0].split("+")[0] != "6.0.0":
            raise RuntimeError(f"Pinned Isaac 6.0.0 required; observed {version}")
        store.record["isaac_version"] = version
        scene = ManipulationScene(profile, camera=camera, empty_grasp=scenario == "empty_grasp")
        backend = _IsaacRobotBackend(setup_scene=scene.build)
        store.record["geometry"] = scene.describe(backend)
        write_json(store.directory / "geometry.json", store.record["geometry"])
        backend._stage.GetRootLayer().Export(str(store.directory / "scene.usda"))
        authority, evidence_key = development_keys() if keys is None else keys
        observed = _ObservedBackend(backend, scene)
        interface = ControllerInterface(Controller(authority.public_key(), evidence_key, observed))
        checker = CalibrationChecker(authority.public_key(), evidence_key.public_key(), profile["candidate_policy"]["tracking_tolerance"])
        if signed:
            from tools.scene_evidence import prepare_run, segment_binding, complete_segment, authorization_probes
            prepare_run(store, program, authority.public_key(), evidence_key.public_key())
        fault = ({"kind": "NONE"} if scenario == "normal" else
                 {"kind": "OBJECT_RELOCATED_BEFORE_RUN", **profile["empty_grasp_setup"]})
        write_json(store.directory / "fault_parameters.json", fault)
        store.record["fault_parameters"] = str((store.directory / "fault_parameters.json").relative_to(ROOT))
        object_rows.append(scene.observe())
        with execution_guard(backend, scene) as guard:
            store.record["execution_guard"] = guard
            if signed:
                authorization_probes(store, interface, observed, authority, program)
            operations = program["operations"] if scenario == "normal" else program["operations"][:1]
            for index, operation in enumerate(operations):
                name = f"{index+1:02d}-{operation['object_id']}-{operation['destination']}"
                reference, phases = expand_operation(program, operation)
                write_json(store.directory / (name + ".reference.json"),
                           {"trajectory": reference, "phases": phases, "hold_steps": program["hold_steps"],
                            "initial_target": program["initial_target"]})
                hello_request = encode({"version": 1, "type": "HELLO"})
                hello_raw = interface.handle(hello_request)
                (store.directory / (name + ".hello.cbor")).write_bytes(hello_raw)
                hello = strict_decode(hello_raw, MAX_RESPONSE_BYTES)
                initial = program["initial_target"] + [program["initial_target"][-1]]
                command = command_for(hello, initial, reference, hold_steps=program["hold_steps"])
                command["initial_tolerance"] = program["initial_tolerance"]
                command["authorization_context_digest"] = sha256(encode({
                    "profile_sha256": store.record["profile_sha256"],
                    "trajectory_sha256": store.record["trajectory_sha256"],
                    "operation_index": index, "object_id": operation["object_id"], "destination": operation["destination"],
                })).digest()
                if signed:
                    command["authorization_context_digest"] = sha256(encode(segment_binding(store.record, index))).digest()
                wire = sign_command(command, authority)
                request = encode({"version": 1, "type": "EXECUTE", "command": wire})
                for suffix, raw in (("command.cbor", wire), ("request.cbor", request)):
                    (store.directory / (name + "." + suffix)).write_bytes(raw)
                context = {"authority_public_der_hex": public_bytes(authority.public_key()).hex(),
                           "evidence_public_der_hex": public_bytes(evidence_key.public_key()).hex(),
                           "config_cbor_hex": encode(L.configuration()).hex(),
                           "profile_sha256": store.record["profile_sha256"],
                           "trajectory_sha256": store.record["trajectory_sha256"],
                           "command_sha256": sha256(wire).hexdigest(),
                           "candidate_tolerance": profile["candidate_policy"]["tracking_tolerance"],
                           "phases": phases}
                if signed:
                    context["binding"] = segment_binding(store.record, index)
                write_json(store.directory / (name + ".public.json"), context)
                joint_start, object_start = len(observed.joints), len(observed.objects)
                started = time.perf_counter()
                response_raw = interface.handle(request)
                execution_seconds = time.perf_counter() - started
                (store.directory / (name + ".response.cbor")).write_bytes(response_raw)
                response = strict_decode(response_raw, MAX_RESPONSE_BYTES)
                joint_trace = observed.joints[joint_start:]
                objects = observed.objects[object_start:]
                # Keep originals before ANY evidence, motion or object assertion.
                write_json(store.directory / (name + ".joints.json"), joint_trace)
                write_json(store.directory / (name + ".objects.json"), objects)
                object_rows.extend(r for r in objects if r["physics_step"] > object_rows[-1]["physics_step"])
                if response.get("type") != "EVIDENCE":
                    raise RuntimeError(f"Signed command did not produce evidence: {response}")
                bundle = response["evidence"]
                (store.directory / (name + ".report.cbor")).write_bytes(bundle)
                checking_started = time.perf_counter()
                evidence = authenticated_evidence(bundle, evidence_key.public_key())
                segment = {"boot_id": command["boot_id"].hex(), "execution_id": command["execution_id"].hex(),
                           "sequence": command["sequence"], "command_bytes": len(wire), "report_bytes": len(bundle),
                           "execution_seconds": execution_seconds, "checking_seconds": 0.0,
                           "phases": phases, "reference_trajectory_sha256": sha256(encode(reference)).hexdigest(),
                           "physics_step_first": objects[0]["physics_step"] if objects else None,
                           "physics_step_last": objects[-1]["physics_step"] if objects else None,
                           **{field: str((store.directory / (name + "." + suffix)).relative_to(ROOT))
                              for field, suffix in (("command", "command.cbor"), ("report", "report.cbor"),
                                                    ("public_context", "public.json"), ("object_observations", "objects.json"),
                                                    ("joint_observations", "joints.json"), ("reference", "reference.json"))}}
                if signed:
                    complete_segment(store, index, name, segment, context, wire, bundle, command, evidence)
                result = checker.assess_segment(wire, bundle)
                _compare_observations(evidence, joint_trace)
                object_result = assess_objects(objects, operation["object_id"], operation["destination"], profile)
                diagnostic = contact_diagnostics(objects, operation["object_id"], phases, profile) if objects else None
                contact_met = contact_requirements_met(diagnostic, profile)
                segment["checking_seconds"] = time.perf_counter() - checking_started
                if signed:
                    write_json(store.directory / (name + ".segment.json"), segment)
                op = {"object_id": operation["object_id"], "destination": operation["destination"],
                      "evidence_validation": result["evidence_validation"], "motion_verdict": result["motion_verdict"],
                      "object_verdict": object_result["object_verdict"], "reasons": result["reasons"] + object_result["reasons"],
                      "motion_diagnostics": result, "object_diagnostics": object_result,
                      "contact_diagnostics": diagnostic, "segments": [segment]}
                op["contact_requirements_met"] = contact_met
                if not contact_met:
                    op["reasons"].append("Actual contact/lift/airborne transport did not satisfy the normal grasp predicate")
                store.record["operations"].append(op)
                write_json(store.directory / (name + ".assessment.json"), op)
                if index == 1:
                    persisted = bool(objects) and all(in_destination(r, "R1", "A", profile) for r in objects)
                    store.record["persistence_observed"] = persisted
                    store.record["persistence_samples"] = len(objects)
                if result["evidence_validation"] != "VALID" or evidence["terminal_state"] != "COMPLETE":
                    raise RuntimeError("Invalid/partial operation retained; controller cannot safely continue")
                if signed:
                    authorization_probes(store, interface, observed, authority, program, accepted=wire)
            store.record["geometry_after"] = scene.describe(backend)
            store.record["physics_steps_measured"] = backend._steps
            store.record["requested_drive_writes"] = observed.drive_writes
        outcomes = store.record["operations"]
        normal_ok = (len(outcomes) == 2 and store.record["persistence_observed"]
                     and all(o["evidence_validation"] == "VALID" and o["motion_verdict"] == "CONFORMANT"
                             and o["object_verdict"] == "DELIVERED" and o["contact_requirements_met"] for o in outcomes))
        if scenario == "empty_grasp":
            feasible = (len(outcomes) == 1 and outcomes[0]["evidence_validation"] == "VALID"
                        and outcomes[0]["motion_verdict"] == "CONFORMANT"
                        and outcomes[0]["object_verdict"] == "NOT_DELIVERED")
            store.record["empty_grasp_feasible_under_candidate_policy"] = feasible
            store.record["status"] = "OBSERVED_FEASIBLE" if feasible else "OBSERVED_INFEASIBLE"
            store.record["reasons"] = ["Same authored R1 trajectory; candidate predicate evaluated on actual empty-grasp observations",
                                       "Policy and controller bounds were not changed"]
        else:
            store.record["status"] = "OBSERVED_NORMAL" if normal_ok else "CALIBRATION_FAILED"
            store.record["reasons"] = ["Two contact grasps, airborne placements and persistence observed" if normal_ok else
                                       "Calibration did not establish both conformant contact placements with persistence; retain diagnostics"]
    except BaseException as exc:
        error = exc
        store.record["status"] = "EXECUTION_FAILED"
        store.record["reasons"] = [repr(exc)]
        write_json(store.directory / "error.json", {"traceback": traceback.format_exc()})
    finally:
        if observed is not None:
            # Also survives an exception while issuing a command: retain every
            # copied sample, including an unsigned trailing acquisition if any.
            write_json(store.directory / "all_joint_observations.json", observed.joints)
            write_json(store.directory / "all_object_observations.json", observed.objects)
        write_json(store.directory / "object_observations.json", object_rows)
        store.record["object_observations"] = str((store.directory / "object_observations.json").relative_to(ROOT))
        if backend is not None:
            try:
                backend.close()
            except BaseException as exc:
                store.record["cleanup_error"] = repr(exc)
                store.record["status"] = "EXECUTION_FAILED"
                error = error or exc
        store.finish()
    if error is not None:
        raise RuntimeError(f"Calibration failed; retained at {store.directory / 'run.json'}") from error
    return store.record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("normal", "empty_grasp"), default="normal")
    parser.add_argument("--camera", action="store_true", help="Author the full-scene observation camera; physics remains headless")
    parser.add_argument("--signed", action="store_true", help="Retain S6-02 coverage context and exercise byte-interface refusals")
    args = parser.parse_args()
    # Kit must not see fixture arguments, and no older native runtime is substituted.
    argv = sys.argv
    sys.argv = [argv[0]]
    from isaacsim import SimulationApp
    app = SimulationApp({"headless": True, "fast_shutdown": True, "multi_gpu": False,
                         "disable_viewport_updates": True, "width": 1200, "height": 900,
                         "enable_crashreporter": False})
    sys.argv = argv
    code = 1
    try:
        record = run_calibration(scenario=args.scenario, camera=args.camera, signed=args.signed)
        print(json.dumps(record, indent=2), flush=True)
        code = 0 if record["status"] in ("OBSERVED_NORMAL", "OBSERVED_FEASIBLE") else 1
    except BaseException:
        traceback.print_exc()
    finally:
        app.close(wait_for_replicator=False, skip_cleanup=False, exit_code=code)


if __name__ == "__main__":
    main()
