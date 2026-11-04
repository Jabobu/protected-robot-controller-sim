"""Pinned B601 asset setup. Import Isaac APIs only after SimulationApp starts.

This module owns model loading, not a transport, controller, or motion policy.
The on-disk overlay is immutable at runtime; no upstream application is imported.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..limits import MODEL_MANIFEST_SHA256

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "artifacts/model_manifest.json"


def read_manifest() -> dict:
    if any(part.is_symlink() for part in (MANIFEST_PATH, *MANIFEST_PATH.parents)):
        raise ValueError("Model manifest path must not contain symlinks")
    raw = MANIFEST_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != MODEL_MANIFEST_SHA256:
        raise ValueError("Model manifest differs from controller configuration")
    return json.loads(raw)


def verify_files(manifest: dict) -> None:
    """Fail closed on absent, changed, or unfetched LFS payloads, offline."""
    trusted = read_manifest()
    if json.dumps(manifest, sort_keys=True, allow_nan=False) != json.dumps(trusted, sort_keys=True, allow_nan=False):
        raise ValueError("Model manifest argument differs from pinned manifest")
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if not path.is_relative_to(ROOT) or any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError(f"Asset path is not an ordinary local path: {path}")
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(ROOT) or resolved != path or not path.is_file():
            raise ValueError(f"Asset escapes workspace or is not a file: {path}")
        data = path.read_bytes()
        if len(data) != entry["size_bytes"]:
            raise ValueError(f"Asset size mismatch: {entry['path']}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Asset hash mismatch: {entry['path']}")


def verify_closure(manifest: dict) -> tuple[str, list[str]]:
    """Verify all pinned assets and the exact local USD dependency closure."""
    from pxr import UsdUtils

    verify_files(manifest)
    asset = str(ROOT / manifest["entrypoint"])
    layers, assets, unresolved = UsdUtils.ComputeAllDependencies(asset)
    if unresolved or assets:
        raise ValueError(f"Unexpected dependencies: assets={assets}, missing={unresolved}")
    actual_layers = []
    for layer in layers:
        path = Path(layer.realPath)
        if (not path.is_absolute() or not path.is_relative_to(ROOT)
                or any(part.is_symlink() for part in (path, *path.parents))
                or path.resolve(strict=True) != path):
            raise ValueError("USD dependency is not a canonical local file")
        actual_layers.append(str(path.relative_to(ROOT)))
    actual_layers.sort()
    if actual_layers != manifest["dependency_closure"]["layers"]:
        raise ValueError(f"Dependency closure changed: {actual_layers}")
    return asset, actual_layers


def inspect_asset(manifest: dict) -> tuple:
    """Compose pinned local layers and enumerate geometry; not a physics test."""
    from pxr import Usd, UsdGeom, UsdPhysics

    asset, actual_layers = verify_closure(manifest)
    stage = Usd.Stage.Open(asset, load=Usd.Stage.LoadAll)
    errors = [str(e) for p in stage.Traverse() for e in p.GetPrimIndex().localErrors]
    if errors:
        raise ValueError(f"USD composition failed: {errors}")
    prims = list(Usd.PrimRange.Stage(stage, Usd.TraverseInstanceProxies()))
    report = {
        "kind": "STATIC_USD_COMPOSITION_NOT_PHYSICS",
        "usd_version": list(Usd.GetVersion()),
        "manifest_sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        "layers": actual_layers,
        "unresolved": [],
        "composition_errors": errors,
        "rigid_bodies": [str(p.GetPath()) for p in prims if p.HasAPI(UsdPhysics.RigidBodyAPI)],
        "meshes": [str(p.GetPath()) for p in prims if p.IsA(UsdGeom.Mesh)],
        "colliders": [str(p.GetPath()) for p in prims if p.HasAPI(UsdPhysics.CollisionAPI)],
        "channels": [],
    }
    for channel in manifest["channels"]:
        prim = stage.GetPrimAtPath(channel["joint_path"])
        angular = channel["unit"] == "rad"
        joint = UsdPhysics.RevoluteJoint(prim) if angular else UsdPhysics.PrismaticJoint(prim)
        drive = UsdPhysics.DriveAPI.Get(prim, "angular" if angular else "linear")
        report["channels"].append({
            "name": prim.GetName(), "type": prim.GetTypeName(),
            "axis": joint.GetAxisAttr().Get(),
            "usd_limits": [joint.GetLowerLimitAttr().Get(), joint.GetUpperLimitAttr().Get()],
            "usd_max_velocity": prim.GetAttribute("physxJoint:maxJointVelocity").Get(),
            "max_effort": drive.GetMaxForceAttr().Get(),
            "stiffness": drive.GetStiffnessAttr().Get(), "damping": drive.GetDampingAttr().Get(),
        })
    follower = stage.GetPrimAtPath("/B601/Physics/joint_right")
    prefix = "physxMimicJoint:rotX:"
    report["gripper_coupling"] = {
        # Read the composed listOp also when only OpenUSD is loaded (no PhysX
        # schema plugin). This detects a stale/extra invalid upstream instance.
        "schemas": [s for s in follower.GetMetadata("apiSchemas").GetAppliedItems()
                    if s.startswith("PhysxMimicJointAPI:")],
        "reference_joint": [str(p) for p in follower.GetRelationship(prefix + "referenceJoint").GetTargets()],
        "reference_axis": follower.GetAttribute(prefix + "referenceJointAxis").Get(),
        "gearing": follower.GetAttribute(prefix + "gearing").Get(),
        "offset": follower.GetAttribute(prefix + "offset").Get(),
    }
    return stage, report


def output_indices(articulation, manifest: dict) -> list[int]:
    """Resolve by name; never assume PhysX traversal order is the wire order."""
    names = list(articulation.dof_names)
    order = manifest["output_order"]
    if len(names) != len(order) or len(set(names)) != len(names) or set(names) != set(order):
        raise ValueError(f"Unexpected measured outputs: {names}; expected {order}")
    return [names.index(name) for name in order]


def load_model(manifest: dict, *, setup_scene=None):
    """Create one fixed-base CPU PhysX articulation in a small, offline scene."""
    from isaacsim.core.api import World
    from isaacsim.core.prims import SingleArticulation
    from isaacsim.core.utils.stage import add_reference_to_stage, get_current_stage

    # This is the actual runtime route, before constructing the simulator World.
    verify_closure(manifest)
    world = World(
        stage_units_in_meters=1.0,
        physics_dt=manifest["runtime"]["physics_dt_seconds"],
        rendering_dt=manifest["runtime"]["physics_dt_seconds"],
        backend="numpy",
        device="cpu",
    )
    try:
        add_reference_to_stage(str(ROOT / manifest["entrypoint"]), manifest["robot_prim"])
        stage = get_current_stage()
        stage.Load()
        robot = world.scene.add(SingleArticulation(
            prim_path=manifest["articulation_root"], name="b601_rs", reset_xform_properties=False,
        ))
        # Trusted construction only: fixture geometry must exist before the
        # single initialization reset. Never retained or exposed on the byte
        # interface. The default S6 scene is unchanged.
        if setup_scene is not None:
            setup_scene(world, stage)
        # reset is trusted initialization. No joint state assignment follows it.
        world.reset()
        indices = output_indices(robot, manifest)
        return world, robot, stage, indices
    except BaseException as error:
        # The caller does not own World until this function returns. Do not
        # strand its singleton if fixture construction or initialization fails.
        for cleanup in (world.stop, world.clear, world.clear_instance):
            try:
                cleanup()
            except BaseException as cleanup_error:
                error.add_note(f"Model setup cleanup failed: {cleanup_error!r}")
        raise
