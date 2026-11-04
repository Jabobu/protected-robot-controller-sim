"""S1 real-Isaac acceptance; exact case names are the external stage contract."""

import json
import math


def test_b601_model_loads(loaded_model, evidence_dir):
    import numpy as np
    from isaacsim.core.version import get_version
    from pxr import Usd, UsdGeom, UsdPhysics

    from protected_robot_controller.simulation.model import inspect_asset

    manifest, world, robot, stage, indices = loaded_model
    version = get_version()
    # The public tuple begins with full version; build metadata may follow patch.
    assert version[0].split("-")[0].split("+")[0] == "6.0.0", version
    source_stage, static = inspect_asset(manifest)
    assert source_stage.GetDefaultPrim().GetPath().pathString == "/B601"
    assert UsdGeom.GetStageMetersPerUnit(source_stage) == 1.0
    assert UsdGeom.GetStageUpAxis(source_stage) == "Z"
    assert len(static["rigid_bodies"]) == 10
    assert len(static["meshes"]) == 33
    assert len(static["colliders"]) == 10
    assert robot.handles_initialized
    assert robot.num_dof == 8
    assert robot.num_bodies == 10

    root = stage.GetPrimAtPath(manifest["articulation_root"])
    assert root.HasAPI(UsdPhysics.ArticulationRootAPI)
    assert root.GetAttribute("physxArticulation:enabledSelfCollisions").Get() is False
    fixed = UsdPhysics.FixedJoint(stage.GetPrimAtPath(manifest["fixed_base_joint"]))
    assert fixed
    assert not fixed.GetBody0Rel().GetTargets()  # world, not a floating base
    assert [str(p) for p in fixed.GetBody1Rel().GetTargets()] == [str(root.GetPath())]

    prims = list(Usd.PrimRange.Stage(stage, Usd.TraverseInstanceProxies()))
    assert sum(p.IsA(UsdGeom.Mesh) for p in prims) == 33
    assert sum(p.HasAPI(UsdPhysics.CollisionAPI) for p in prims) == 10
    collider_owners = set()
    for collider in [p for p in prims if p.HasAPI(UsdPhysics.CollisionAPI)]:
        owner = collider
        while owner and not owner.HasAPI(UsdPhysics.RigidBodyAPI):
            owner = owner.GetParent()
        assert owner, f"Collider has no rigid body: {collider.GetPath()}"
        collider_owners.add(str(owner.GetPath()))
    for body in [p for p in prims if p.HasAPI(UsdPhysics.RigidBodyAPI)]:
        assert not UsdPhysics.RigidBodyAPI(body).GetKinematicEnabledAttr().Get()
        mass = UsdPhysics.MassAPI(body)
        assert mass.GetMassAttr().Get() > 0
        assert np.all(np.asarray(mass.GetDiagonalInertiaAttr().Get()) > 0)
        assert str(body.GetPath()) in collider_owners
    for prim in prims:
        if prim.IsA(UsdGeom.Mesh):
            mesh = UsdGeom.Mesh(prim)
            points = np.asarray(mesh.GetPointsAttr().Get())
            assert points.ndim == 2 and points.shape[0] > 0
            assert np.isfinite(points).all()
            assert len(mesh.GetFaceVertexIndicesAttr().Get()) > 0

    # Smoke-test actual PhysX stepping and copied measured coordinates, no targets.
    start_step, start_time = world.current_time_step_index, world.current_time
    initial_pose = [np.array(value, copy=True) for value in robot.get_world_pose()]
    rows = []
    for _ in range(12):
        world.step(render=False)
        positions = np.array(robot.get_joint_positions(), dtype=float, copy=True)[indices]
        velocities = np.array(robot.get_joint_velocities(), dtype=float, copy=True)[indices]
        assert positions.shape == velocities.shape == (8,)
        assert np.isfinite(positions).all() and np.isfinite(velocities).all()
        for value, channel in zip(positions, manifest["channels"]):
            tolerance = 1e-3 if channel["unit"] == "rad" else 1e-4
            assert channel["position_limits"][0] - tolerance <= value
            assert value <= channel["position_limits"][1] + tolerance
        rows.append({"step": int(world.current_time_step_index),
                     "time_seconds": float(world.current_time),
                     "positions": positions.tolist(), "velocities": velocities.tolist()})
    assert world.current_time_step_index - start_step == 12
    assert math.isclose(world.current_time - start_time, 12 / 120, abs_tol=1e-7)
    final_pose = robot.get_world_pose()
    np.testing.assert_allclose(final_pose[0], initial_pose[0], atol=1e-6, rtol=0)
    # Quaternions q and -q encode the same fixed orientation.
    assert abs(float(np.dot(final_pose[1], initial_pose[1]))) > 1 - 1e-6
    (evidence_dir / "model_load.json").write_text(json.dumps({
        "test": "test_b601_model_loads", "isaac_version": list(version),
        "static": static, "runtime_dof_order": list(robot.dof_names),
        "output_order": manifest["output_order"], "samples": rows,
        "scope": "S1 load only; not a normal/obstructed motion verdict",
    }, indent=2) + "\n")


def test_all_output_channels_mapped(loaded_model, evidence_dir):
    import numpy as np
    from pxr import UsdPhysics

    manifest, world, robot, stage, indices = loaded_model
    expected = [f"joint{i}" for i in range(1, 7)] + ["joint_left", "joint_right"]
    assert manifest["output_order"] == expected
    assert manifest["actuator_order"] == expected[:6] + ["gripper"]
    assert [c["name"] for c in manifest["channels"]] == expected
    assert len(set(indices)) == 8
    assert [robot.dof_names[i] for i in indices] == expected
    movable = {p.GetName() for p in stage.Traverse()
               if p.IsA(UsdPhysics.RevoluteJoint) or p.IsA(UsdPhysics.PrismaticJoint)}
    assert movable == set(expected)
    properties = robot.dof_properties
    mapping = []
    for c, index in zip(manifest["channels"], indices):
        prim = stage.GetPrimAtPath(c["joint_path"])
        assert prim.GetTypeName() == c["joint_type"]
        angular = c["role"] == "arm"
        assert c["unit"] == ("rad" if angular else "m")
        assert c["direction"] == 1 and c["axis"] == "Z"
        joint = UsdPhysics.RevoluteJoint(prim) if angular else UsdPhysics.PrismaticJoint(prim)
        assert joint.GetAxisAttr().Get() == "Z"
        assert [str(p) for p in joint.GetBody0Rel().GetTargets()] == [c["body0"]]
        assert [str(p) for p in joint.GetBody1Rel().GetTargets()] == [c["body1"]]
        np.testing.assert_allclose([joint.GetLowerLimitAttr().Get(), joint.GetUpperLimitAttr().Get()],
                                   c["usd_position_limits"], atol=1e-5, rtol=1e-6)
        np.testing.assert_allclose([properties["lower"][index], properties["upper"][index]],
                                   c["position_limits"], atol=1e-6, rtol=1e-6)
        assert math.isclose(properties["maxVelocity"][index], c["max_velocity"], rel_tol=1e-5)
        assert math.isclose(properties["maxEffort"][index], c["max_effort"], abs_tol=1e-6)
        drive = UsdPhysics.DriveAPI.Get(prim, "angular" if angular else "linear")
        assert drive.GetTypeAttr().Get() == "force"
        for attr, key in [(drive.GetMaxForceAttr(), "max_effort"),
                          (drive.GetStiffnessAttr(), "stiffness"),
                          (drive.GetDampingAttr(), "damping")]:
            assert math.isclose(attr.Get(), c[key], abs_tol=1e-6)
        assert c["max_velocity"] > 0 and 0 <= c["max_effort"] < 100
        mapping.append({"output": c["name"], "runtime_index": int(index),
                        "unit": c["unit"], "limits": c["position_limits"]})

    follower = stage.GetPrimAtPath("/B601/Physics/joint_right")
    # Mimic API instance names are rotX/rotY/rotZ, including for a prismatic
    # single-DOF joint. The physical joint-frame axis remains Z (checked above).
    # The old assertion preserved an invalid upstream token, so S1 passed at
    # rest even though S2 proved that the passive finger did not follow.
    assert [s for s in follower.GetAppliedSchemas() if s.startswith("PhysxMimicJointAPI:")] == [
        "PhysxMimicJointAPI:rotX"]
    assert manifest["gripper_coupling"]["schema"] == "PhysxMimicJointAPI:rotX"
    assert manifest["gripper_coupling"]["reference_axis"] == "rotX"
    assert [str(p) for p in follower.GetRelationship("physxMimicJoint:rotX:referenceJoint").GetTargets()] == [
        "/B601/Physics/joint_left"]
    assert follower.GetAttribute("physxMimicJoint:rotX:gearing").Get() == -1
    assert follower.GetAttribute("physxMimicJoint:rotX:offset").Get() == 0
    assert follower.GetAttribute("physxMimicJoint:rotX:referenceJointAxis").Get() == "rotX"
    assert sum(c["drive_enabled"] for c in manifest["channels"]) == 7
    # A second fresh PhysX observation must cover BOTH fingers independently.
    world.step(render=False)
    observed = np.array(robot.get_joint_positions(), dtype=float, copy=True)[indices]
    assert observed.shape == (8,) and np.isfinite(observed).all()
    assert abs(observed[6] - observed[7]) < 1e-4
    (evidence_dir / "channel_map.json").write_text(json.dumps({
        "test": "test_all_output_channels_mapped", "mapping": mapping,
        "coupling": manifest["gripper_coupling"], "observed_positions": observed.tolist(),
        "step": int(world.current_time_step_index),
    }, indent=2) + "\n")
