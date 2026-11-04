"""Static preflight: run with a Python environment providing OpenUSD (pxr)."""

import argparse
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from protected_robot_controller.simulation.model import inspect_asset, read_manifest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
manifest = read_manifest()
stage, report = inspect_asset(manifest)
assert len(report["rigid_bodies"]) == 10
assert len(report["meshes"]) == 33
assert len(report["colliders"]) == 10
assert report["gripper_coupling"] == {
    "schemas": ["PhysxMimicJointAPI:rotX"],
    "reference_joint": ["/B601/Physics/joint_left"],
    "reference_axis": "rotX", "gearing": -1, "offset": 0,
}
assert manifest["gripper_coupling"]["schema"] == "PhysxMimicJointAPI:rotX"
assert manifest["gripper_coupling"]["reference_axis"] == "rotX"
for configured, observed in zip(manifest["channels"], report["channels"], strict=True):
    assert configured["name"] == observed["name"]
    assert configured["joint_type"] == observed["type"]
    assert configured["axis"] == observed["axis"]
    for key in ("max_effort", "stiffness", "damping"):
        assert math.isclose(configured[key], observed[key], abs_tol=1e-6)
    speed = configured["max_velocity"]
    if configured["unit"] == "rad":
        speed = math.degrees(speed)
    assert math.isclose(speed, observed["usd_max_velocity"], rel_tol=1e-6)
    assert all(math.isclose(a, b, abs_tol=1e-5) for a, b in
               zip(configured["usd_position_limits"], observed["usd_limits"], strict=True))
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + "\n")
print(f"Static USD only: {len(report['rigid_bodies'])} bodies, "
      f"{len(report['meshes'])} meshes, {len(report['colliders'])} colliders; {args.output}")
