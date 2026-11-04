"""Test-only, offscreen Isaac visualization. Never supplies controller evidence."""

import asyncio
from hashlib import sha256
import json
from pathlib import Path
import struct
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "artifacts/demo/full_arm_gripper.png"
METADATA = IMAGE.with_suffix(".json")


def inspect_png(path):
    """Check a complete, nonempty renderer PNG without an imaging dependency."""
    raw = Path(path).read_bytes()
    if not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw) > 16 * 1024 * 1024:
        raise ValueError("Invalid or oversized PNG")
    offset, compressed, dimensions, ended = 8, bytearray(), None, False
    while offset + 12 <= len(raw):
        size = struct.unpack_from(">I", raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        body = raw[offset + 8:offset + 8 + size]
        if offset + 12 + size > len(raw):
            raise ValueError("Truncated PNG")
        crc = struct.unpack_from(">I", raw, offset + 8 + size)[0]
        if zlib.crc32(kind + body) & 0xFFFFFFFF != crc:
            raise ValueError("PNG CRC mismatch")
        if kind == b"IHDR":
            width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", body)
            if (width, height) != (1200, 900) or depth != 8 or color not in (2, 6) or interlace:
                raise ValueError("Unexpected renderer PNG format")
            dimensions = (width, height, 3 if color == 2 else 4)
        elif kind == b"IDAT":
            compressed.extend(body)
        elif kind == b"IEND":
            ended = offset + 12 == len(raw)
            break
        offset += size + 12
    if not ended or dimensions is None:
        raise ValueError("Incomplete PNG")
    width, height, channels = dimensions
    decoder = zlib.decompressobj()
    expected = height * (1 + width * channels)
    pixels = decoder.decompress(compressed, expected + 1)
    if not decoder.eof or len(pixels) != expected or len(set(pixels)) < 16 or len(compressed) < 10_000:
        raise ValueError("Empty/flat or malformed renderer image")
    return {"width": width, "height": height, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def capture(app):
    """Render a separate initialized full robot, after headless measured tests."""
    import numpy as np
    from isaacsim.core.version import get_version
    from omni.kit.viewport.utility import capture_viewport_to_file, get_active_viewport
    from pxr import Gf, Usd, UsdGeom, UsdLux, UsdPhysics
    from protected_robot_controller.simulation._backend import _IsaacRobotBackend
    from protected_robot_controller.simulation.model import MANIFEST_PATH

    IMAGE.parent.mkdir(parents=True, exist_ok=True)
    IMAGE.unlink(missing_ok=True)
    METADATA.unlink(missing_ok=True)
    record = {"status": "STARTED", "scope": "Real Isaac visualization only; motion verdicts are separate signed traces"}
    METADATA.write_text(json.dumps(record, indent=2) + "\n")
    backend, viewport, previous_updates = None, None, None
    try:
        version = list(get_version())
        if version[0].split("-")[0].split("+")[0] != "6.0.0":
            raise RuntimeError(f"Unpinned Isaac runtime: {version}")
        backend = _IsaacRobotBackend()  # Bounded drives even for trusted setup.
        backend.drive(backend._last_targets)
        backend.step_physics()
        sample = backend.sample_outputs()
        backend._world.pause()
        stage = backend._stage
        viewport = get_active_viewport()
        if viewport is None:
            raise RuntimeError("No offscreen viewport in provisioned Isaac runtime")
        previous_updates = viewport.updates_enabled
        viewport.updates_enabled = True
        viewport.resolution = (1200, 900)

        # Runtime link origins from PhysX, padded by local geometry radii. USD
        # bounds only provide conservative mesh sizes, never output samples.
        transforms = np.array(backend._robot._articulation_view._physics_view.get_link_transforms(), copy=True)[0]
        if transforms.shape != (10, 7) or not np.isfinite(transforms).all():
            raise RuntimeError("Missing full-arm PhysX link transforms")
        cache = UsdGeom.BBoxCache(Usd.TimeCode.Default(), ["default", "render", "proxy"])
        bodies = [p for p in stage.Traverse() if p.HasAPI(UsdPhysics.RigidBodyAPI)]
        radii = []
        for body in bodies:
            bounds = cache.ComputeLocalBound(body).ComputeAlignedRange()
            radii.append(max(float(Gf.Vec3d(bounds.GetCorner(i)).GetLength()) for i in range(8)))
        padding = max(radii) + 0.02
        lo, hi = transforms[:, :3].min(axis=0) - padding, transforms[:, :3].max(axis=0) + padding
        center = (lo + hi) / 2
        radius = float(np.linalg.norm(hi - lo) / 2)
        direction = np.array([1.2, 1.6, 0.9])
        direction /= np.linalg.norm(direction)
        # Fits the complete conservative sphere within the vertical field.
        distance = radius / np.sin(np.arctan(12 / 35)) * 1.08
        eye = center + direction * distance
        camera = UsdGeom.Camera.Define(stage, "/S6DemoCamera")
        camera.CreateFocalLengthAttr(35)
        camera.CreateHorizontalApertureAttr(32)
        camera.CreateVerticalApertureAttr(24)
        camera.CreateClippingRangeAttr(Gf.Vec2f(0.01, 100))
        # PhysX link transforms are float32. Boost.Python's Gf constructors
        # require native Python floats, even when NumPy scalars are finite.
        view = Gf.Matrix4d().SetLookAt(Gf.Vec3d(*(float(v) for v in eye)),
                                     Gf.Vec3d(*(float(v) for v in center)),
                                     Gf.Vec3d(0, 0, 1))
        UsdGeom.Xformable(camera).AddTransformOp().Set(view.GetInverse())
        viewport.camera_path = camera.GetPath()
        UsdLux.DomeLight.Define(stage, "/S6DemoFill").CreateIntensityAttr(1000)
        key = UsdLux.DistantLight.Define(stage, "/S6DemoKey")
        key.CreateIntensityAttr(2000)
        UsdGeom.Xformable(key).AddRotateXYZOp().Set(Gf.Vec3f(-35, 25, 35))
        frozen_step = backend._world.current_time_step_index
        backend._world.render()  # Sync PhysX/Fabric into rendering, no physics step.
        for _ in range(60):
            app.update()
        helper = capture_viewport_to_file(viewport, file_path=str(IMAGE))
        future = asyncio.ensure_future(helper.wait_for_result(completion_frames=30))
        deadline = time.monotonic() + 300
        while not future.done() and time.monotonic() < deadline:
            app.update()
        if not future.done():
            future.cancel()
            raise TimeoutError("Offscreen capture exceeded 300 seconds")
        future.result()
        # The renderer's future can precede asynchronous file writing.
        while time.monotonic() < deadline:
            try:
                image = inspect_png(IMAGE)
                break
            except (OSError, ValueError, zlib.error):
                app.update()
        else:
            raise TimeoutError("Renderer did not write a complete PNG")
        if backend._world.current_time_step_index != frozen_step:
            raise RuntimeError("Demo physics advanced while capture was paused")
        record.update(status="CAPTURED", image=image, isaac_version=version,
                      model_manifest_sha256=sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
                      source_revision=backend._manifest["source"]["commit"],
                      output_order=backend._manifest["output_order"],
                      positions=list(sample.positions), physics_step=sample.physics_step,
                      simulation_time_ns=sample.simulation_time_ns,
                      independent_actuators=7, observed_outputs=8, rigid_bodies=len(bodies),
                      camera={"eye": eye.tolist(), "target": center.tolist(),
                              "bounds_padding_m": padding, "bounds_radius_m": radius},
                      method="Paused actual driven articulation, offscreen Kit viewport, no UI or image synthesis")
        METADATA.write_text(json.dumps(record, indent=2) + "\n")
        return record
    except BaseException:
        record.update(status="FAILED", traceback=traceback.format_exc())
        METADATA.write_text(json.dumps(record, indent=2) + "\n")
        IMAGE.unlink(missing_ok=True)
        raise
    finally:
        if viewport is not None and previous_updates is not None:
            viewport.updates_enabled = previous_updates
        if backend is not None:
            backend.close()


if __name__ == "__main__":
    from isaacsim import SimulationApp
    application = SimulationApp({"headless": True, "fast_shutdown": True,
                                 "multi_gpu": False, "width": 1200, "height": 900,
                                 "enable_crashreporter": False})
    code = 0
    try:
        capture(application)
    except BaseException:
        traceback.print_exc()
        code = 1
    finally:
        application.close(wait_for_replicator=False, exit_code=code)
