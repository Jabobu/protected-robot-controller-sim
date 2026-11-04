"""Sparse, genuine Isaac viewport frames for the S6-04 scene fixtures.

This observer is outside the controller and never supplies signed samples.
Construct it and capture ``setup`` before constructing the controller or issuing
HELLO: the first render can compile shaders for minutes. Later captures belong
between completed EXECUTE calls, never inside a backend call with a two-second
deadline. A frame pauses the existing scene; it never advances or resets physics.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import time
import traceback
from uuid import uuid4
import zlib

from tools.capture_full_model import inspect_png

ROOT = Path(__file__).resolve().parents[1]
CAPTURE_TIMEOUT_SECONDS = 300


def _write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _relative(path):
    return str(Path(path).resolve().relative_to(ROOT))


class SceneRecorder:
    """Capture the already authored observation camera without changing state.

    ``records`` includes failed attempts. Each attempt has its own JSON and PNG
    name; an incomplete image is retained if rendering fails. ``index_path``
    identifies the whole sequence. Call ``close`` before closing the backend.
    This deliberately uses Timeline.play/commit rather than World.play, whose
    documented initialization step would break the next signed command's clock.
    """

    def __init__(self, app, backend, scene, directory):
        from isaacsim.core.version import get_version
        import omni.timeline
        from omni.kit.viewport.utility import get_active_viewport

        self.app, self.backend, self.scene = app, backend, scene
        self.directory = Path(directory).resolve()
        # Keep all recording output inside the scene-work artifact tree.
        self.directory.relative_to(ROOT / "artifacts" / "scene-work")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.index_path = self.directory / "index.json"
        if any(self.directory.iterdir()):
            raise FileExistsError("Recording directory must be new and empty; prior attempts are retained")
        self.records = []
        self._closed = False
        self._warmed = False
        self._viewport = None
        self._previous_viewport = None
        self._timeline = omni.timeline.get_timeline_interface()
        from tools.runtime_provenance import current_runtime
        self.runtime_identity = current_runtime()
        self.version = list(get_version())
        self.index = {
            "schema_version": 1, "status": "STARTED", "records": self.records,
            "isaac_version": self.version,
            "runtime_image": self.runtime_identity["image_id"], "runtime_identity": self.runtime_identity,
            "scope": "Actual simulator images supplement separate signed joint evidence and object observations",
            "method": "Paused existing scene; World.render synchronizes PhysX/Fabric; Kit viewport PNG capture",
            "frame_schedule": "Before controller construction, between EXECUTE calls, and after observed hold",
        }
        self._flush()
        try:
            if self.version[0].split("-")[0].split("+")[0] != "6.0.0":
                raise RuntimeError(f"Pinned Isaac 6.0.0 required for recordings; observed {self.version}")
            camera = scene.profile["camera"]
            if not scene.camera_enabled or not backend._stage.GetPrimAtPath(camera["prim"]):
                raise RuntimeError("Recording requires the authored manipulation observation camera")
            if tuple(camera["resolution"]) != (1200, 900):
                raise RuntimeError("Recording must retain the calibrated 1200 by 900 camera format")
            self._viewport = get_active_viewport()
            if self._viewport is None:
                raise RuntimeError("No offscreen viewport in the provisioned Isaac runtime")
            self._previous_viewport = {
                "updates_enabled": self._viewport.updates_enabled,
                "resolution": self._viewport.resolution,
                "camera_path": self._viewport.camera_path,
            }
            self._viewport.updates_enabled = True
            self._viewport.resolution = tuple(camera["resolution"])
            self._viewport.camera_path = camera["prim"]
            self.index["camera"] = self._camera_metadata()
            self.index["model_manifest_sha256"] = sha256(
                (ROOT / scene.profile["model"]["manifest"]).read_bytes()).hexdigest()
            self.index["source_revision"] = backend._manifest["source"]["commit"]
            self.index["output_order"] = list(backend._manifest["output_order"])
            self._flush()
        except BaseException:
            self.index.update(status="FAILED", traceback=traceback.format_exc())
            self._flush()
            self._restore_viewport()
            raise

    def _flush(self):
        _write_json(self.index_path, self.index)

    def _camera_metadata(self):
        from pxr import UsdGeom

        prim = self.backend._stage.GetPrimAtPath(self.scene.profile["camera"]["prim"])
        camera = UsdGeom.Camera(prim)
        transform = UsdGeom.Xformable(prim).GetLocalTransformation()
        return {
            "prim": str(prim.GetPath()),
            "resolution": list(self._viewport.resolution),
            "focal_length_mm": float(camera.GetFocalLengthAttr().Get()),
            "horizontal_aperture_mm": float(camera.GetHorizontalApertureAttr().Get()),
            "vertical_aperture_mm": float(camera.GetVerticalApertureAttr().Get()),
            "clipping_m": [float(v) for v in camera.GetClippingRangeAttr().Get()],
            "local_transform": [[float(v) for v in row] for row in transform],
        }

    def _snapshot(self):
        """Read actual arrays without consuming or changing backend sample state."""
        backend = self.backend
        return {
            "physics_step": int(backend._world.current_time_step_index),
            "simulation_time_ns": round(float(backend._world.current_time) * 1e9),
            "joint_positions": list(backend._read_vector(backend._robot.get_joint_positions)),
            "joint_velocities": list(backend._read_vector(backend._robot.get_joint_velocities)),
            "joint_units": ["rad"] * 6 + ["m"] * 2,
            "objects": self.scene.observe(),
        }

    def capture(self, label):
        """Retain one PNG and its actual state, or retain failure diagnostics.

        All application updates happen with the timeline paused. Both the time
        counters and copied joint/object arrays must be identical after rendering
        AND after restoring play. No clock rebasing can hide an extra step.
        """
        from omni.kit.viewport.utility import capture_viewport_to_file

        if self._closed:
            raise RuntimeError("Recorder is closed")
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", label):
            raise ValueError("Frame labels must be 1-80 letters, digits, hyphens or underscores")
        if self._timeline.is_stopped():
            raise RuntimeError("Cannot record a stopped/reset scene")
        name = f"{len(self.records):03d}-{label}-{uuid4().hex[:12]}"
        image_path = self.directory / (name + ".png")
        metadata_path = self.directory / (name + ".json")
        record = {
            "status": "STARTED", "label": label,
            "image_path": _relative(image_path), "metadata_path": _relative(metadata_path),
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "isaac_version": list(self.version),
            "runtime_image": self.runtime_identity["image_id"], "runtime_identity": self.runtime_identity,
            "camera": deepcopy(self.index["camera"]), "method": self.index["method"],
            "physics_advanced": None, "timeline_restored_without_step": False,
        }
        self.records.append(record)
        _write_json(metadata_path, record)
        self._flush()
        started = time.monotonic()
        was_playing = bool(self._timeline.is_playing())
        future = None
        try:
            record["before"] = self._snapshot()
            record["timeline_playing_before"] = was_playing
            self._timeline.pause()
            self._timeline.commit()
            if self._timeline.is_playing():
                raise RuntimeError("Timeline did not pause for observation recording")
            # Existing S6 capture uses render to synchronize the actual articulation
            # into Fabric/renderer. Neither this call nor the paused app updates
            # is allowed to simulate another physics step.
            self.backend._world.render()
            for _ in range(60 if not self._warmed else 2):
                self.app.update()
            deadline = time.monotonic() + CAPTURE_TIMEOUT_SECONDS
            helper = capture_viewport_to_file(self._viewport, file_path=str(image_path))
            future = asyncio.ensure_future(helper.wait_for_result(completion_frames=30))
            while not future.done() and time.monotonic() < deadline:
                self.app.update()
            if not future.done():
                future.cancel()
                raise TimeoutError("Offscreen scene capture exceeded 300 seconds")
            future.result()
            # Completion can precede the asynchronous PNG file write. Validate
            # chunks, CRCs, decompressed size and nonflat content before success.
            while time.monotonic() < deadline:
                try:
                    record["image"] = inspect_png(image_path)
                    break
                except (OSError, ValueError, zlib.error):
                    self.app.update()
            else:
                raise TimeoutError("Renderer did not produce a complete nonflat scene PNG")
            record["after_render"] = self._snapshot()
            if record["after_render"] != record["before"]:
                raise RuntimeError("Actual physics state changed while the scene was paused for recording")
            self._warmed = True
        except BaseException:
            record.update(status="FAILED", traceback=traceback.format_exc())
            raise
        finally:
            try:
                if future is not None and not future.done():
                    future.cancel()
                if was_playing:
                    # World.play() documents an internal physics step. The Kit
                    # timeline commits only play state; there is deliberately NO
                    # app.update after this point, until the caller's next step.
                    self._timeline.play()
                    self._timeline.commit()
                record["after"] = self._snapshot()
                record["timeline_playing_after"] = bool(self._timeline.is_playing())
                record["physics_advanced"] = record["after"] != record.get("before")
                record["timeline_restored_without_step"] = (
                    not record["physics_advanced"]
                    and record["timeline_playing_after"] == was_playing)
                if not record["timeline_restored_without_step"]:
                    raise RuntimeError("Timeline restoration changed physical state or failed to restore play")
                if record["status"] == "STARTED":
                    record["status"] = "CAPTURED"
            except BaseException:
                record.update(status="FAILED", restoration_traceback=traceback.format_exc())
                raise
            finally:
                record["capture_seconds"] = time.monotonic() - started
                record["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
                _write_json(metadata_path, record)
                self._flush()
        return deepcopy(record)

    def _restore_viewport(self):
        if self._viewport is not None and self._previous_viewport is not None:
            self._viewport.camera_path = self._previous_viewport["camera_path"]
            self._viewport.resolution = self._previous_viewport["resolution"]
            self._viewport.updates_enabled = self._previous_viewport["updates_enabled"]

    def close(self):
        """Restore viewport configuration; retain every frame and failure record."""
        if self._closed:
            return
        try:
            self._restore_viewport()
        finally:
            self._closed = True
            self.index["status"] = (
                "CLOSED" if self.records and all(r["status"] == "CAPTURED" for r in self.records)
                else "FAILED")
            self.index["closed_at_utc"] = datetime.now(timezone.utc).isoformat()
            self._flush()
