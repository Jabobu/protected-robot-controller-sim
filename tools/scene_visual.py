"""Restricted standalone Isaac viewport for trusted-host scene examples.

This is an operator integrity boundary, not protection against a hostile host.
The GUI exposes camera navigation only; the controller remains the sole motion
path. Unknown extensions and unsafe UI affordances are blocked; detected stage or
clock changes fault rather than being treated as a valid completed command.
PhysX itself updates dynamic USD properties, so UI isolation is essential.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = ROOT / "tools" / "visual_runtime.json"
CAMERA = "/OmniverseKit_Persp"
# Kit parser accepts JSON strings as TOML strings. Paths belong to the supplied
# binary installation, not the user's shell or a container-specific location.
_EXPERIENCE = '''[package]
title = "PRC Visual"
version = "1.0.0"

[dependencies]
"omni.isaac.ml_archive" = {{ order = -100 }}
"omni.pip.compute" = {{}}
"isaacsim.core.api" = {{}}
"isaacsim.core.utils" = {{}}
"isaacsim.core.version" = {{}}
"isaacsim.simulation_app" = {{}}
"omni.kit.loop-isaac" = {{}}
"omni.kit.mainwindow" = {{}}
"omni.kit.manipulator.camera" = {{}}
"omni.kit.viewport.window" = {{}}
"omni.kit.viewport.utility" = {{}}
"omni.kit.viewport.scene_camera_model" = {{}}
"omni.hydra.rtx" = {{}}
"omni.hydra.usdrt_delegate" = {{}}
"omni.physics.physx" = {{}}
"omni.physics.stageupdate" = {{}}
"omni.physx.tensors" = {{}}

[settings.app]
name = "PRC Visual"
version = "1.0.0"
vulkan = true
settings.persistent = false
runLoops.main.manualModeEnabled = true
useFabricSceneDelegate = true
asyncRendering = false

[settings.app.exts.folders]
'++' = [{folders}]

[settings.exts."omni.kit.viewport.window"]
startup.disableWindowOnLoad = true
startup.selectionManipulator.enabled = false
startup.cameraManipulator.enabled = true

[settings.exts."omni.kit.window.viewport"]
showContextMenu = false

[settings.persistent.app.viewport]
coiDoubleClick = false

[settings.telemetry]
enableAnonymousAppName = false
enableAnonymousData = false
'''


def _configuration():
    return json.loads(PIN_PATH.read_text())


@contextmanager
def visual_experience():
    """Provide a private Kit experience without modifying the Isaac install."""
    value = os.environ.get("ISAAC_PATH")
    if not value:
        raise RuntimeError("Use the Isaac Sim python.sh launcher for visual mode")
    root = Path(value).resolve(strict=True)
    folders = [root / name for name in ("apps", "exts", "extscache", "extsDeprecated")]
    if not all(p.is_dir() for p in folders):
        raise RuntimeError("Isaac Sim extension directories are unavailable")
    with tempfile.TemporaryDirectory(prefix="prc-visual-") as directory:
        path = Path(directory) / "prcview.kit"
        path.write_text(_EXPERIENCE.format(folders=", ".join(json.dumps(str(p)) for p in folders)))
        yield path


def configure_viewport():
    """Create the sole viewport; no file-drop or editor affordances."""
    import carb
    from omni.kit.viewport.window import ViewportWindow
    from omni.kit.viewport.window.dragdrop.delegate import DragDropDelegate

    settings = carb.settings.get_settings()
    settings.set_bool("/exts/omni.kit.viewport.window/startup/selectionManipulator/enabled", False)
    settings.set_bool("/exts/omni.kit.window.viewport/showContextMenu", False)
    settings.set_bool("/persistent/app/viewport/coiDoubleClick", False)
    for delegate in list(DragDropDelegate.get_instances()):
        delegate.destroy()
    if list(DragDropDelegate.get_instances()):
        raise RuntimeError("Cannot disable viewport drag and drop")
    return ViewportWindow("Viewport", width=1200, height=900, usd_drop_support=False)


class VisualGuard:
    """Latch unsafe GUI events and verify PhysX is unchanged by each render."""

    def __init__(self, app, backend, scene, viewport):
        import carb
        import carb.eventdispatcher
        import omni.kit.app
        import omni.timeline
        import omni.usd
        from pxr import Tf, Usd, UsdGeom, UsdPhysics
        from omni.kit.viewport.window.dragdrop.delegate import DragDropDelegate

        self.app, self.backend, self.scene, self.viewport = app, backend, scene, viewport
        self._owner = threading.get_ident()
        self._settings = carb.settings.get_settings()
        self._context = omni.usd.get_context()
        self._extension_manager = omni.kit.app.get_app().get_extension_manager()
        self._drop_delegate = DragDropDelegate
        self._stage = backend._stage
        self._fault = None
        self._in_pump = False
        self._armed = False
        self._physics_paths = frozenset(_configuration()["physics_notice_paths"])
        self._extension_ids = frozenset(_configuration()["extensions"])
        self._UsdGeom, self._UsdPhysics = UsdGeom, UsdPhysics
        # Physics is stepped explicitly. Keep the UI's timeline from advancing
        # independently while a render pumps events; restore it during teardown.
        self._timeline = omni.timeline.get_timeline_interface()
        if hasattr(self._timeline, "get_timeline"):
            self._timeline = self._timeline.get_timeline()
        self._timeline_auto_before = self._timeline.is_auto_updating()
        self._subscriptions = []
        self._notice = None
        self._closed = False
        try:
            self._timeline.set_auto_update(False)
            self._timeline.commit()
            if self._timeline.is_auto_updating():
                raise RuntimeError("Cannot disable automatic visual timeline updates")
            self._notice = Tf.Notice.Register(Usd.Notice.ObjectsChanged, self._stage_changed, self._stage)
            dispatcher = carb.eventdispatcher.get_eventdispatcher()
            names = ("PLAY", "PAUSE", "STOP", "LOOP_MODE_CHANGED", "START_TIME_CHANGED", "END_TIME_CHANGED",
                     "TIME_CODE_PER_SECOND_CHANGED", "AUTO_UPDATE_CHANGED", "PREROLLING_CHANGED",
                     "TICKS_PER_FRAME_CHANGED", "PLAY_EVERY_FRAME_CHANGED", "TARGET_FRAMERATE_CHANGED",
                     "TENTATIVE_TIME_CHANGED", "DIRECTOR_CHANGED")
            for name in names:
                self._subscriptions.append(dispatcher.observe_event(
                    observer_name="prc-visual-" + name, filter=self._timeline.get_event_key(),
                    event_name=getattr(omni.timeline, "GLOBAL_EVENT_" + name),
                    on_event=lambda event, name=name: self._timeline_changed(name)))
            # PERMANENT ticks are emitted on every app update even with auto-update
            # disabled; explicit seek/step methods emit CURRENT_TIME_TICKED.
            for name in ("CURRENT_TIME_TICKED",):
                self._subscriptions.append(dispatcher.observe_event(
                    observer_name="prc-visual-" + name, filter=self._timeline.get_event_key(),
                    event_name=getattr(omni.timeline, "GLOBAL_EVENT_" + name),
                    on_event=lambda event, name=name: self._timeline_changed(name) if self._in_pump else None))
            self._armed = True
            self._limit_baseline = self._limits()
            self.check()
        except BaseException:
            self.close()
            raise

    def _fail(self, message):
        if self._fault is None:
            self._fault = message

    def _timeline_changed(self, name):
        if self._armed:
            self._fail("Timeline changed during guarded execution: " + name)

    def _stage_changed(self, notice, stage):
        if not self._armed:
            return
        if notice.GetResyncedPaths():
            self._fail("Stage structure changed during guarded execution")
        for path in notice.GetChangedInfoOnlyPaths():
            value = str(path)
            if value in self._physics_paths:
                continue  # PhysX publishes these; this is not the UI isolation boundary.
            if value.startswith(CAMERA + "."):
                attribute = value.split(".", 1)[1]
                if attribute.startswith("xformOp:") or attribute in {
                    "xformOpOrder", "focalLength", "horizontalAperture", "verticalAperture", "clippingRange"
                }:
                    continue
            self._fail("Unexpected stage change during guarded execution: " + value)

    def _targets(self):
        view = self.backend._robot._articulation_view._physics_view
        values = []
        for getter in (view.get_dof_position_targets, view.get_dof_velocity_targets):
            raw = getter()
            if raw is None:
                raise RuntimeError("PhysX target read unavailable")
            arr = self.backend._np.array(raw, dtype=float, copy=True)
            if arr.ndim != 2 or arr.shape[0] != 1 or not self.backend._np.isfinite(arr).all():
                raise RuntimeError("Invalid PhysX target read")
            values.append(arr[0])
        return values

    def _limits(self):
        view = self.backend._robot._articulation_view._physics_view
        values = []
        for getter in (view.get_dof_max_forces, view.get_dof_max_velocities):
            raw = getter()
            if raw is None:
                raise RuntimeError("PhysX limit read unavailable")
            arr = self.backend._np.array(raw, dtype=float, copy=True)
            if not self.backend._np.isfinite(arr).all():
                raise RuntimeError("Invalid PhysX limit read")
            values.append(arr.tolist())
        return values

    def _state(self):
        objects = self.scene.observe()["objects"]
        positions, velocities = self._targets()
        return (self.backend._read_vector(self.backend._robot.get_joint_positions),
                self.backend._read_vector(self.backend._robot.get_joint_velocities),
                positions.tolist(), velocities.tolist(), self._limits(),
                {key: {field: item[field] for field in ("position", "orientation_wxyz", "linear_velocity", "angular_velocity")}
                 for key, item in objects.items()})

    def check(self):
        """Fail before any requested drive and before a completed report."""
        if threading.get_ident() != self._owner:
            raise RuntimeError("GUI operations must stay on the simulation owner thread")
        # A close can also trigger renderer USD notices. Report the actual
        # close and avoid dereferencing a UI/context already being torn down.
        if not self.app.is_running():
            self._fail("Visual window closed")
            raise RuntimeError("Visual window closed")
        if not self.viewport.visible:
            self._fail("Visual viewport closed")
            raise RuntimeError("Visual viewport closed")
        if self._context.get_stage() != self._stage:
            self._fail("Active stage was replaced")
        if str(self.viewport.viewport_api.camera_path) != CAMERA:
            self._fail("Viewport camera changed")
        prim = self._stage.GetPrimAtPath(CAMERA)
        if (not prim or not prim.IsA(self._UsdGeom.Camera)
                or prim.HasAPI(self._UsdPhysics.RigidBodyAPI)):
            self._fail("Visual camera is not a dedicated non-physical camera")
        enabled = frozenset(e["id"] for e in self._extension_manager.get_extensions() if e["enabled"])
        if enabled != self._extension_ids:
            self._fail("Visual extension inventory differs from tested Isaac runtime")
        if list(self._drop_delegate.get_instances()):
            self._fail("Viewport drag/drop delegate became active")
        for key in ("/exts/omni.kit.viewport.window/startup/selectionManipulator/enabled",
                    "/exts/omni.kit.window.viewport/showContextMenu",
                    "/persistent/app/viewport/coiDoubleClick"):
            if self._settings.get(key) is not False:
                self._fail("Restricted visual setting changed: " + key)
        if not self.backend._world.is_playing() or self._timeline.is_auto_updating():
            self._fail("Physics timeline stopped, paused, or auto-updating")
        if self._limits() != self._limit_baseline:
            self._fail("Actuator limits changed")
        positions, velocities = self._targets()
        indices = self.backend._drive_indices
        np = self.backend._np
        # PhysX drive targets are binary32. Compare their actual representation
        # exactly, rather than allowing an unauthorized sub-microunit change.
        if (not np.array_equal(np.asarray(positions[indices], dtype=np.float32),
                               np.asarray(self.backend._last_targets, dtype=np.float32))
                or not np.array_equal(np.asarray(velocities[indices], dtype=np.float32),
                                      np.zeros(7, dtype=np.float32))):
            self._fail("PhysX drive targets differ from controller targets")
        if self._fault is not None:
            raise RuntimeError(self._fault)

    def pump(self, expected_steps):
        """Render without an extra physics step; any mismatch invalidates capture."""
        self.check()
        world = self.backend._world
        self.backend._check_physics_clock(expected_steps)
        before = self._state()
        clock_before = (int(world.current_time_step_index), float(world.current_time), world.is_playing(),
                        float(self._timeline.get_current_time()))
        previous = self._settings.get("/app/player/playSimulations")
        if previous is not True:
            raise RuntimeError("Unexpected Isaac player state before visual update")
        self._in_pump = True
        try:
            world.render()
        finally:
            self._in_pump = False
            self._settings.set_bool("/app/player/playSimulations", previous)
        if self._settings.get("/app/player/playSimulations") is not previous:
            raise RuntimeError("Could not restore Isaac player state")
        self.check()
        self.backend._check_physics_clock(expected_steps)
        clock_after = (int(world.current_time_step_index), float(world.current_time), world.is_playing(),
                       float(self._timeline.get_current_time()))
        after = self._state()
        if clock_after != clock_before or after != before:
            labels = ("joint_positions", "joint_velocities", "position_targets", "velocity_targets", "limits", "objects")
            changed = [label for label, old, new in zip(labels, before, after) if old != new]
            raise RuntimeError(f"Physics state or clock changed during visual update: clock={clock_before!r}->{clock_after!r}, fields={changed}")

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._armed = False
        try:
            self._subscriptions.clear()
        finally:
            try:
                if self._notice is not None:
                    self._notice.Revoke()
            finally:
                try:
                    self._timeline.set_auto_update(self._timeline_auto_before)
                finally:
                    self._timeline.commit()
                if self._timeline.is_auto_updating() != self._timeline_auto_before:
                    raise RuntimeError("Could not restore timeline auto-update state")


def visual_metadata(experience):
    return {"mode": "standalone_visual", "kit_configuration_sha256": sha256(Path(experience).read_bytes()).hexdigest(),
            "extension_pin_sha256": sha256(PIN_PATH.read_bytes()).hexdigest(),
            "scope": "trusted-host GUI; viewport observations are not signed evidence"}
