"""Private, trusted-host B601 PhysX adapter. No transport or verdict logic.

Only drive targets are written. All observations come from PhysX, after a step,
and are copied into immutable tuples. Test-only obstruction code lives in tests.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import time

from .model import load_model, read_manifest
from ..backend import Observation


SETUP_TARGET = (0.0, -0.7, -1.1, 0.0, 0.0, 0.0, 0.02)
SETUP_RAMP_STEPS = 480
SETUP_HOLD_STEPS = 240
MAX_SAMPLES = 4097
MAX_STEP_WALL_NS = 2_000_000_000
MAX_RUN_WALL_NS = 120_000_000_000


class BackendFault(RuntimeError):
    """Acquisition/execution is invalid; never substitute a synthetic sample."""


@dataclass(frozen=True)
class OutputSample(Observation):
    velocities: tuple[float, ...]
    measured_joint_efforts: tuple[float, ...]

    @property
    def sequence(self):
        """Retain the S2 diagnostic API; counter is the controller wire meaning."""
        return self.counter


class _IsaacRobotBackend:
    """One owning adapter; not an interface exposed to the robot application.

    SimulationApp must already exist. Construction performs bounded trusted
    setup, using drives even for the initial pose. A fresh scene is required per
    instance; there is no reset/calibration/sensor-injection execution method.
    """

    def __init__(self, *, setup_scene=None):
        import numpy as np
        from isaacsim.core.utils.stage import create_new_stage

        self._np = np
        self._manifest = read_manifest()
        self._channels = self._manifest["channels"]
        self._dt = self._manifest["runtime"]["physics_dt_seconds"]
        # PhysX's step callback carries binary32 seconds; World accumulates
        # those values in its clock. Keep the nominal dt for command limits.
        self._physics_dt = float(np.float32(self._dt))
        self._world = None
        self._closed = False
        self._faulted = False
        self._visual_guard = None
        create_new_stage()
        try:
            self._world, self._robot, self._stage, self._indices = load_model(
                self._manifest, setup_scene=setup_scene)
            self._driven = [i for i, c in enumerate(self._channels) if c["drive_enabled"]]
            if self._driven != list(range(7)):
                raise BackendFault("Unexpected independent actuator mapping")
            self._drive_indices = np.array([self._indices[i] for i in self._driven], dtype=np.int32)
            self._verify_limits()
            start = self._read_vector(self._robot.get_joint_positions)[:7]
            # All initialization is finite and uses the same capped drives.
            for step in range(1, SETUP_RAMP_STEPS + SETUP_HOLD_STEPS + 1):
                alpha = min(step / SETUP_RAMP_STEPS, 1.0)
                target = tuple(a + (b - a) * alpha for a, b in zip(start, SETUP_TARGET))
                previous = start if step == 1 else self._last_targets
                self._validate_targets(target, previous)
                self._write_targets(target)
                self._last_targets = target
                self._world.step(render=False)
            self._start_step = int(self._world.current_time_step_index)
            self._start_sim_time = float(self._world.current_time)
            self._start_wall = time.monotonic_ns()
            self._steps = 0
            self._run_start_steps = 0
            self._last_sample_step = -1
            self._pending_drive = False
            self.initial_sample = self._capture()
        except BaseException:
            self.close()
            raise

    def _verify_limits(self):
        props = self._robot.dof_properties
        for index, channel in zip(self._indices, self._channels):
            for field, expected in (("maxEffort", channel["max_effort"]),
                                    ("maxVelocity", channel["max_velocity"])):
                if not math.isclose(float(props[field][index]), expected, rel_tol=1e-5, abs_tol=1e-6):
                    raise BackendFault(f"Unpinned {field} on {channel['name']}")

    def _read_vector(self, getter):
        values = self._np.array(getter(), dtype=float, copy=True)
        if values.shape != (8,) or not self._np.isfinite(values).all():
            raise BackendFault("Invalid PhysX output")
        return tuple(float(values[index]) for index in self._indices)

    def _write_targets(self, target):
        from isaacsim.core.utils.types import ArticulationAction

        # No follower command, raw effort command, or state assignment.
        self._robot.apply_action(ArticulationAction(
            joint_positions=self._np.array(target, dtype=float, copy=True),
            joint_velocities=self._np.zeros(7), joint_indices=self._drive_indices,
        ))

    def _validate_targets(self, targets, previous):
        if len(targets) != 7:
            raise ValueError("Expected six arm targets and one gripper target")
        for target, old, channel in zip(targets, previous, self._channels):
            if isinstance(target, bool) or not isinstance(target, (int, float)) or not math.isfinite(target):
                raise ValueError("Targets must be finite numbers")
            lo, hi = channel["position_limits"]
            if not lo <= target <= hi:
                raise ValueError(f"Position limit: {channel['name']}")
            if abs(target - old) > channel["max_velocity"] * self._dt + 1e-9:
                raise ValueError(f"Target speed limit: {channel['name']}")

    def read_initial(self):
        """Acquire afresh after authorization, never return the setup timestamp."""
        self._require_live()
        if self._pending_drive or self._last_sample_step != self._steps:
            raise BackendFault("Previous drive/step has not been sampled")
        self._verify_limits()
        self._start_wall = time.monotonic_ns()
        self._run_start_steps = self._steps
        return self._capture()

    def drive(self, targets, *, velocity_limits=None, effort_limits=None):
        self._require_live()
        # S2 callers use the already pinned caps; the controller must request
        # exactly those caps. No message can reconfigure the articulation.
        if velocity_limits is not None or effort_limits is not None:
            if (velocity_limits is None or effort_limits is None
                    or tuple(velocity_limits) != tuple(c["max_velocity"] for c in self._channels[:7])
                    or tuple(effort_limits) != tuple(c["max_effort"] for c in self._channels[:7])):
                raise ValueError("Unpinned controller drive limits")
        if self._pending_drive or self._last_sample_step != self._steps:
            raise BackendFault("Previous drive/step has not been sampled")
        targets = tuple(targets)
        self._validate_targets(targets, self._last_targets)
        self._write_targets(targets)
        self._last_targets = targets
        self._pending_drive = True

    def step_physics(self, *, deadline_ns=None):
        self._require_live()
        if not self._pending_drive:
            raise BackendFault("No bounded target pending")
        started = time.monotonic_ns()
        deadline = min(started + MAX_STEP_WALL_NS, self._start_wall + MAX_RUN_WALL_NS,
                       deadline_ns if deadline_ns is not None else started + MAX_STEP_WALL_NS)
        try:
            if started >= deadline or self._steps - self._run_start_steps >= MAX_SAMPLES - 1:
                raise BackendFault("Capture deadline/resource limit")
            if not self._world.is_playing():
                raise BackendFault("Physics is paused/stopped")
            self._check_physics_clock(self._steps)
            self._world.step(render=False)
            self._check_physics_clock(self._steps + 1)
            if self._visual_guard is not None:
                self._visual_guard.pump(self._steps + 1)
            if time.monotonic_ns() > deadline:
                raise BackendFault("Physics step deadline exceeded")
            self._check_physics_clock(self._steps + 1)
            self._steps += 1
            self._pending_drive = False
        except BaseException:
            self.stop_or_hold()
            raise

    def _check_physics_clock(self, steps):
        # Check configured dt as well as the event-driven World counter/clock.
        # No time or sample is manufactured from the expected values here.
        configured_dt = float(self._world.get_physics_dt())
        actual_step = int(self._world.current_time_step_index)
        actual_time = float(self._world.current_time)
        expected_step = self._start_step + steps
        expected_time = self._start_sim_time + steps * self._physics_dt
        if (not math.isclose(configured_dt, self._dt, abs_tol=1e-12, rel_tol=0)
                or actual_step != expected_step
                or not math.isclose(actual_time, expected_time, abs_tol=1e-9, rel_tol=0)):
            raise BackendFault(
                "Physics did not advance by exactly one fixed step: "
                f"step={actual_step}/{expected_step}, time={actual_time!r}/{expected_time!r}, "
                f"configured_dt={configured_dt!r}, nominal_dt={self._dt!r}, "
                f"physx_dt={self._physics_dt!r}"
            )

    def _capture(self):
        self._check_physics_clock(self._steps)
        sample = OutputSample(
            self._steps, int(self._world.current_time_step_index),
            round(float(self._world.current_time) * 1e9), time.monotonic_ns(),
            self._read_vector(self._robot.get_joint_positions),
            (True,) * 8,  # _read_vector rejects every missing/nonfinite reading.
            self._read_vector(self._robot.get_joint_velocities),
            # Constraint reactions may exceed a drive cap. They are not PD
            # actuator effort telemetry and must never be clipped to that cap.
            self._read_vector(self._robot.get_measured_joint_efforts),
        )
        self._check_physics_clock(self._steps)
        self._last_sample_step = self._steps
        return sample

    def sample_outputs(self):
        self._require_live()
        if self._pending_drive or self._last_sample_step == self._steps:
            raise BackendFault("A fresh physics step is required before sampling")
        try:
            return self._capture()
        except BaseException:
            self.stop_or_hold()
            raise

    def _require_live(self):
        if self._closed or self._faulted:
            raise BackendFault("Backend closed or faulted")
        if self._visual_guard is not None:
            self._visual_guard.check()

    def stop_or_hold(self, reason=None):
        """Latch a fault and request capped position hold; do not reset state.

        If acquisition is broken, leave the last finite bounded target in place.
        The caller retains its already captured prefix, with an aborted status.
        """
        if reason == "NONE":
            self._require_live()
            if self._pending_drive or self._last_sample_step != self._steps:
                raise BackendFault("Cannot complete an unsampled drive")
            # The final target has already been held and sampled for the whole
            # authenticated hold interval. Keep that capped target on completion.
            self._write_targets(self._last_targets)
            return
        self._faulted = True
        try:
            measured = self._read_vector(self._robot.get_joint_positions)[:7]
            hold = tuple(min(max(q, c["position_limits"][0]), c["position_limits"][1])
                         for q, c in zip(measured, self._channels))
        except Exception:
            hold = self._last_targets
        self._write_targets(hold)

    def close(self):
        if not self._closed and self._world is not None:
            self._closed = True
            try:
                self._world.stop()
                self._world.clear()
            finally:
                self._world.clear_instance()
