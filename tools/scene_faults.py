"""S6-04 trusted scene faults acting on real PhysX constraints/read handles.

This fixture is never imported by the controller. It does not author samples,
change commands, sign reports, or assign joint/object positions. Simulator
imports are deliberately deferred until the pinned SimulationApp exists.
"""
from __future__ import annotations

import time
from unittest.mock import patch


TENSOR_API_REFERENCE = (
    "https://docs.omniverse.nvidia.com/kit/docs/omni_physics/109.0/"
    "extensions/runtime/source/omni.physics.tensors/docs/api/python.html"
)


def _clock(backend):
    return {
        "relative_physics_step": int(backend._steps),
        "physics_step": int(backend._world.current_time_step_index),
        "simulation_time_ns": round(float(backend._world.current_time) * 1e9),
        "monotonic_time_ns": time.monotonic_ns(),
    }


def _paths(value):
    if isinstance(value, (list, tuple)):
        return [_paths(item) for item in value]
    return str(value)


def constrain_arm_joint(backend, actuator="joint1"):
    """Narrow a real arm DOF's limits around its current measured position.

    Distinct bounds preserve the articulation's eight DOFs. The tensor API
    takes radians, unlike angular USD attributes. No effort, slew, authored
    trajectory, measurement, or policy limit changes here.
    """
    import numpy as np

    manifest = backend._manifest
    if actuator not in manifest["actuator_order"][:6]:
        raise ValueError("The scenario obstruction must constrain an arm joint")
    output_index = manifest["actuator_order"].index(actuator)
    runtime_index = backend._indices[output_index]
    view = backend._robot._articulation_view._physics_view
    before = np.array(view.get_dof_limits(), copy=True)
    positions = np.array(view.get_dof_positions(), dtype=float, copy=True)
    if before.shape != (1, 8, 2) or positions.shape != (1, 8) or not np.isfinite(positions).all():
        raise RuntimeError("Unexpected real articulation limits/position layout")
    q = float(positions[0, runtime_index])
    half_width = 1e-5
    if not before[0, runtime_index, 0] <= q - half_width < q + half_width <= before[0, runtime_index, 1]:
        raise RuntimeError("Measured obstruction position is outside original limits")
    requested = before.copy()
    requested[0, runtime_index] = (q - half_width, q + half_width)
    view.set_dof_limits(requested, np.array([0], dtype=np.int32))
    readback = np.array(view.get_dof_limits(), copy=True)
    if not np.allclose(readback, requested, atol=1e-8, rtol=0):
        raise RuntimeError("Real PhysX hard-limit readback disagrees with request")
    if not readback[0, runtime_index, 0] < readback[0, runtime_index, 1]:
        raise RuntimeError("Obstruction collapsed the articulation DOF")
    return {
        "kind": "PHYSX_ARM_DOF_CONSTRAINT",
        "method": "PhysX articulation DOF hard limits",
        "api": "ArticulationView.set_dof_limits with native readback",
        "api_reference": TENSOR_API_REFERENCE,
        "actuator": actuator,
        "output": manifest["output_order"][output_index],
        "output_index": output_index,
        "runtime_index": runtime_index,
        "initial_position": q,
        "half_width": half_width,
        "units": manifest["channels"][output_index]["unit"],
        "old_limits": before[0, runtime_index].tolist(),
        "limits": readback[0, runtime_index].tolist(),
        "all_limits_before": before.tolist(),
        "all_limits_after": readback.tolist(),
        "applied_at": _clock(backend),
        "measurement_source": "Native get_dof_positions before constraining the same articulated joint",
        "direct_state_assignment": False,
    }


class NativeAcquisitionInterruption:
    """Invalidate a native position-acquisition handle while physics stays live.

    A separate read-only tensor view reads the same actual articulation. Only
    the existing backend tensor object's position getter is temporarily bound
    to that native getter. Drives, velocities, efforts, and an independent
    diagnostic position getter remain on the original live view.

    The caller enters before authorization, invokes ``interrupt`` immediately
    before acquisition at relative physics step 121 (after 120 good samples),
    and exits only after retaining the controller's exact signed response. No
    fixture-created exception stands in for failed acquisition: the unchanged
    backend calls the invalid native getter itself.
    """

    expected_trigger_step = 121

    def __init__(self, backend):
        self.backend = backend
        self._source = None
        self._sensor_view = None
        self._getter_patch = None
        self._original_getter = None
        self.record = {
            "kind": "NATIVE_PHYSX_ACQUISITION_INVALIDATION",
            "method": "Invalidate a native SimulationView used only for position acquisition",
            "api_reference": TENSOR_API_REFERENCE,
            "expected_trigger_relative_physics_step": self.expected_trigger_step,
            "expected_complete_prefix_samples": self.expected_trigger_step,
            "position_getter": "Native ArticulationView.get_dof_positions",
            "interruption_calls": 0,
            "triggered": False,
            "native_read_failed": False,
            "getter_restored": False,
            "source_revived": False,
            "synthetic_measurements": False,
            "fixture_generated_sensor_exception": False,
        }

    def __enter__(self):
        import numpy as np
        import omni.physics.tensors as tensors
        from isaacsim.core.utils.stage import get_current_stage, get_current_stage_id

        if self._source is not None:
            raise RuntimeError("Acquisition fixture may be entered only once")
        original_view = self.backend._robot._articulation_view._physics_view
        self._original_getter = original_view.get_dof_positions
        # Isaac 6 registers physics by USD stage ID. Its own SimulationManager
        # passes that ID explicitly; the tensor API's default -1 need not name
        # the currently running scene. Never create/reset another physics scene
        # or step it to make acquisition available.
        if get_current_stage() != self.backend._stage:
            raise RuntimeError("Acquisition stage differs from the executing backend")
        stage_id = int(get_current_stage_id())
        self.record["source_creation"] = {
            "stage_id": stage_id, "backend": "physx", "frontend": "numpy",
            "stage_root_layer": self.backend._stage.GetRootLayer().identifier,
            "at": _clock(self.backend),
        }
        if stage_id < 0:
            raise RuntimeError("Acquisition requires an explicit active USD stage ID")
        source = self._source = tensors.create_simulation_view("numpy", stage_id=stage_id, backend="physx")
        source.set_subspace_roots("/")
        sensor = self._sensor_view = source.create_articulation_view(self.backend._manifest["articulation_root"])
        original_paths, sensor_paths = _paths(original_view.dof_paths), _paths(sensor.dof_paths)
        original_prims, sensor_prims = _paths(original_view.prim_paths), _paths(sensor.prim_paths)
        original = np.array(self._original_getter(), dtype=float, copy=True)
        acquired = np.array(sensor.get_dof_positions(), dtype=float, copy=True)
        self.record["setup"] = {
            "at": _clock(self.backend),
            "source_valid": bool(source.is_valid),
            "articulation_root": self.backend._manifest["articulation_root"],
            "original_dof_paths": original_paths,
            "source_dof_paths": sensor_paths,
            "original_prim_paths": original_prims,
            "source_prim_paths": sensor_prims,
            "output_indices": list(self.backend._indices),
            "output_order": list(self.backend._manifest["output_order"]),
            "original_positions_runtime_order": original.tolist(),
            "source_positions_runtime_order": acquired.tolist(),
            "positions_equal": bool(np.array_equal(original, acquired)),
            "shape": list(acquired.shape),
            "source_class": type(source).__module__ + "." + type(source).__name__,
            "getter_class": type(sensor).__module__ + "." + type(sensor).__name__,
        }
        if (not source.is_valid or sensor.count != 1 or sensor.max_dofs != 8
                or original_paths != sensor_paths or original_prims != sensor_prims
                or original.shape != (1, 8) or acquired.shape != (1, 8)
                or not np.isfinite(acquired).all() or not np.array_equal(original, acquired)):
            raise RuntimeError("Native acquisition source does not match the actual articulation")
        # Directly install the native bound reader, not a sensor-value wrapper.
        self._getter_patch = patch.object(original_view, "get_dof_positions", sensor.get_dof_positions)
        self._getter_patch.__enter__()
        self.record["getter_bound"] = True
        return self

    def original_positions(self):
        """Copy real runtime-order positions through the unaffected native view."""
        import numpy as np

        if self._original_getter is None:
            raise RuntimeError("Independent position getter is not initialized")
        result = np.array(self._original_getter(), dtype=float, copy=True)
        if result.shape != (1, 8) or not np.isfinite(result).all():
            raise RuntimeError("Independent native position acquisition failed")
        return result

    def interrupt(self):
        """Perform actual invalidation; the next protected native read must fail.

        Probe failure is recorded but not raised by this method. The unchanged
        backend must encounter its own native failure, and final acceptance
        must reject an unexpected successful read or wrong prefix length.
        """
        if self._source is None or self._getter_patch is None:
            raise RuntimeError("Native acquisition source is not active")
        self.record["interruption_calls"] += 1
        if self.record["interruption_calls"] != 1:
            raise RuntimeError("Acquisition source may be interrupted only once")
        self.record["trigger_at"] = _clock(self.backend)
        self.record["scheduled_step_match"] = self.backend._steps == self.expected_trigger_step
        self.record["source_valid_before"] = bool(self._source.is_valid)
        self._source.invalidate()
        self.record["triggered"] = True
        self.record["source_valid_after"] = bool(self._source.is_valid)
        try:
            # Exercise the same native method that the backend is about to use.
            # A success is a failed fault experiment, never a fabricated error.
            self._sensor_view.get_dof_positions()
        except Exception as error:
            self.record["native_read_failed"] = True
            self.record["native_read_error"] = {
                "type": type(error).__module__ + "." + type(error).__name__,
                "message": str(error),
            }
        else:
            self.record["unexpected_native_read_success"] = True
        self.record["physics_still_playing"] = bool(self.backend._world.is_playing())
        # This independent read is diagnostic only and is never returned as a
        # replacement for the interrupted protected acquisition.
        try:
            self.record["independent_positions_after_invalidation"] = self.original_positions().tolist()
            self.record["independent_view_live"] = True
        except Exception as error:
            self.record["independent_view_live"] = False
            self.record["independent_view_error"] = repr(error)

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self._getter_patch is not None:
            self._getter_patch.__exit__(exc_type, exc_value, exc_traceback)
            self._getter_patch = None
            self.record["getter_restored"] = True
            self.record["restored_at"] = _clock(self.backend)
        if self._source is not None:
            self.record["source_valid_after_restore"] = bool(self._source.is_valid)
        return False
