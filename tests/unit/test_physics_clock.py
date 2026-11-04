"""Clock arithmetic regression only. No robot, outputs, or physics evidence."""

import struct
from types import SimpleNamespace

import pytest

from protected_robot_controller.simulation._backend import BackendFault, MAX_SAMPLES, _IsaacRobotBackend


def clock_only():
    backend = _IsaacRobotBackend.__new__(_IsaacRobotBackend)
    backend._dt = 1 / 120
    backend._physics_dt = struct.unpack("f", struct.pack("f", backend._dt))[0]
    backend._start_step = 720
    backend._start_sim_time = 720 * backend._physics_dt
    backend._world = SimpleNamespace(
        get_physics_dt=lambda: 1 / 120,
        current_time_step_index=backend._start_step,
        current_time=backend._start_sim_time,
    )
    return backend


def test_float32_callback_clock_covers_full_capture_bound():
    backend = clock_only()
    world = backend._world
    for step in range(MAX_SAMPLES):
        backend._check_physics_clock(step)
        world.current_time_step_index += 1
        world.current_time += backend._physics_dt


@pytest.mark.parametrize("change", ["missing_step", "extra_step", "stalled_time", "extra_time", "changed_dt", "nan_time"])
def test_clock_rejects_missing_extra_or_changed_physics(change):
    backend = clock_only()
    world = backend._world
    world.current_time_step_index += 1
    world.current_time += backend._physics_dt
    if change == "missing_step":
        world.current_time_step_index -= 1
    elif change == "extra_step":
        world.current_time_step_index += 1
    elif change == "stalled_time":
        world.current_time -= backend._physics_dt
    elif change == "extra_time":
        world.current_time += backend._physics_dt
    elif change == "changed_dt":
        world.get_physics_dt = lambda: 1 / 60
    else:
        world.current_time = float("nan")
    with pytest.raises(BackendFault, match="exactly one fixed step"):
        backend._check_physics_clock(1)
