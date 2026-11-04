"""Pure target-bound validation only; never counted as PhysX evidence."""

import math

import pytest

from protected_robot_controller.simulation._backend import SETUP_TARGET, _IsaacRobotBackend
from protected_robot_controller.simulation.model import read_manifest


@pytest.fixture
def limits_only():
    # No World, robot, sensor, or mock physics. Exercise the numeric preflight.
    backend = _IsaacRobotBackend.__new__(_IsaacRobotBackend)
    manifest = read_manifest()
    backend._channels = manifest["channels"]
    backend._dt = manifest["runtime"]["physics_dt_seconds"]
    return backend


@pytest.mark.parametrize("index", range(7))
def test_target_envelope_rejects_every_actuator(limits_only, index):
    channel = limits_only._channels[index]
    for invalid in [math.nan, math.inf, -math.inf, True,
                    channel["position_limits"][0] - 1e-6,
                    channel["position_limits"][1] + 1e-6]:
        target = list(SETUP_TARGET)
        target[index] = invalid
        with pytest.raises(ValueError):
            limits_only._validate_targets(target, SETUP_TARGET)


@pytest.mark.parametrize("index", range(7))
def test_target_speed_bound_is_per_physics_step(limits_only, index):
    max_delta = limits_only._channels[index]["max_velocity"] * limits_only._dt
    target = list(SETUP_TARGET)
    target[index] += max_delta
    limits_only._validate_targets(target, SETUP_TARGET)
    target[index] += 1e-6
    with pytest.raises(ValueError, match="speed"):
        limits_only._validate_targets(target, SETUP_TARGET)


@pytest.mark.parametrize("count", [6, 8])
def test_target_requires_seven_independent_actuators(limits_only, count):
    with pytest.raises(ValueError, match="six arm"):
        limits_only._validate_targets([0.0] * count, SETUP_TARGET)
