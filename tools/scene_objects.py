"""Offline object predicates for retained direct simulator observations.

This module needs only the standard library. Object replay is not sensor
authentication: these unsigned readings are independent of signed joint motion.
The final window is anchored to an endpoint retained independently of its data.
"""

import argparse
import json
from math import hypot, isclose, isfinite
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "scenes/manipulation/evidence_policy.json"
DEFAULT_PROFILE = ROOT / "scenes/manipulation/profile.json"
PHYSICS_HZ = 120
SENSOR_NOTE = ("Object replay evaluates unsigned direct simulator observations; "
               "it is not sensor authentication or physical attestation.")


def _vector(value, count, label):
    if (type(value) not in (list, tuple) or len(value) != count
            or any(type(item) not in (int, float) or not isfinite(item)
                   for item in value)):
        raise ValueError(f"{label} must contain {count} finite numbers")
    return tuple(float(item) for item in value)


def _number(value, label, *, positive=False):
    if (type(value) not in (int, float) or not isfinite(value)
            or value < 0 or (positive and value == 0)):
        raise ValueError(f"{label} must be finite and {'positive' if positive else 'nonnegative'}")
    return float(value)


def _settings(profile, policy, object_id, destination):
    if type(object_id) is not str or type(destination) is not str:
        raise ValueError("Object and destination identifiers must be strings")
    rules = policy["objects"]
    intervals = rules["settling_intervals"]
    tolerance = rules["simulation_time_tolerance_ns"]
    if type(intervals) is not int or intervals <= 0:
        raise ValueError("Settling intervals must be a positive integer")
    if type(tolerance) is not int or not 0 <= tolerance <= 5:
        raise ValueError("Simulation time tolerance must be an integer from zero to five ns")
    margin = _number(rules["position_margin_m"], "Position margin", positive=True)
    linear_max = _number(rules["linear_speed_max_m_s"], "Linear speed threshold")
    angular_max = _number(rules["angular_speed_max_rad_s"], "Angular speed threshold")
    contact_max = _number(rules["release_contact_max_n"], "Contact threshold", positive=True)
    for dt in (profile["physics"]["dt_seconds"], profile["runtime"]["physics_dt_seconds"]):
        if not isclose(_number(dt, "Physics interval", positive=True),
                       1 / PHYSICS_HZ, rel_tol=0, abs_tol=1e-15):
            raise ValueError("Object replay requires the fixed 120 Hz physics profile")
    matches = [obj for obj in profile["objects"] if obj["id"] == object_id]
    if len(matches) != 1:
        raise ValueError("Profile must identify exactly one requested object")
    if matches[0]["shape"] != "cuboid":
        raise ValueError("Object predicate supports the authored cuboids only")
    dimensions = _vector(matches[0]["dimensions_m"], 3, "Object dimensions")
    if any(size <= 0 for size in dimensions):
        raise ValueError("Object dimensions must be positive")
    region = profile["regions"][destination]
    center = _vector(region["center_xy_m"], 2, "Region center")
    extents = _vector(region["half_extents_xy_m"], 2, "Region half extents")
    if any(size <= margin for size in extents):
        raise ValueError("Region extents must exceed the interior margin")
    if not all(isfinite(value) for axis in (0, 1)
               for value in (center[axis] - extents[axis] + margin,
                             center[axis] + extents[axis] - margin)):
        raise ValueError("Destination bounds must remain finite")
    top = profile["work_surface"]["top_z_m"]
    if type(top) not in (int, float) or not isfinite(top):
        raise ValueError("Support height must be finite")
    geometry = dimensions, center, extents, margin, float(top)
    return geometry, intervals, tolerance, linear_max, angular_max, contact_max


def _inside(state, geometry):
    dimensions, center, extents, margin, top = geometry
    position = _vector(state["position"], 3, "Object position")
    quaternion = _vector(state["orientation_wxyz"], 4, "Object orientation")
    norm = hypot(*quaternion)
    if abs(norm - 1) > 1e-3:
        raise ValueError("Object orientation must be a unit quaternion")
    w, x, y, z = (value / norm for value in quaternion)
    rotation = (
        (1 - 2 * (y*y + z*z), 2 * (x*y - z*w), 2 * (x*z + y*w)),
        (2 * (x*y + z*w), 1 - 2 * (x*x + z*z), 2 * (y*z - x*w)),
        (2 * (x*z - y*w), 2 * (y*z + x*w), 1 - 2 * (x*x + y*y)),
    )
    # Absolute rotation sums give the extrema of all eight OBB corners. Thus
    # full-box containment is checked even when the center lies in the region.
    radius = tuple(sum(abs(entry) * size / 2 for entry, size in zip(row, dimensions))
                   for row in rotation)
    lower = tuple(p-r for p, r in zip(position, radius))
    upper = tuple(p+r for p, r in zip(position, radius))
    if not all(isfinite(value) for value in lower + upper):
        raise ValueError("Object bounds must remain finite")
    return (all(lower[axis] >= center[axis] - extents[axis] + margin
                and upper[axis] <= center[axis] + extents[axis] - margin
                for axis in (0, 1))
            and abs(lower[2] - top) <= margin)


def in_destination(observation, object_id, destination, profile, policy):
    """Check full oriented-box membership and support height, for persistence.

    Velocity and release are intentionally not membership predicates. Missing
    or malformed geometry cannot establish this observation of persistence.
    """
    try:
        geometry = _settings(profile, policy, object_id, destination)[0]
        return _inside(observation["objects"][object_id], geometry)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def assess_objects(observations, object_id, destination, profile, policy, *, end_step, end_time_ns):
    """Replay object delivery independently of evidence validity and motion.

    The final N intervals require N+1 contiguous observations, inclusive of the
    explicitly retained endpoint. Prefix gaps are allowed; duplicate or reversed
    timestamps/steps are not. Missing, malformed or incomplete final data gives
    UNKNOWN. A complete window failing a predicate gives NOT_DELIVERED.
    """
    coverage = {"required_settling_intervals": None, "required_observations": None,
                "supplied_observations": len(observations) if type(observations) in (list, tuple) else 0,
                "observed_settling_observations": 0, "observed_settling_intervals": 0,
                "contiguous": False, "endpoint_present": False}
    failures = {"geometry": 0, "linear_speed": 0, "angular_speed": 0, "release": 0}

    def result(verdict, reasons):
        return {"object_verdict": verdict, "sensor_authenticated": False,
                "sensor_note": SENSOR_NOTE, "reasons": reasons,
                "coverage": coverage, "failures": failures}

    try:
        geometry, intervals, tolerance, linear_max, angular_max, contact_max = _settings(
            profile, policy, object_id, destination)
        required = intervals + 1
        coverage.update(required_settling_intervals=intervals, required_observations=required)
        if (type(end_step) is not int or end_step < 0
                or type(end_time_ns) is not int or end_time_ns < 0):
            raise ValueError("Explicit nonnegative integer endpoint step and time are required")
        coverage.update(end_step=end_step, end_time_ns=end_time_ns)
        if type(observations) not in (list, tuple) or len(observations) < required:
            return result("UNKNOWN", ["Insufficient observations for the full final settling interval"])
        previous = None
        for observation in observations:
            step, time_ns = observation["physics_step"], observation["simulation_time_ns"]
            if type(step) is not int or step < 0 or type(time_ns) is not int or time_ns < 0:
                raise ValueError("Physics steps and simulation timestamps must be nonnegative integers")
            if previous is not None and (step <= previous[0] or time_ns <= previous[1]):
                raise ValueError("Object observations must have ordered unique physics steps and timestamps")
            previous = step, time_ns
        if previous != (end_step, end_time_ns):
            raise ValueError("Final object observation does not match the independently retained endpoint")
        coverage["endpoint_present"] = True
        window = observations[-required:]
        previous = None
        for observation in window:
            step, time_ns = observation["physics_step"], observation["simulation_time_ns"]
            if previous is not None and (step != previous[0] + 1
                    or abs((time_ns - previous[1]) * PHYSICS_HZ - 1_000_000_000)
                    > tolerance * PHYSICS_HZ):
                raise ValueError("Final settling observations must cover consecutive physics steps and timestamps")
            # The protocol's 5 ns allowance is per measured increment. PhysX
            # float timestep representation can accumulate a small offset; no
            # separate cumulative drift threshold is defined by this policy.
            state = observation["objects"][object_id]
            inside = _inside(state, geometry)
            linear = _vector(state["linear_velocity"], 3, "Linear velocity")
            angular = _vector(state["angular_velocity"], 3, "Angular velocity")
            forces = state["finger_forces_n"]
            if type(forces) not in (list, tuple) or len(forces) != 2:
                raise ValueError("Both independent finger/object contact vectors are required")
            contact = tuple(_vector(force, 3, "Finger contact force") for force in forces)
            failures["geometry"] += not inside
            failures["linear_speed"] += hypot(*linear) > linear_max
            failures["angular_speed"] += hypot(*angular) > angular_max
            failures["release"] += any(hypot(*force) >= contact_max for force in contact)
            coverage["observed_settling_observations"] += 1
            coverage["observed_settling_intervals"] += previous is not None
            previous = step, time_ns
        coverage.update(contiguous=True, first_physics_step=window[0]["physics_step"],
                        last_physics_step=window[-1]["physics_step"])
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return result("UNKNOWN", [f"Object policy, geometry or observation coverage is invalid: {error}"])
    descriptions = {
        "geometry": "Full object box does not remain inside the destination inset at support height",
        "linear_speed": "Linear speed exceeds the frozen settling threshold",
        "angular_speed": "Angular speed exceeds the frozen settling threshold",
        "release": "At least one finger contact force does not establish release",
    }
    if any(failures.values()):
        return result("NOT_DELIVERED", [f"{descriptions[key]} ({count}/{required} observations)"
                                        for key, count in failures.items() if count])
    return result("DELIVERED", ["Full oriented box, support height, low velocity and release satisfy the frozen predicate throughout the final contiguous settling interval"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--object-id", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--end-step", type=int, required=True)
    parser.add_argument("--end-time-ns", type=int, required=True)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args(argv)
    try:
        result = assess_objects(json.loads(args.observations.read_text()), args.object_id,
                                args.destination, json.loads(args.profile.read_text()),
                                json.loads(args.policy.read_text()), end_step=args.end_step,
                                end_time_ns=args.end_time_ns)
    except (OSError, ValueError) as error:
        result = {"object_verdict": "UNKNOWN", "sensor_authenticated": False,
                  "sensor_note": SENSOR_NOTE, "reasons": [f"Cannot read replay inputs: {error}"],
                  "coverage": None, "failures": None}
    print(json.dumps(result, indent=2, allow_nan=False))
    return 2 if result["object_verdict"] == "UNKNOWN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
