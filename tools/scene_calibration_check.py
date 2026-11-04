"""Offline S6-01 calibration diagnostics, outside the protected controller.

These are candidate-policy checks, not a frozen campaign or physical
attestation. Object observations are unsigned simulator readings: replaying the
predicate cannot authenticate their physical origin. No Isaac imports occur.
"""

from math import isfinite, sqrt

from protected_robot_controller import limits as L
from protected_robot_controller.protocol import verify_sign1
from tools.controller_fixture import EvidenceChecker, authenticated_evidence


class CalibrationChecker:
    """Retain one existing signature/context/replay checker across a run.

The S6 fixture's nonzero endpoint-displacement rule is inappropriate for a
stationary axis or a grasp/return segment. Its authenticity checks are reused
unchanged; its complete trace predicate is then applied with zero minimum
displacement and the explicit candidate tracking tolerances.
    """

    def __init__(self, authority_public_key, evidence_public_key, tolerance):
        self._tolerance = tuple(tolerance)
        if (len(self._tolerance) != len(L.OUTPUTS)
                or any(type(value) is not int or value < 0
                       for value in self._tolerance)):
            raise ValueError("Candidate tolerance must contain eight nonnegative integers")
        self._authority = authority_public_key
        self._evidence = evidence_public_key
        self._checker = EvidenceChecker(authority_public_key, evidence_public_key)

    def assess_segment(self, command_bytes, evidence_bytes):
        """Check exact original signed bytes, then describe observed tracking.

Repeated boot/challenge pairs are rejected by the retained S6 checker. A valid
but incomplete capture remains UNKNOWN; available tracking errors remain in
the diagnostics so a preceding deviation is not hidden by missing coverage.
        """
        rejected = {
            "evidence_validation": "REJECTED_EVIDENCE",
            "motion_verdict": None,
            "reasons": ["Signature, command binding, schema or replay check failed"],
            "max_error": None,
            "coverage": None,
        }
        if type(command_bytes) is not bytes or type(evidence_bytes) is not bytes:
            rejected["reasons"] = ["Original signed command and evidence bytes are required"]
            return rejected
        # The existing checker requires positive displacement thresholds. Its
        # movement label is deliberately not used for this candidate policy.
        checked = self._checker.check(
            evidence_bytes, command_bytes, tolerance=self._tolerance,
            minimum_displacement=(1,) * len(L.OUTPUTS),
        )
        if checked == "REJECTED":
            return rejected
        try:
            command = verify_sign1(command_bytes, self._authority)
            evidence = authenticated_evidence(evidence_bytes, self._evidence)
            motion = EvidenceChecker._motion(
                evidence, command, self._tolerance, (0,) * len(L.OUTPUTS),
            )
            diagnostics = _tracking_diagnostics(evidence, command, self._tolerance)
        except Exception:
            return rejected
        verdict = {
            "VERIFIED_SUCCESS": "CONFORMANT",
            "VERIFIED_FAILURE": "DEVIATED",
            "NOT_PROVEN": "UNKNOWN",
        }[motion]
        reasons = ["Original signatures and command/context binding verified; fresh checker context"]
        if verdict == "CONFORMANT":
            reasons.append("Every output in every trajectory and hold row meets the candidate tolerance")
        elif verdict == "DEVIATED":
            reasons.append("Complete valid observations violate initial agreement or candidate tracking tolerance")
        else:
            reasons.append("Incomplete, aborted, invalid or mistimed capture cannot establish full segment motion")
            if diagnostics["captured_tracking_deviation"]:
                reasons.append("Available captured rows already exceed the candidate tracking tolerance")
        return {
            "evidence_validation": "VALID", "motion_verdict": verdict,
            "reasons": reasons, **diagnostics,
        }


def _tracking_diagnostics(evidence, command, tolerance):
    """Report partial errors without substituting targets for observations."""
    rows = evidence["samples"]
    expected_count = 1 + len(command["trajectory"]) + command["hold_steps"]
    targets = [command["initial_positions"]]
    targets.extend(row + [row[6]] for row in command["trajectory"])
    targets.extend([targets[-1]] * command["hold_steps"])
    max_error = [0] * len(L.OUTPUTS)
    comparable_rows = 0
    all_channels_valid = True
    captured_deviation = False
    for index, row in enumerate(rows if type(rows) is list else []):
        if (index >= len(targets) or type(row) is not list or len(row) != 7
                or type(row[5]) is not list or len(row[5]) != len(L.OUTPUTS)
                or any(type(value) is not int for value in row[5])
                or type(row[6]) is not list or len(row[6]) != len(L.OUTPUTS)
                or any(value is not True for value in row[6])):
            all_channels_valid = False
            continue
        errors = [abs(actual - target) for actual, target in zip(row[5], targets[index])]
        max_error = [max(previous, error) for previous, error in zip(max_error, errors)]
        thresholds = command["initial_tolerance"] if index == 0 else tolerance
        captured_deviation |= any(error > limit for error, limit in zip(errors, thresholds))
        comparable_rows += 1
    captured = len(rows) if type(rows) is list else 0
    return {
        "max_error": max_error if comparable_rows else None,
        "max_error_units": list(L.UNITS),
        "captured_tracking_deviation": captured_deviation,
        "coverage": {
            "expected_samples": expected_count,
            "captured_samples": captured,
            "reported_expected_samples": evidence["expected_sample_count"],
            "reported_captured_samples": evidence["sample_count"],
            "comparable_samples": comparable_rows,
            "all_channels_valid": all_channels_valid and captured > 0,
            "terminal_state": evidence["terminal_state"],
            "partial": evidence["partial"],
            "reason": evidence["reason"],
            "count_complete": captured == expected_count,
        },
    }


def _vector(value, count, label):
    if (not isinstance(value, (list, tuple)) or len(value) != count
            or any(type(item) not in (int, float) or not isfinite(item) for item in value)):
        raise ValueError(f"{label} must contain {count} finite numbers")
    return tuple(float(item) for item in value)


def _number(value, label, *, positive=False):
    if (type(value) not in (int, float) or not isfinite(value)
            or value < 0 or (positive and value == 0)):
        raise ValueError(f"{label} must be finite and {'positive' if positive else 'nonnegative'}")
    return float(value)


def _geometry(profile, object_id, destination):
    objects = [obj for obj in profile["objects"] if obj["id"] == object_id]
    if len(objects) != 1:
        raise ValueError("Profile must identify exactly one requested object")
    dimensions = _vector(objects[0]["dimensions_m"], 3, "Object dimensions")
    if any(value <= 0 for value in dimensions):
        raise ValueError("Object dimensions must be positive")
    region = profile["regions"][destination]
    center = _vector(region["center_xy_m"], 2, "Region center")
    half_extents = _vector(region["half_extents_xy_m"], 2, "Region half extents")
    margin = _number(profile["candidate_policy"]["position_margin_m"], "Position margin")
    if any(value <= margin for value in half_extents):
        raise ValueError("Region must exceed its positive interior margin")
    top = profile["work_surface"]["top_z_m"]
    if type(top) not in (int, float) or not isfinite(top):
        raise ValueError("Work surface height must be finite")
    return dimensions, center, half_extents, margin, float(top)


def _box_bounds(observation, object_id, dimensions):
    state = observation["objects"][object_id]
    position = _vector(state["position"], 3, "Object position")
    quaternion = _vector(state["orientation_wxyz"], 4, "Object orientation")
    norm = sqrt(sum(value * value for value in quaternion))
    if abs(norm - 1.0) > 1e-3:
        raise ValueError("Object orientation must be a unit quaternion")
    w, x, y, z = (value / norm for value in quaternion)
    rotation = (
        (1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)),
        (2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)),
        (2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)),
    )
    # The absolute rotation sum is exactly the extrema of all eight OBB
    # corners along each world axis; checking the center alone is insufficient.
    radius = [sum(abs(entry) * size / 2 for entry, size in zip(row, dimensions))
              for row in rotation]
    return tuple(p - r for p, r in zip(position, radius)), tuple(p + r for p, r in zip(position, radius))


def _inside(observation, object_id, geometry):
    dimensions, center, half_extents, margin, top = geometry
    lower, upper = _box_bounds(observation, object_id, dimensions)
    # Margin is a conservative XY inset, and a support-height tolerance. It
    # never expands the declared destination to accommodate a failed placement.
    return (all(lower[axis] >= center[axis] - half_extents[axis] + margin
                and upper[axis] <= center[axis] + half_extents[axis] - margin
                for axis in (0, 1))
            and abs(lower[2] - top) <= margin)


def in_destination(observation, object_id, destination, profile):
    """Check the full oriented box and support height for persistence.

No velocity or contact rule is applied here: this helper checks every observed
placement during the next operation, independently of its final settling test.
Missing or malformed observations cannot establish persistence.
    """
    geometry = _geometry(profile, object_id, destination)
    try:
        return _inside(observation, object_id, geometry)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def assess_objects(observations, object_id, destination, profile):
    """Assess the final contiguous settling interval from retained readings.

The caller removes duplicate boundary observations when joining command
traces. Missing, malformed or discontinuous data yields UNKNOWN. A complete
window that fails geometry, settling or release yields NOT_DELIVERED.
    """
    geometry = _geometry(profile, object_id, destination)
    policy = profile["candidate_policy"]
    required = policy["settling_steps"]
    if type(required) is not int or required < 2:
        raise ValueError("Settling interval must contain at least two physics steps")
    linear_max = _number(policy["linear_speed_max_m_s"], "Linear speed threshold")
    angular_max = _number(policy["angular_speed_max_rad_s"], "Angular speed threshold")
    contact_max = _number(policy["release_contact_max_n"], "Release contact threshold", positive=True)
    coverage = {"required_settling_steps": required, "observed_settling_steps": 0,
                "contiguous": False}

    def result(verdict, reasons):
        return {"object_verdict": verdict, "reasons": reasons, "coverage": coverage}

    if not isinstance(observations, (list, tuple)) or len(observations) < required:
        coverage["observed_settling_steps"] = len(observations) if isinstance(observations, (list, tuple)) else 0
        return result("UNKNOWN", ["Insufficient observations for the full candidate settling interval"])
    window = observations[-required:]
    failures = {"geometry": 0, "linear_speed": 0, "angular_speed": 0, "release": 0}
    previous = None
    try:
        for observation in window:
            step = observation["physics_step"]
            time_ns = observation["simulation_time_ns"]
            if type(step) is not int or step < 0 or type(time_ns) is not int or time_ns < 0:
                raise ValueError("Invalid physics step or simulation timestamp")
            if previous is not None and (step != previous[0] + 1
                    or abs((time_ns - previous[1]) * L.HZ - 1_000_000_000) > 5 * L.HZ):
                raise ValueError("Settling observations must cover successive physics steps and timestamps")
            previous = step, time_ns
            state = observation["objects"][object_id]
            linear = _vector(state["linear_velocity"], 3, "Linear velocity")
            angular = _vector(state["angular_velocity"], 3, "Angular velocity")
            forces = state["finger_forces_n"]
            if not isinstance(forces, (list, tuple)) or len(forces) != 2:
                raise ValueError("Both observed finger/object contact vectors are required")
            contact = [_vector(force, 3, "Finger contact force") for force in forces]
            failures["geometry"] += not _inside(observation, object_id, geometry)
            failures["linear_speed"] += sqrt(sum(value * value for value in linear)) > linear_max
            failures["angular_speed"] += sqrt(sum(value * value for value in angular)) > angular_max
            failures["release"] += any(sqrt(sum(value * value for value in force)) >= contact_max
                                       for force in contact)
            coverage["observed_settling_steps"] += 1
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return result("UNKNOWN", [f"Object observation coverage is invalid: {error}"])
    coverage.update({"contiguous": True, "first_physics_step": window[0]["physics_step"],
                     "last_physics_step": window[-1]["physics_step"], "failed_rows": failures})
    if any(failures.values()):
        explanations = {
            "geometry": "Full object box does not remain inside the destination inset at surface height",
            "linear_speed": "Object linear speed exceeds the candidate settling threshold",
            "angular_speed": "Object angular speed exceeds the candidate settling threshold",
            "release": "Observed finger contact does not establish release",
        }
        return result("NOT_DELIVERED", [f"{explanations[key]} ({count}/{required} rows)"
                                       for key, count in failures.items() if count])
    return result("DELIVERED", ["Full oriented box, surface support, low velocity and release hold throughout the contiguous settling interval"])
