"""Protected B601 simulation envelope, independent of Isaac imports.

Integer limits round inward from the pinned model. These are simulation limits,
not certified hardware ratings. No command can configure them.
"""

from hashlib import sha256

from .protocol import encode, PROFILE, MAX_ROWS

ROBOT_ID = "b601-rs-dev"
CONTROLLER_ID = "prc-dev-1"
ACTUATORS = tuple(f"joint{i}" for i in range(1, 7)) + ("gripper",)
OUTPUTS = ACTUATORS[:6] + ("joint_left", "joint_right")
UNITS = ("urad",) * 6 + ("um", "um")
LOWER = (-2_799_999, -3_140_000, -3_140_000, -1_790_000, -1_570_000, -3_140_000, 0, 0)
UPPER = (2_799_999, 0, 0, 1_689_999, 1_570_000, 3_140_000, 50_000, 50_000)
VELOCITY = (500_000,) * 6 + (40_000,)
EFFORT = (36_000,) * 3 + (14_000,) * 3 + (12_000,)  # mN*m, mN
INITIAL_TOLERANCE = (50_000,) * 6 + (2_000, 2_000)
OUTPUT_MARGIN = (10_000,) * 6 + (1_000, 1_000)
HZ = 120
MIN_HOLD_STEPS = 12
MAX_HOLD_STEPS = 240
MAX_DURATION_STEPS = 30 * HZ
CHALLENGE_NS = 5_000_000_000
MAX_STEP_NS = 2_000_000_000
MAX_RUN_NS = 120_000_000_000
MAX_EXECUTIONS = 1024  # Bounds the per-boot execution-ID history.
MODEL_MANIFEST_SHA256 = "a60229daf5abb39f147046d736b103752c592f7f29792405bbd5fe8b29605193"


def configuration():
    return {
        "profile": PROFILE, "robot_id": ROBOT_ID, "controller_id": CONTROLLER_ID,
        "model_manifest_sha256": bytes.fromhex(MODEL_MANIFEST_SHA256),
        "actuators": list(ACTUATORS), "outputs": list(OUTPUTS), "units": list(UNITS),
        "position_lower": list(LOWER), "position_upper": list(UPPER),
        "velocity_limits": list(VELOCITY), "effort_limits": list(EFFORT),
        "initial_tolerance_max": list(INITIAL_TOLERANCE), "output_margin": list(OUTPUT_MARGIN),
        "physics_dt": [1, HZ], "min_hold_steps": MIN_HOLD_STEPS,
        "max_hold_steps": MAX_HOLD_STEPS, "max_duration_steps": MAX_DURATION_STEPS,
        "max_rows": MAX_ROWS, "challenge_ns": CHALLENGE_NS, "max_step_ns": MAX_STEP_NS,
        "max_run_ns": MAX_RUN_NS, "max_executions": MAX_EXECUTIONS,
        "stop_policy": "BOUNDED_HOLD", "start_behavior": "IMMEDIATE_IF_MATCH",
        "position_scale": 1_000_000, "rounding": "NEAREST_TIES_EVEN",
    }


CONFIG_DIGEST = sha256(encode(configuration())).digest()
