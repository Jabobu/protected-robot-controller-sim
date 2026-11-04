"""One synchronous, bounded authenticated execution; no Isaac dependency.

Only hello() and execute(original_bytes) are peer operations. Construction,
backend references, keys and clocks belong to trusted setup, not to a guest.
Python visibility is not an OS security boundary.
"""

import math
import secrets
import threading
import time
from hashlib import sha256

from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message

from . import limits as L
from .backend import Observation, PrivateBackend
from .protocol import (PROFILE, MAX_EVIDENCE_BYTES, MAX_ROWS, Rejected,
                       encode, verify_sign1, key_id, cose_private)

COMMAND_FIELDS = frozenset({
    "version", "type", "profile", "robot_id", "controller_id", "boot_id", "challenge",
    "execution_id", "sequence", "expires_ns", "config_digest", "authorization_context_digest",
    "actuators", "outputs", "units", "physics_dt", "sample_every_steps", "trajectory",
    "initial_positions", "initial_tolerance", "start_behavior", "hold_steps",
    "velocity_limits", "effort_limits",
})


def _integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def _vector(value, count):
    return type(value) is list and len(value) == count and all(
        _integer(v, -(2**31), 2**31 - 1) for v in value)


class _CaptureFault(Exception):
    pass


class EvidenceUnavailable(RuntimeError):
    """Execution may have occurred; a peer must treat the result as NOT_PROVEN."""


class Controller:
    def __init__(self, authority_public_key, evidence_private_key, backend: PrivateBackend,
                 *, monotonic_ns=time.monotonic_ns):
        # Only one authority key; separate evidence key is mandatory, not a key list.
        self.__authority = authority_public_key
        self.__evidence_id = key_id(evidence_private_key.public_key())
        if key_id(authority_public_key) == self.__evidence_id:
            raise ValueError("Command authority and evidence keys must be separate")
        self.__evidence_key = cose_private(evidence_private_key)
        self.__backend = backend
        self.__clock = monotonic_ns
        self.__boot = secrets.token_bytes(32)
        self.__pending = None
        self.__sequence = 0
        self.__executions = set()
        self.__lock = threading.Lock()
        self.__state = "IDLE"
        self.__last_clock = 0

    @property
    def state(self):
        return self.__state

    def __now(self):
        now = self.__clock()
        if not _integer(now, self.__last_clock, 2**63 - 1):
            raise _CaptureFault("CLOCK")
        self.__last_clock = now
        return now

    def hello(self):
        if not self.__lock.acquire(blocking=False):
            raise Rejected("BUSY")
        try:
            if self.__state in ("ABORTED", "FAULT"):
                raise Rejected("FAULT")
            if len(self.__executions) >= L.MAX_EXECUTIONS:
                raise Rejected("BOOT_EXHAUSTED")
            try:
                now = self.__now()
            except _CaptureFault as error:
                self.__state = "FAULT"
                self.__pending = None
                raise Rejected("CLOCK") from error
            self.__state = "IDLE"
            challenge = secrets.token_bytes(32)
            expiry = now + L.CHALLENGE_NS
            self.__pending = (challenge, expiry)
            return {"version": 1, "type": "HELLO", "profile": PROFILE,
                    "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
                    "boot_id": self.__boot, "challenge": challenge, "expires_ns": expiry,
                    "sequence_floor": self.__sequence, "config_digest": L.CONFIG_DIGEST,
                    "evidence_key_id": self.__evidence_id}
        finally:
            self.__lock.release()

    def __validate(self, command, now):
        if type(command) is not dict or command.keys() != COMMAND_FIELDS:
            raise Rejected("SCHEMA")
        constants = {
            "version": 1, "type": "EXECUTE", "profile": PROFILE,
            "robot_id": L.ROBOT_ID, "controller_id": L.CONTROLLER_ID,
            "config_digest": L.CONFIG_DIGEST, "actuators": list(L.ACTUATORS),
            "outputs": list(L.OUTPUTS), "units": list(L.UNITS), "physics_dt": [1, L.HZ],
            "sample_every_steps": 1, "start_behavior": "IMMEDIATE_IF_MATCH",
            "velocity_limits": list(L.VELOCITY), "effort_limits": list(L.EFFORT),
        }
        for field, value in constants.items():
            # Encoded equality distinguishes true from 1, even in nested arrays.
            if encode(command[field]) != encode(value):
                raise Rejected("CONTEXT" if field not in ("effort_limits", "velocity_limits") else "LIMIT")
        for field, length in (("boot_id", 32), ("challenge", 32), ("execution_id", 16),
                              ("authorization_context_digest", 32)):
            if type(command[field]) is not bytes or len(command[field]) != length:
                raise Rejected("SCHEMA")
        if command["boot_id"] != self.__boot:
            raise Rejected("BOOT")
        if (self.__pending is None or command["challenge"] != self.__pending[0]
                or not _integer(command["sequence"], self.__sequence + 1, 2**63 - 1)
                or command["execution_id"] in self.__executions):
            raise Rejected("REPLAY")
        if (not _integer(command["expires_ns"], 0, self.__pending[1])
                or now >= command["expires_ns"] or now >= self.__pending[1]):
            raise Rejected("EXPIRED")
        initial, tolerance = command["initial_positions"], command["initial_tolerance"]
        trajectory, hold = command["trajectory"], command["hold_steps"]
        if (not _vector(initial, 8) or not _vector(tolerance, 8)
                or any(not lo <= q <= hi for q, lo, hi in zip(initial, L.LOWER, L.UPPER))
                or any(not 0 <= t <= cap for t, cap in zip(tolerance, L.INITIAL_TOLERANCE))
                or not _integer(hold, L.MIN_HOLD_STEPS, L.MAX_HOLD_STEPS)
                or type(trajectory) is not list or not trajectory
                or len(trajectory) + hold > min(MAX_ROWS - 1, L.MAX_DURATION_STEPS)):
            raise Rejected("LIMIT")
        previous = initial[:7]
        for target in trajectory:
            if not _vector(target, 7):
                raise Rejected("LIMIT")
            for q, old, lo, hi, speed in zip(target, previous, L.LOWER, L.UPPER, L.VELOCITY):
                if not lo <= q <= hi or abs(q - old) * L.HZ > speed:
                    raise Rejected("LIMIT")
            previous = target

    def execute(self, original_bytes):
        """Return one signed bundle, or raise Rejected before requested drive writes."""
        if not self.__lock.acquire(blocking=False):
            raise Rejected("BUSY")
        try:
            if self.__state in ("ABORTED", "FAULT"):
                raise Rejected("FAULT")
            command = verify_sign1(original_bytes, self.__authority)
            try:
                now = self.__now()
            except _CaptureFault as error:
                self.__state = "FAULT"
                self.__pending = None
                raise Rejected("CLOCK") from error
            self.__validate(command, now)
            # Atomic consumption occurs before private acquisition and any drive.
            self.__pending = None
            self.__sequence = command["sequence"]
            self.__executions.add(command["execution_id"])
            self.__state = "ACCEPTED"
            return self.__run(command, sha256(original_bytes).digest(), now)
        finally:
            self.__lock.release()

    def __capture(self, rows, initial, started, deadline):
        before = self.__now()
        if before > deadline:
            raise _CaptureFault("OVERRUN")
        reading = (self.__backend.read_initial() if initial else self.__backend.sample_outputs())
        after = self.__now()
        if after > deadline:
            raise _CaptureFault("OVERRUN")
        if not isinstance(reading, Observation):
            raise _CaptureFault("SENSOR")
        positions, valid = tuple(reading.positions), tuple(reading.valid)
        if (len(positions) != 8 or len(valid) != 8 or any(type(v) is not bool for v in valid)
                or any(type(q) not in (int, float) or not math.isfinite(q) or abs(q) > 2148
                       for q in positions)):
            raise _CaptureFault("SENSOR")
        values = [round(q * 1_000_000) for q in positions]
        if any(not _integer(q, -(2**31), 2**31 - 1) for q in values):
            raise _CaptureFault("SENSOR")
        if (not _integer(reading.counter, 0, 2**63 - 1)
                or not _integer(reading.physics_step, 0, 2**63 - 1)
                or not _integer(reading.simulation_time_ns, 0, 2**63 - 1)
                or not _integer(reading.monotonic_time_ns, before, after)
                or after - before > L.MAX_STEP_NS or after - started > L.MAX_RUN_NS):
            raise _CaptureFault("TIMING")
        elapsed = reading.monotonic_time_ns - started
        if rows:
            previous = rows[-1]
            if (reading.counter != previous[1] + 1 or reading.physics_step != previous[2] + 1
                    or abs((reading.simulation_time_ns - previous[3]) * L.HZ - 1_000_000_000) > 5 * L.HZ
                    or elapsed < previous[4]):
                raise _CaptureFault("TIMING")
        # Preserve finite invalid/out-of-envelope observations honestly, then abort.
        rows.append([len(rows), reading.counter, reading.physics_step, reading.simulation_time_ns,
                     elapsed, values, list(valid)])
        if not all(valid):
            raise _CaptureFault("SENSOR")
        if any(not lo - margin <= q <= hi + margin
               for q, lo, hi, margin in zip(values, L.LOWER, L.UPPER, L.OUTPUT_MARGIN)):
            raise _CaptureFault("OUTPUT_LIMIT")
        return values

    def __run(self, command, digest, started):
        rows, reason, terminal = [], "NONE", "COMPLETE"
        try:
            actual = self.__capture(rows, True, started, started + L.MAX_STEP_NS)
            if any(abs(q - expected) > tolerance for q, expected, tolerance in zip(
                    actual, command["initial_positions"], command["initial_tolerance"])):
                raise _CaptureFault("INITIAL_STATE")
            if any(abs(q - target) * L.HZ > speed for q, target, speed in zip(
                    actual, command["trajectory"][0], L.VELOCITY)):
                raise _CaptureFault("INITIAL_SLEW")
            # Recheck the monotonic start window after acquisition, before driving.
            if self.__now() >= command["expires_ns"]:
                raise _CaptureFault("START_EXPIRED")
            self.__state = "RUNNING"
            targets = command["trajectory"] + [command["trajectory"][-1]] * command["hold_steps"]
            for target in targets:
                before = self.__now()
                if len(rows) == 1 and before >= command["expires_ns"]:
                    raise _CaptureFault("START_EXPIRED")
                deadline = min(started + L.MAX_RUN_NS, before + L.MAX_STEP_NS,
                               started + rows[-1][4] + L.MAX_STEP_NS)
                if before >= deadline:
                    raise _CaptureFault("OVERRUN")
                self.__backend.drive(tuple(q / 1_000_000 for q in target),
                                     velocity_limits=tuple(v / 1_000_000 for v in L.VELOCITY),
                                     effort_limits=tuple(v / 1000 for v in L.EFFORT))
                if self.__now() > deadline:
                    raise _CaptureFault("OVERRUN")
                self.__backend.step_physics(deadline_ns=deadline)
                if self.__now() > deadline:
                    raise _CaptureFault("OVERRUN")
                self.__capture(rows, False, started, deadline)
        except _CaptureFault as error:
            terminal, reason = "ABORTED", str(error)
        except Exception:
            terminal, reason = "ABORTED", "BACKEND"
        finally:
            # Even exceptional interruption requests a stop. BaseException itself
            # propagates, so it cannot accidentally produce COMPLETE evidence.
            self.__state = "FAULT"
            stop_deadline = min(started + L.MAX_RUN_NS, self.__last_clock + L.MAX_STEP_NS)
            try:
                self.__backend.stop_or_hold(reason)
                # A returning stop is still part of bounded execution. This
                # cannot preempt a wedged backend; it detects a late return or
                # broken clock without certifying completion after either.
                if self.__now() > stop_deadline:
                    terminal, reason = "ABORTED", "STOP_OVERRUN"
            except _CaptureFault as error:
                terminal, reason = "ABORTED", str(error)
            except Exception:
                terminal, reason = "ABORTED", "STOP_FAILED"
        self.__state = "FAULT" if reason in ("STOP_FAILED", "STOP_OVERRUN", "CLOCK") else terminal
        evidence = {key: command[key] for key in (
            "profile", "robot_id", "controller_id", "boot_id", "challenge", "execution_id",
            "sequence", "config_digest", "authorization_context_digest", "outputs", "units",
            "physics_dt", "sample_every_steps", "hold_steps")}
        evidence.update(version=1, type="EVIDENCE", evidence_key_id=self.__evidence_id,
                        command_digest=digest, samples=rows, sample_count=len(rows),
                        expected_sample_count=1 + len(command["trajectory"]) + command["hold_steps"],
                        terminal_state=terminal, partial=terminal != "COMPLETE", reason=reason)
        try:
            # This is the sole evidence-key operation, fed only the internal trace.
            payload = encode(evidence)
            if len(payload) > MAX_EVIDENCE_BYTES - 256:
                raise ValueError("evidence ceiling")
            message = Sign1Message(phdr={Algorithm: Es256, KID: self.__evidence_id},
                                   uhdr={}, payload=payload, key=self.__evidence_key)
            bundle = message.encode(tag=True)
            if len(bundle) > MAX_EVIDENCE_BYTES:
                raise ValueError("evidence ceiling")
            return bundle
        except Exception:
            self.__state = "FAULT"
            raise EvidenceUnavailable("EVIDENCE_UNAVAILABLE") from None
