# Protected controller protocol contract

The simulation profile `PRC-B601-SIM-1` defines signed commands, evidence and
the controller state machine. The protocol alone does not establish physical
attestation, actual simulator motion, or isolation from a compromised host.

## Dependencies and encoding

`requirements-controller.txt` pins the provisioned versions: cbor2 6.1.5,
pycose 1.1.0, cryptography 46.0.7, and pytest 9.1.1. The implementation uses
[cbor2's canonical encoder and bounded decoder](https://cbor2.readthedocs.io/en/latest/api.html)
and [pycose COSE_Sign1](https://pycose.readthedocs.io/en/latest/pycose/messages/sign1message.html).
The test checker independently verifies ES256 with cryptography.

Both authenticated messages have exactly this COSE_Sign1 encoding:

```
tag 18([protected_bstr, {}, payload_bstr, signature_bstr])
protected_bstr = deterministic_CBOR({1: -7, 4: key_id})
key_id = SHA256(DER SubjectPublicKeyInfo of provisioned P-256 public key)
Sig_structure = ["Signature1", protected_bstr, h'', payload_bstr]
signature_bstr = 32-byte r || 32-byte s (ES256)
```

Tag 18 is mandatory and minimally encoded (`d2`). No unprotected headers,
detached payload, external AAD, negotiated algorithm, extra protected fields,
embedded key, or key list is supported. Exactly one authority public key verifies
commands. The evidence private key must have a different public key. Both keys
are provisioned by trusted construction, never selected by the message peer.

Payloads are definite-length CBOR maps with text keys, canonical length-first
map ordering and shortest integer/length encodings (`cbor2.dumps(canonical=True)`).
The permitted value types are maps, arrays, text, bytes, signed 64-bit integers,
and booleans only where the schema specifies them. No floats (including NaN),
null, semantic tags, duplicate keys, indefinite containers, references, cycles,
nonminimal encodings, invalid UTF-8, trailing bytes, or unknown fields are accepted.
Integers do not accept booleans. Payload/envelope nesting is limited to 8 and
decoded tree visits to 100,000. Payload map keys must be text before insertion.
The sole integer-keyed map is the protected header, matched as fixed bytes.

A small non-decoding framing guard enforces those bounds and rejects semantic
tags/references and non-text keys before calling cbor2. This is necessary because
the pinned 6.1.5 release predates the `strict_hashable_types` option and the later
shared-reference depth fix listed in the [upstream release history](https://cbor2.readthedocs.io/en/latest/versionhistory.html).
Values are still decoded and canonically encoded by cbor2; no cryptographic
primitive is implemented locally.

The entire original command is limited to 65,536 bytes. The entire evidence
bundle is limited to 1,048,576 bytes. Signature verification uses the original
protected header and payload bytes. Canonical re-encoding is an additional
format check, never a replacement for those authenticated bytes. The controller
computes `command_digest = SHA256(original complete tagged COSE command bytes)`,
including its signature. ECDSA signatures need not be deterministic or low-S;
freshness prevents signature variants from authorizing a second execution.

For compatibility with the pinned pair, `verify_sign1` passes a copy of the
strictly decoded and validated envelope to `Sign1Message.from_cose_obj`, with
unknown attributes disabled. It does not use pycose's generic tagged decoder:
[pycose issue 141](https://github.com/TimothyClaeys/pycose/issues/141) documents
that decoder requiring a list while cbor2 6.x returns a tuple for tagged arrays.
The mandatory tag, envelope shape, fixed header bytes and canonical encoding are
all checked first. The parser receives the original protected-header and payload
byte strings, and their equality is checked again before signature verification.
No dependency downgrade, permissive decoder fallback or re-signing is used.

## Peer operations and freshness

Only `Controller.hello()` and `Controller.execute(original_bytes)` are peer
operations. The read-only `state` property is diagnostic. Construction and
Python object access belong to the trusted host, not a transport API. There is
no peer signing, measurement injection, drive, reset, calibration or key method.
Python private attributes are not an OS isolation claim.

`hello()` returns a fresh ordinary map with `version=1`, `type="HELLO"`,
`profile`, `robot_id`, `controller_id`, `boot_id`, `challenge`, `expires_ns`,
`sequence_floor`, `config_digest`, and `evidence_key_id`. This readiness response
is not execution evidence. Boot and challenge are independently generated
32-byte OS-random values. Boot changes on every construction. Only one challenge
is pending; a new HELLO invalidates the old one. Its expiry is five seconds after
issue according to the controller's monotonic nanosecond clock, never wall time.
The authority copies that deadline (or chooses an earlier one) into the command.

Command sequence is an integer in `[1, 2**63-1]`, strictly greater than the last
accepted sequence in this boot. `execution_id` is a unique 16-byte identifier per
boot; the controller retains up to 1,024 accepted IDs, then refuses new HELLOs.
No guest-persisted freshness value is trusted. A nonblocking execution lock also
guards HELLO, so concurrent or reentrant calls return `BUSY` without altering
authorization or issuing a drive. Restart requires a fresh boot/challenge.

Pre-execution refusal raises `Rejected` with a bounded code: `SIZE`, `MALFORMED`,
`HEADERS`, `SIGNATURE`, `SCHEMA`, `CONTEXT`, `LIMIT`, `BOOT`, `REPLAY`, `EXPIRED`,
`BUSY`, `FAULT`, `CLOCK`, or `BOOT_EXHAUSTED`. It does not claim execution.
Rejected commands issue zero requested drive writes. A transport may serialize
this as a REJECT; it must not expose exception internals. A post-execution
`EvidenceUnavailable` is a distinct error: movement may have occurred and the
result is NOT_PROVEN, never a pre-execution REJECT or a success assertion.

## Exact EXECUTE payload

Every field is required; extra fields are rejected. Arrays have fixed order.

| Field | Required value or meaning |
| --- | --- |
| `version`, `type`, `profile` | `1`, `"EXECUTE"`, `"PRC-B601-SIM-1"` |
| `robot_id`, `controller_id` | `"b601-rs-dev"`, `"prc-dev-1"` |
| `boot_id`, `challenge` | Current 32-byte controller values |
| `execution_id`, `sequence`, `expires_ns` | Unique 16 bytes; increasing sequence; controller-monotonic exclusive start deadline |
| `config_digest` | SHA-256 of deterministic CBOR of `limits.configuration()` |
| `authorization_context_digest` | Opaque 32-byte upstream binding, never interpreted as policy |
| `actuators` | `joint1` through `joint6`, then `gripper` |
| `outputs` | `joint1` through `joint6`, then `joint_left`, `joint_right` |
| `units` | Six `"urad"` entries, then two `"um"` entries |
| `physics_dt`, `sample_every_steps` | `[1, 120]` seconds, `1` |
| `initial_positions`, `initial_tolerance` | Eight int32 output expectations and eight nonnegative int32 tolerances |
| `start_behavior` | `"IMMEDIATE_IF_MATCH"` only |
| `trajectory` | Nonempty array of seven-int32 actuator target rows, one per physics step |
| `hold_steps` | 12 through 240 repeated final-target steps, all sampled |
| `velocity_limits` | `[500000,500000,500000,500000,500000,500000,40000]` in urad/s or um/s |
| `effort_limits` | `[36000,36000,36000,14000,14000,14000,12000]` in mN*m or mN |

One gripper target means left-finger outward travel. The mechanically coupled
right finger is measured independently and is not a second commanded actuator.
No command-time effort/velocity customization is implemented: the signed arrays
must equal the fixed local settings, including when a caller requests a lower
cap. This avoids silently using a different drive cap than the authority signed.

All command positions must be within the protected integer bounds below. Every
transition, including the signed initial expectation to the first target, must
satisfy `abs(delta) * 120 <= local_velocity_limit`. Actual initial output must
match the signed expectation and independently satisfy the first-target slew
bound. It is sampled only after authorization consumption. Mismatch gives honest
ABORTED evidence with no requested drive, and does not restore authorization.

| Output | Minimum | Maximum | Maximum initial tolerance | Observed boundary margin |
| --- | ---: | ---: | ---: | ---: |
| joint1 | -2799999 | 2799999 | 50000 | 10000 |
| joint2 | -3140000 | 0 | 50000 | 10000 |
| joint3 | -3140000 | 0 | 50000 | 10000 |
| joint4 | -1790000 | 1689999 | 50000 | 10000 |
| joint5 | -1570000 | 1570000 | 50000 | 10000 |
| joint6 | -3140000 | 3140000 | 50000 | 10000 |
| joint_left / joint_right | 0 | 50000 | 2000 | 1000 |

These values round command bounds inward from the model manifest. The
configuration digest includes that manifest's SHA-256, order, units, all limits,
sampling, deadline and stop policies. `test_limits_pin_existing_model_manifest`
checks the pin and conservative limits against the actual file. Observed margins
accommodate solver excursions; they do not enlarge command limits. Samples are
never clamped. Finite observations outside the margin are retained and abort.

Total trajectory plus hold is at most 3,600 steps (30 simulated seconds). Thus
the profile is stricter than the global 4,097-row and 16-channel ceilings: it
uses at most 3,601 rows and exactly eight observed channels. Raw command size
can impose a tighter workload bound. Initial acquisition is limited to two wall
seconds. Each drive/physics/acquisition cycle shares a two-second deadline,
also bounded relative to the previous observation; the complete run has a
120-second wall deadline, including the terminal stop/hold. A returning stop
must also finish within two seconds of the last trusted clock observation.
Late stop return produces `STOP_OVERRUN`; clock regression produces `CLOCK`.
Both latch FAULT and yield ABORTED/partial evidence even if every motion sample
was captured. The private adapter must enforce deadlines internally;
Python cannot preempt a wedged native backend. An external hardware watchdog is
a later physical requirement, not a claimed simulation feature.

## Execution and evidence

State is `IDLE -> ACCEPTED -> RUNNING -> COMPLETE`, or `ACCEPTED/RUNNING ->
ABORTED`. Signature, address, schema, config, freshness, trajectory and local
limits are checked before ACCEPTED. Challenge/sequence/execution ID are consumed
under the lock before reading outputs or driving. Expiry is checked again at
the first-drive boundary. No new peer setpoint is read during execution.

The private backend contract is in `protected_robot_controller/backend.py`:
fresh `read_initial`, capped `drive`, `step_physics(deadline_ns=...)`, private
`sample_outputs`, and `stop_or_hold(reason)`. It supplies `Observation` objects
with eight physical-unit outputs, validity, counters and clocks. Unit doubles
live only in tests. The PhysX adapter implements this contract with a fresh
initial acquisition, protected drive caps, copied samples and a capped terminal
hold. See [SCENE_INTERFACE.md](SCENE_INTERFACE.md) and [TESTING.md](TESTING.md)
for the byte interface and physics tests.

Each observation is copied immediately, converted from radians/metres to
urad/um using nearest rounding with ties to even, and checked for finite int32
range. Values beyond the conversion range produce a partial trace, not overflow
or saturation. Simulation timestamps are measured values, not reconstructed
from targets. Counter and physics step must increase by one; simulation time
increments must match 1/120 s within 5 ns (accounting for clock quantization).
Acquisition time must lie within the trusted read interval and cannot regress.
Malformed or missing observations are not backfilled. Finite samples with false
validity are retained as such and terminate capture.

Normal execution samples the final hold interval and requests a protected capped
hold. Faults, deadline failures and sensor errors also request that stop/hold,
retain the captured prefix and produce ABORTED evidence when signing works.
ABORTED is latched; there is no peer reset. Stop failure produces `STOP_FAILED`,
late stop produces `STOP_OVERRUN`, and clock faults produce `CLOCK`; each latches
FAULT. Signing failure also latches FAULT. Trusted recovery constructs
a new controller with a new boot after restoring a safe backend. COMPLETE allows
a new HELLO and a fresh private initial acquisition.

Exactly one complete or honestly partial trace is signed per accepted execution.
The EVIDENCE payload contains:

- `version=1`, `type="EVIDENCE"`, and the provisioned `evidence_key_id`.
- The accepted `profile`, `robot_id`, `controller_id`, `boot_id`, `challenge`,
  `execution_id`, `sequence`, `config_digest`, `authorization_context_digest`,
  `outputs`, `units`, `physics_dt`, `sample_every_steps` and `hold_steps`.
- `command_digest`, computed from original complete command bytes.
- `samples`, `sample_count`, and `expected_sample_count` (initial + targets + hold).
- `terminal_state` (`COMPLETE` or `ABORTED`), `partial` boolean, and `reason`.

Each sample is exactly `[index, backend_counter, physics_step,
simulation_time_ns, acquisition_elapsed_ns, eight_int32_positions,
eight_boolean_validity_flags]`. Elapsed time is relative to command acceptance.
Fault reasons are bounded literals: `NONE`, `SENSOR`, `TIMING`, `OUTPUT_LIMIT`,
`INITIAL_STATE`, `INITIAL_SLEW`, `START_EXPIRED`, `CLOCK`, `OVERRUN`, `BACKEND`,
`STOP_FAILED`, or `STOP_OVERRUN`. The payload has no task-success field.

## Test signer, checker and reproduction

`tools/controller_fixture.py` creates an ephemeral command authority and a
separate evidence key in memory, assembles development commands, signs them, and
checks evidence against the exact expected command retained by the trusted
runner. The controller never imports this module or sees expected verdicts.

The checker independently verifies the original evidence Sig_structure and
signature, all command/context bindings, and consumes a boot/challenge once.
It requires complete valid timing/count/channel coverage, checks every trajectory
row and final-hold row, and requires nonzero displacement on all eight outputs.
Thresholds are trusted runner inputs, never received from evidence. Its results
are `REJECTED` (signature/context/replay), `NOT_PROVEN` (missing/aborted/invalid
capture), `VERIFIED_FAILURE` (authentic complete observations fail movement
checks), or `VERIFIED_SUCCESS`. A stationary but authenticated trace can therefore
be verified failure despite terminal COMPLETE. Unit verdicts do not count as
Isaac normal or obstructed movement evidence.

Unit defaults are 2,000 urad / 200 um tracking tolerance and 1,000 urad / 100 um
minimum displacement, both below the complete test trajectory's excursion.
A partial movement followed by a stall is tested separately from zero motion.
Use tolerances justified by the actual physics runs.

Run the controller tests using the command and prerequisites in
[TESTING.md](TESTING.md). Replay retained vectors without the backend or private
keys with `python -m tools.controller_fixture "$PRC_VECTOR_DIRECTORY"`.
The verifier rejects missing or altered vectors. A verified vector alone does
not establish a physical or simulator motion result.
