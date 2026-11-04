# Scene integration handoff — PRC byte interface

PRC uses `protected_robot_controller.interface.ControllerInterface` without
new controller messages. Trusted setup constructs
`Controller(authority_public_key, evidence_private_key, private_backend)` and
then `ControllerInterface(controller)`. A client receives only
`ControllerInterface.handle(request: bytes) -> bytes`. Execution is synchronous.
Scene planning, faults, object observations and verdicts belong to fixture and
offline checker tools, never to the controller. This in-process simulation
interface establishes neither physical attestation nor isolation from host root.

The machine-readable summary below is checked against the existing API by the
interface regression. Full signed schemas and rejection rules remain in
[PROTOCOL_CONTRACT.md](PROTOCOL_CONTRACT.md).

<!-- controller-interface-contract-v1 -->
```json
{
  "implementation": "protected_robot_controller.interface.ControllerInterface",
  "entry_point": "handle(request: bytes) -> bytes",
  "request_types": ["HELLO", "EXECUTE"],
  "response_types": ["HELLO", "EVIDENCE", "REJECTED", "UNAVAILABLE"],
  "retrieve_supported": false,
  "max_command_bytes": 65536,
  "max_evidence_bytes": 1048576,
  "max_request_bytes": 65664,
  "max_response_bytes": 1048704,
  "profile": "PRC-B601-SIM-1",
  "robot_id": "b601-rs-dev",
  "controller_id": "prc-dev-1",
  "actuators": ["joint1", "joint2", "joint3", "joint4", "joint5", "joint6", "gripper"],
  "outputs": ["joint1", "joint2", "joint3", "joint4", "joint5", "joint6", "joint_left", "joint_right"],
  "units": ["urad", "urad", "urad", "urad", "urad", "urad", "um", "um"],
  "physics_dt": [1, 120],
  "sample_every_steps": 1
}
```

## Trusted identities and readiness

Trusted setup provisions exactly one P-256 command-authority public key and a
different P-256 evidence private key. The development fixture creates both key
pairs in memory with `tools.controller_fixture.development_keys()`. The authority
private key remains with the test client; the controller receives only its public
key. Only the controller's evidence key signs execution reports. No private key
is retained in an archive. The public key identifier is SHA-256 of DER
SubjectPublicKeyInfo, not a peer-selected identity. A verifier should obtain both
public keys and the expected configuration from trusted setup independently of
the returned report. Archive-supplied development keys establish consistency,
not certified identity.

Use `protected_robot_controller.protocol.encode` for canonical CBOR and retain
the returned bytes unchanged. These are the only request maps, with no additional
fields:

```python
hello_request = encode({"version": 1, "type": "HELLO"})
execute_request = encode({"version": 1, "type": "EXECUTE", "command": signed_command_bytes})
```

HELLO returns an unsigned map containing `version`, `type`, `profile`, `robot_id`,
`controller_id`, `boot_id`, `challenge`, `expires_ns`, `sequence_floor`,
`config_digest` and `evidence_key_id`. It is readiness context, not execution
evidence. Boot and challenge are 32 bytes each; a new HELLO replaces the previous
challenge. Its five-second expiry uses the controller's monotonic nanosecond
clock. Do not interpret it as UTC or compare it with a remote wall clock.

Copy the current boot/challenge into a fresh command, choose a unique 16-byte
`execution_id`, and choose `sequence > sequence_floor`. The scene client uses
`sequence_floor + 1`. Copy `expires_ns` or choose an earlier start deadline. The
controller consumes challenge, sequence and execution ID before private initial
acquisition or actuator writes. Concurrent calls return `REJECTED/BUSY`; after
1,024 accepted execution IDs this boot returns `BOOT_EXHAUSTED` on HELLO.
Constructing a new controller creates a new boot identity.

## Signed input and bounded execution

The `command` byte string is the complete tagged COSE_Sign1 ES256 message:
canonical protected headers `{1: -7, 4: authority_key_id}`, empty unprotected
headers, canonical CBOR payload, and 64-byte `r || s` signature. Tag 18 is
required. The parser forbids unknown fields, detached payload, external AAD,
floats, duplicate keys and noncanonical encodings. Signing covers the original
protected-header and payload bytes. The evidence binds
`SHA256(original_complete_command_bytes)`, including the command signature.

`tools.controller_fixture.command_for(hello, initial, trajectory,
hold_steps=...)` constructs the development payload; `sign_command(payload,
authority_private_key)` signs it. The client supplies eight integer initial
expectations/tolerances, seven integer actuator targets for every physics step,
and the exact fixed velocity/effort arrays. It must supply the current
configuration digest, output order, units and identities from
`protected_robot_controller.limits`. `authorization_context_digest` is an opaque
32-byte value. Scene example bindings include the semantic security configuration,
model manifest and predetermined run and operation plan. Existing v2 bindings
retain runtime provenance separately. New example runs use v3, which additionally
binds the hash of declared runtime metadata through the signed command. The
runtime identity is a trusted-host assertion, not attestation. A source inventory
or supplied source fingerprint is retained; record the scene release commit
separately as part of the handoff. The controller treats the context as opaque
and does not interpret object IDs or task outcomes.

The seven commanded actuators are joint1–joint6 and one coupled gripper. The
eight independently sampled outputs include both fingers. Arm integers are
microradians; finger integers are micrometres. The gripper target means one
finger's outward travel, not total opening. Conversion from measured physical
units uses nearest, ties-even rounding. There is no camera input or peer sensor
injection method.

The command is limited to 65,536 bytes and the outer request to 65,664 bytes.
Each command has a nonempty trajectory, 12–240 hold steps, at most 3,600 total
trajectory-plus-hold steps, and at most 3,601 captured rows including the initial
sample. The global format ceiling is 4,097 rows and 16 channels; this profile
uses eight channels at 120 Hz, one sample per physics step. Arm target slew is
0.5 rad/s and gripper slew 0.04 m/s. Effort caps are 36/36/36/14/14/14 N·m and
12 N; signed velocity/effort arrays must equal the fixed configuration, even if
the caller proposes a lower cap. Initial, transition and position bounds are
specified in `limits.py` and [PROTOCOL_CONTRACT.md](PROTOCOL_CONTRACT.md).

Each private acquisition/drive/step cycle has a two-second wall deadline; total
execution has a 120-second wall deadline and at most 30 simulated seconds.
Initial output must match the signed expectation and first-target slew bound.
An accepted command that fails initial acquisition or matching is consumed and
returns honest abort evidence where signing remains possible. There is no new
client setpoint or task-success input during execution.

## Returned bytes, invalid requests and partial evidence

| Response | Meaning and client action |
| --- | --- |
| `{"version":1,"type":"EVIDENCE","evidence": report_bytes}` | Retain original report and command bytes plus trusted context; independently verify them. The report is at most 1,048,576 bytes; the outer response at most 1,048,704 bytes. |
| `{"version":1,"type":"REJECTED","reason": code}` | Request/authorization refused before requested drive writes. The response is unsigned and is not execution evidence. |
| `{"version":1,"type":"UNAVAILABLE","reason":"EVIDENCE_UNAVAILABLE"}` | Execution may have occurred but a signed report is unavailable. Do not infer success or safe nonexecution. |

Signed EVIDENCE binds the accepted command digest, identities, boot/challenge,
execution ID, sequence, configuration and opaque authorization context. It retains
samples, expected/captured counts, output order/units, sampling, `terminal_state`,
`partial` and `reason`. Each sample includes measured physics step/time,
acquisition elapsed time, backend counter, eight positions and eight validity
flags. `COMPLETE` describes capture, not successful movement. An authentic
`ABORTED`/partial report is still useful evidence of its captured prefix; it
cannot establish complete motion. Missing readings are never filled from targets.

ABORTED and FAULT latch; there is no peer reset. Stop/signing/clock errors may
latch FAULT. Trusted recovery first restores a safe backend and then constructs
a new controller, producing a fresh boot. A COMPLETE controller may receive a
new HELLO and perform another fresh initial acquisition. Normal scene operations
share the same controller and physical scene without reset.

Offline tools keep `evidence_validation`, `motion_verdict` and `object_verdict`
separate. Valid authentication may accompany CONFORMANT, DEVIATED or UNKNOWN
motion. Rejected evidence has a null motion verdict. Object delivery is evaluated
separately from unsigned direct simulator observations; its replay does not
authenticate sensor truth. Neither an image nor a COMPLETE report proves delivery.

## Retrieval and archive handoff

There is **no RETRIEVE request** in `ControllerInterface`. For example,
`encode({"version": 1, "type": "RETRIEVE"})` returns
`{"version": 1, "type": "REJECTED", "reason": "REQUEST"}`. The adapter has no
report store, transport or durable retrieval method. Resubmitting an accepted
EXECUTE is a replay rejection, not retrieval, and requesting HELLO invalidates
the pending challenge. If the synchronous response is lost, this API cannot
recover it; the client must retain original returned bytes before proceeding.

The scene runner implements file retention outside the controller. Verify the
retained `run.json` and every `files` entry before reading each segment's
`command`, `report` and
`public_context`. Preserve HELLO, outer request/response, public DER keys,
configuration, profile/program/policy/model snapshots, full reference/measured
traces, object observations, counts, partial reasons, stop diagnostics and the
predetermined operation plan. Keep failures and original signed bytes, including
repository-relative paths under `artifacts/scene-work/`. Run
`python -m tools.scene_check --help` for replay arguments. The replay accepts historical v2 archives under their original image pin. For new
v3 archives, pass `--expected-runtime native` or the full expected local container
image ID to `tools.scene_check` or `tools.scene_evidence`. Select that expectation
through trusted setup, not from the archive being checked. Historical v1 archives
require their original verifier. Offline replay needs neither private keys nor a
simulator; it does not establish runtime or hardware attestation.
