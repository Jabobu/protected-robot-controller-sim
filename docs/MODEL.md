# Model and license

The selected model is Seeed reBot Arm B601-RS at upstream commit
`158f87317fcaa35a7d1706ef364e324d3565939e` in
`Seeed-Projects/reBot-Isaacsim`. The included notice is
`assets/notices/Seeed-reBot-Isaacsim-LICENSE`. The model closure and its exact
file lengths and SHA-256 values are in `artifacts/model_manifest.json`.
`python3 tools/fetch_scene_model.py` obtains only missing selected payloads over
normal HTTPS and verifies every file; it refuses to replace a mismatch.

Trusted runtime setup checks the unchanged manifest against the controller
configuration, validates all 11 manifest entries, and checks the exact nine USD
layers before constructing the simulator World. Network, unresolved, extra,
symlinked and path-escaping dependencies fail closed. This check is not a
physical attestation.

The manifest's exact bytes are deliberately retained as a narrow compatibility
exception. Its model display names, source URL and notes therefore also affect
the configuration digest if edited. Do not describe the authorization contract
as independent of those manifest fields. Other release documentation, source
paths and ROS display names are separate from the semantic authorization binding.
