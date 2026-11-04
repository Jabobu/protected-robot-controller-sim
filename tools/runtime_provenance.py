"""Record runtime identity without treating the frozen calibration image as current.

This metadata is supplied by the trusted host, not a remote attestation. The
profile's historical image pin remains part of its immutable calibration data.
"""
from __future__ import annotations

import os
import re
import sys

_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def current_runtime():
    image = os.environ.get("PRC_RUNTIME_IMAGE")
    kind = os.environ.get("PRC_RUNTIME_KIND")
    if image is not None:
        if kind not in (None, "container"):
            raise ValueError("Conflicting runtime identity declarations")
        if not _IMAGE.fullmatch(image):
            raise ValueError("PRC_RUNTIME_IMAGE must be a full sha256 Docker image ID")
        return {"schema_version": 1, "kind": "container", "image_id": image,
                "identity_source": "trusted_launcher", "python_executable": sys.executable}
    if kind != "native":
        raise ValueError("Runtime identity missing; use a trusted native or container launcher")
    return {"schema_version": 1, "kind": "native", "image_id": None,
            "identity_source": "local_process", "python_executable": sys.executable}


def validate_runtime(runtime, run, profile, *, expected_runtime=None):
    """Validate metadata shape and preserve legacy profile-pinned archives.

    Neither branch proves the host or image identity. Caller-signed evidence
    never makes a remote-attestation claim about this metadata.
    """
    if type(runtime) is not dict or type(run) is not dict or type(profile) is not dict:
        return False
    if runtime.get("visual_runtime") != run.get("visual_runtime"):
        return False
    visual = runtime.get("visual_runtime")
    if visual is not None:
        if (type(visual) is not dict or set(visual) != {"mode", "kit_configuration_sha256", "extension_pin_sha256", "scope"}
                or visual.get("mode") != "standalone_visual"
                or not isinstance(visual.get("scope"), str) or not visual["scope"]
                or any(not isinstance(visual.get(k), str) or re.fullmatch(r"[0-9a-f]{64}", visual[k]) is None
                       for k in ("kit_configuration_sha256", "extension_pin_sha256"))):
            return False
    identity = runtime.get("runtime_identity")
    if visual is not None and identity is None:
        return False
    if identity is None:
        legacy_image = profile.get("runtime_image")
        return (isinstance(legacy_image, str) and bool(_IMAGE.fullmatch(legacy_image))
                and expected_runtime in (None, legacy_image)
                and runtime.get("runtime_image") == run.get("runtime_image") == legacy_image)
    if type(identity) is not dict or set(identity) != {
        "schema_version", "kind", "image_id", "identity_source", "python_executable"
    } or identity.get("schema_version") != 1:
        return False
    if not isinstance(identity.get("python_executable"), str) or not identity["python_executable"]:
        return False
    if identity["kind"] == "native":
        valid = identity["image_id"] is None and identity["identity_source"] == "local_process"
    elif identity["kind"] == "container":
        valid = (isinstance(identity["image_id"], str) and bool(_IMAGE.fullmatch(identity["image_id"]))
                 and identity["identity_source"] == "trusted_launcher")
    else:
        return False
    expected = "native" if identity["kind"] == "native" else identity["image_id"]
    return (valid and expected_runtime == expected and identity == run.get("runtime_identity")
            and runtime.get("runtime_image") == run.get("runtime_image") == identity["image_id"])
