import copy

import pytest

from tools.runtime_provenance import current_runtime, validate_runtime


def test_native_does_not_claim_calibration_image(monkeypatch):
    monkeypatch.delenv("PRC_RUNTIME_IMAGE", raising=False)
    monkeypatch.setenv("PRC_RUNTIME_KIND", "native")
    identity = current_runtime()
    run = {"runtime_image": None, "runtime_identity": identity}
    metadata = dict(run)
    assert identity["kind"] == "native"
    assert not validate_runtime(metadata, run, {"runtime_image": "sha256:" + "a" * 64})
    assert validate_runtime(metadata, run, {"runtime_image": "sha256:" + "a" * 64}, expected_runtime="native")
    forged = copy.deepcopy(metadata)
    forged["runtime_image"] = "sha256:" + "a" * 64
    assert not validate_runtime(forged, run, {"runtime_image": "sha256:" + "a" * 64}, expected_runtime="native")


def test_unknown_runtime_fails_closed(monkeypatch):
    monkeypatch.delenv("PRC_RUNTIME_IMAGE", raising=False)
    monkeypatch.delenv("PRC_RUNTIME_KIND", raising=False)
    with pytest.raises(ValueError):
        current_runtime()


def test_container_identity_and_rejection(monkeypatch):
    image = "sha256:" + "b" * 64
    monkeypatch.setenv("PRC_RUNTIME_IMAGE", image)
    identity = current_runtime()
    run = {"runtime_image": image, "runtime_identity": identity}
    assert validate_runtime(dict(run), run, {"runtime_image": "sha256:" + "a" * 64}, expected_runtime=image)
    with pytest.raises(ValueError):
        monkeypatch.setenv("PRC_RUNTIME_IMAGE", "mutable:tag")
        current_runtime()


def test_legacy_archives_still_require_profile_pin():
    profile = {"runtime_image": "sha256:" + "a" * 64}
    assert validate_runtime(dict(profile), dict(profile), profile)
    assert not validate_runtime({"runtime_image": "sha256:" + "b" * 64}, dict(profile), profile)
    assert not validate_runtime(dict(profile), dict(profile), profile, expected_runtime="native")


def test_visual_metadata_is_consistent_and_has_well_formed_digests(monkeypatch):
    monkeypatch.delenv('PRC_RUNTIME_IMAGE', raising=False)
    monkeypatch.setenv('PRC_RUNTIME_KIND', 'native')
    identity = current_runtime()
    visual = {'mode': 'standalone_visual', 'kit_configuration_sha256': 'a' * 64,
              'extension_pin_sha256': 'b' * 64, 'scope': 'trusted host'}
    run = {'runtime_image': None, 'runtime_identity': identity, 'visual_runtime': visual}
    metadata = copy.deepcopy(run)
    assert validate_runtime(metadata, run, {'runtime_image': 'sha256:' + 'c' * 64}, expected_runtime='native')
    metadata['visual_runtime']['mode'] = 'headless'
    assert not validate_runtime(metadata, run, {'runtime_image': 'sha256:' + 'c' * 64}, expected_runtime='native')
    metadata = copy.deepcopy(run)
    metadata['visual_runtime']['kit_configuration_sha256'] = 'not-a-digest'
    assert not validate_runtime(metadata, run, {'runtime_image': 'sha256:' + 'c' * 64}, expected_runtime='native')
