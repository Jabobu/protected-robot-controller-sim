"""Reject asset/closure changes before runtime model construction; no Isaac physics."""
from hashlib import sha256
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys

import pytest
from protected_robot_controller.simulation import model


@pytest.fixture
def pinned_model(tmp_path, monkeypatch):
    payload = b'local USD test payload'
    (tmp_path / 'asset.usda').write_bytes(payload)
    manifest = {'entrypoint': 'asset.usda', 'files': [{'path': 'asset.usda',
        'size_bytes': len(payload), 'sha256': sha256(payload).hexdigest()}],
        'dependency_closure': {'layers': ['asset.usda']}}
    raw = json.dumps(manifest, sort_keys=True).encode()
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_bytes(raw)
    monkeypatch.setattr(model, 'ROOT', tmp_path)
    monkeypatch.setattr(model, 'MANIFEST_PATH', manifest_path)
    monkeypatch.setattr(model, 'MODEL_MANIFEST_SHA256', sha256(raw).hexdigest())
    return tmp_path, manifest


def test_pinned_manifest_and_payload_are_both_required(pinned_model):
    root, manifest = pinned_model
    assert model.read_manifest() == manifest
    model.verify_files(manifest)
    modified = dict(manifest, entrypoint='other.usda')
    with pytest.raises(ValueError, match='argument differs'):
        model.verify_files(modified)
    (root / 'asset.usda').write_bytes(b'altered')
    with pytest.raises(ValueError, match='Asset (size|hash) mismatch'):
        model.verify_files(manifest)
    (root / 'manifest.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='manifest differs'):
        model.read_manifest()


def test_model_asset_symlink_is_rejected_even_inside_root(pinned_model):
    root, manifest = pinned_model
    (root / 'real.usda').write_bytes((root / 'asset.usda').read_bytes())
    (root / 'asset.usda').unlink()
    (root / 'asset.usda').symlink_to('real.usda')
    with pytest.raises(ValueError, match='ordinary local path'):
        model.verify_files(manifest)


def test_exact_local_usd_closure_required(pinned_model, monkeypatch):
    root, manifest = pinned_model
    layer = SimpleNamespace(realPath=str(root / 'asset.usda'))
    utils = SimpleNamespace(ComputeAllDependencies=lambda _: ([layer], [], []))
    monkeypatch.setitem(sys.modules, 'pxr', SimpleNamespace(UsdUtils=utils))
    assert model.verify_closure(manifest)[1] == ['asset.usda']
    utils.ComputeAllDependencies = lambda _: ([layer], ['network-or-extra-asset'], [])
    with pytest.raises(ValueError, match='Unexpected dependencies'):
        model.verify_closure(manifest)
    utils.ComputeAllDependencies = lambda _: ([layer], [], ['missing-layer'])
    with pytest.raises(ValueError, match='Unexpected dependencies'):
        model.verify_closure(manifest)
    utils.ComputeAllDependencies = lambda _: ([], [], [])
    with pytest.raises(ValueError, match='closure changed'):
        model.verify_closure(manifest)


def test_runtime_loader_checks_closure_before_world_creation(monkeypatch):
    called = []
    api = ModuleType('isaacsim.core.api')
    api.World = lambda **kwargs: called.append('world')
    prims = ModuleType('isaacsim.core.prims')
    prims.SingleArticulation = object
    stage = ModuleType('isaacsim.core.utils.stage')
    stage.add_reference_to_stage = lambda *args: None
    stage.get_current_stage = lambda: None
    for name, module in [('isaacsim', ModuleType('isaacsim')), ('isaacsim.core', ModuleType('isaacsim.core')),
                         ('isaacsim.core.api', api), ('isaacsim.core.prims', prims),
                         ('isaacsim.core.utils', ModuleType('isaacsim.core.utils')),
                         ('isaacsim.core.utils.stage', stage)]:
        monkeypatch.setitem(sys.modules, name, module)
    def reject(_):
        called.append('closure')
        raise ValueError('invalid closure')
    monkeypatch.setattr(model, 'verify_closure', reject)
    with pytest.raises(ValueError, match='invalid closure'):
        model.load_model({})
    assert called == ['closure']
