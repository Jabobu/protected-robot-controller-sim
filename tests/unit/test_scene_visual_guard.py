"""Fail-closed visual boundary checks without claiming live GUI evidence."""
from pathlib import Path
from types import SimpleNamespace
import time

import pytest

from protected_robot_controller.simulation._backend import BackendFault, _IsaacRobotBackend
from tools.scene_visual import VisualGuard, visual_experience


class Notice:
    def __init__(self, *, resync=(), changed=()):
        self.resync, self.changed = resync, changed

    def GetResyncedPaths(self):
        return self.resync

    def GetChangedInfoOnlyPaths(self):
        return self.changed


def notice_guard():
    guard = VisualGuard.__new__(VisualGuard)
    guard._armed = True
    guard._fault = None
    guard._physics_paths = frozenset({'/B601/Geometry/link.xformOp:translate'})
    return guard


def test_stage_notice_rejects_unexpected_or_structural_change():
    guard = notice_guard()
    guard._stage_changed(Notice(changed=['/B601/Geometry/link.xformOp:translate',
                                        '/OmniverseKit_Persp.xformOp:transform']), None)
    assert guard._fault is None
    guard._stage_changed(Notice(changed=['/B601/Physics/joint1.drive:angular:physics:targetPosition']), None)
    assert 'Unexpected stage change' in guard._fault
    other = notice_guard()
    other._stage_changed(Notice(resync=['/Manipulation/Objects/R1']), None)
    assert 'Stage structure changed' in other._fault


def test_visual_experience_is_private_and_excludes_user_extensions(tmp_path, monkeypatch):
    for name in ('apps', 'exts', 'extscache', 'extsDeprecated'):
        (tmp_path / name).mkdir()
    monkeypatch.setenv('ISAAC_PATH', str(tmp_path))
    with visual_experience() as experience:
        assert experience.is_file() and experience.name == 'prcview.kit'
        text = experience.read_text()
        assert str(tmp_path / 'extsDeprecated') in text
        assert 'extsUser' not in text
        assert 'startup.selectionManipulator.enabled = false' in text
        assert 'showContextMenu = false' in text
    assert not experience.exists()


class Settings:
    def __init__(self):
        self.values = {'/app/player/playSimulations': True}

    def get(self, key):
        return self.values[key]

    def set_bool(self, key, value):
        self.values[key] = value


def test_pump_rejects_unexpected_clock_and_restores_player_setting():
    guard = VisualGuard.__new__(VisualGuard)
    guard._settings = Settings()
    guard._in_pump = False
    guard._timeline = SimpleNamespace(get_current_time=lambda: 10.0)
    guard.check = lambda: None
    guard._state = lambda: ('actual-state',)
    world = SimpleNamespace(current_time_step_index=10, current_time=10.0, is_playing=lambda: True)
    def render():
        guard._settings.set_bool('/app/player/playSimulations', False)
        world.current_time_step_index += 1
    world.render = render
    guard.backend = SimpleNamespace(_world=world, _check_physics_clock=lambda steps: None)
    with pytest.raises(RuntimeError, match='state or clock changed'):
        guard.pump(10)
    assert guard._settings.get('/app/player/playSimulations') is True
    assert guard._in_pump is False


def test_backend_checks_visual_pump_after_exactly_one_physics_step():
    backend = _IsaacRobotBackend.__new__(_IsaacRobotBackend)
    backend._closed = backend._faulted = False
    backend._pending_drive = True
    backend._steps = backend._run_start_steps = 0
    backend._start_wall = time.monotonic_ns()
    backend._dt = backend._physics_dt = 1 / 120
    backend._start_step = 10
    backend._start_sim_time = 10 / 120
    calls = []
    world = SimpleNamespace(current_time_step_index=10, current_time=10 / 120,
                            is_playing=lambda: True, get_physics_dt=lambda: 1 / 120)
    def one_step(*, render):
        assert render is False
        world.current_time_step_index += 1
        world.current_time += 1 / 120
        calls.append('step')
    world.step = one_step
    backend._world = world
    backend._visual_guard = SimpleNamespace(check=lambda: calls.append('check'),
                                             pump=lambda n: calls.append(('pump', n)))
    backend.step_physics()
    assert calls == ['check', 'step', ('pump', 1)]
    assert backend._steps == 1 and not backend._pending_drive


def test_guard_cleanup_restores_timeline_even_if_notice_revocation_fails():
    guard = VisualGuard.__new__(VisualGuard)
    guard._closed = False
    guard._armed = True
    guard._subscriptions = [object()]
    def fail_revoke():
        raise RuntimeError('notice teardown failed')
    guard._notice = SimpleNamespace(Revoke=fail_revoke)
    events = []
    guard._timeline_auto_before = True
    guard._timeline = SimpleNamespace(set_auto_update=lambda value: events.append(('restore', value)),
                                      commit=lambda: events.append(('commit',)),
                                      is_auto_updating=lambda: True)
    with pytest.raises(RuntimeError, match='notice teardown'):
        guard.close()
    assert events == [('restore', True), ('commit',)]
    assert guard._closed and not guard._armed and not guard._subscriptions
