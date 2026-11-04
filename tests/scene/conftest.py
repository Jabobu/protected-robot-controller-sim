"""Isaac 6.0 scene gate lifecycle; no host/mock fallback and no skipped cases."""
import json
from pathlib import Path
import sys
import traceback
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
_APP = pytest.StashKey()
_LOG = pytest.StashKey()


def diagnostic(config, name, data):
    if _LOG not in config.stash:
        directory = ROOT / "artifacts/scene-work/calibration" / ("pytest-" + uuid4().hex)
        directory.mkdir(parents=True, exist_ok=False)
        config.stash[_LOG] = directory
    (config.stash[_LOG] / name).write_text(json.dumps(data, indent=2) + "\n")


@pytest.fixture(scope="session")
def scene_simulation_app(pytestconfig):
    argv = sys.argv
    try:
        sys.argv = [argv[0]]
        from isaacsim import SimulationApp
        app = SimulationApp({"headless": True, "fast_shutdown": True, "multi_gpu": False,
                             "disable_viewport_updates": True, "width": 1200, "height": 900,
                             "enable_crashreporter": False})
    finally:
        sys.argv = argv
    pytestconfig.stash[_APP] = app
    diagnostic(pytestconfig, "startup.json", {"status": "STARTED", "runtime": "Isaac 6.0.0 required by fixture"})
    return app


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    diagnostic(item.config, item.name + "-" + report.when + ".json",
               {"nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome,
                "traceback": report.longreprtext if report.failed else None})
    return report


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    # Isaac fast shutdown may not return. Let JUnit flush before close, and
    # propagate real pytest/hook failure status into the application's exit.
    try:
        yield
    except BaseException:
        session.exitstatus = int(session.exitstatus) or int(pytest.ExitCode.INTERNAL_ERROR)
        diagnostic(session.config, "session_error.json", {"traceback": traceback.format_exc()})
        raise
    finally:
        app = session.config.stash.get(_APP, None)
        if app is not None:
            diagnostic(session.config, "shutdown.json", {"pytest_exit_code": int(session.exitstatus)})
            app.close(wait_for_replicator=False, skip_cleanup=False, exit_code=int(session.exitstatus))
