"""Additive S6 artifacts around unchanged acceptance suites.

No tests are deselected, marked, patched, or given altered expectations. Run
the five suites once each, in any order (or together).
Only artifact records and a separate offscreen demo are produced here.
"""

from pathlib import Path
import shlex
import sys
import traceback

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import functional_release as release

_STATE = pytest.StashKey()
_PHASES = pytest.StashKey()
_COLLECTED = pytest.StashKey()


def pytest_collection_modifyitems(session, config, items):
    collected = {}
    for item in items:
        if item.path.parent.name == "acceptance" and item.path.name in release.REQUIRED:
            collected.setdefault(item.path.name, []).append(item.nodeid)
    if collected:
        config.stash[_COLLECTED] = collected
        config.stash[_PHASES] = []
        config.stash[_STATE] = release.begin(collected, shlex.join([sys.executable, "-m", "pytest", *config.invocation_params.args]),
                                             config.getoption("xmlpath", default=None))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if _PHASES in item.config.stash:
        item.config.stash[_PHASES].append({"nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome})
    return report


@pytest.fixture(scope="session", autouse=True)
def s6_visualization(request):
    selected = request.config.stash.get(_COLLECTED, {})
    app = request.getfixturevalue("simulation_app") if "test_model.py" in selected else None
    yield
    if app is not None and request.session.testsfailed == 0:
        # Module Worlds have torn down; accepted fixture closes SimulationApp
        # only in sessionfinish, after this real capture and JUnit serialization.
        from tools.capture_full_model import capture
        capture(app)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    config = session.config
    if _STATE not in config.stash:
        return
    try:
        release.finish(config.stash[_STATE], config.stash[_PHASES], config.stash[_COLLECTED], int(session.exitstatus))
    except BaseException:
        release.write_json(release.DIRECTORY / "publication_error.json", {"traceback": traceback.format_exc()})
        # The existing outer shutdown hook forwards this nonzero status to Kit.
        session.exitstatus = int(session.exitstatus) or int(pytest.ExitCode.INTERNAL_ERROR)
        raise
