"""One real headless Isaac process; unavailable prerequisites are errors, not skips."""

import json
import sys
import traceback
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_APP = pytest.StashKey()
_REPORTS = pytest.StashKey()


def _evidence_directory(config):
    xml_path = config.getoption("xmlpath", default=None)
    # Only the report mount or ignored workspace output; no gate configuration.
    directory = (Path(xml_path).resolve().parent if xml_path else
                 Path(__file__).resolve().parents[2] / "output") / "s1"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_diagnostic(config, name, value):
    try:
        (_evidence_directory(config) / name).write_text(json.dumps(value, indent=2) + "\n")
    except Exception as error:
        # Optional diagnostics must not replace the original test/cleanup error.
        print(f"Could not write S1 diagnostic {name}: {error!r}", file=sys.stderr)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    reports = item.config.stash.setdefault(_REPORTS, [])
    if not reports:
        _write_diagnostic(item.config, "shutdown.json", {"state": "NOT_REQUESTED"})
    entry = {"nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome}
    if report.failed:
        entry["traceback"] = report.longreprtext
    reports.append(entry)
    # Persist even setup errors, before any application cleanup can terminate
    # Python. Rewriting this session's list avoids retaining stale prior results.
    _write_diagnostic(item.config, "pytest_phases.json", reports)
    return report


@pytest.fixture(scope="session")
def simulation_app(pytestconfig):
    # SimulationApp forwards sys.argv to Kit. Pytest's -q/-s, test selectors,
    # and --junitxml belong to pytest, not the embedded application. Restore
    # the original list even if importing/starting Isaac raises an exception.
    argv = sys.argv
    try:
        sys.argv = [argv[0]]
        from isaacsim import SimulationApp

        app = SimulationApp({
            "headless": True,
            # Use Isaac 6.0's supported default. Slow extension unloading
            # segfaulted after successful pytest teardown on this runtime.
            # sessionfinish below flushes JUnit and preserves pytest's status.
            "fast_shutdown": True,
            "multi_gpu": False,
            "disable_viewport_updates": True,
            "width": 320,
            "height": 240,
            "enable_crashreporter": False,
        })
    finally:
        sys.argv = argv
    pytestconfig.stash[_APP] = app
    return app


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    # The outer wrapper resumes after JUnit's sessionfinish hook has flushed
    # every test/setup/teardown result. Close before interpreter finalization:
    # Python 3.12 forbids starting threads from atexit callbacks. Fast shutdown
    # may not return: flush evidence first and pass pytest's actual status to
    # Isaac 6.0's close API; never turn a failure into exit 0.
    try:
        result = yield
    except BaseException:
        # Do not leave Isaac's default-zero atexit close to handle hook errors.
        failure = traceback.format_exc()
        session.exitstatus = int(session.exitstatus) or int(pytest.ExitCode.INTERNAL_ERROR)
        _write_diagnostic(session.config, "session_finish_error.json", {"traceback": failure})
        print(failure, file=sys.stderr, flush=True)
        _close_simulation_app(session)
        raise
    _close_simulation_app(session)
    return result


def _close_simulation_app(session):
    app = session.config.stash.get(_APP, None)
    if app is not None:
        record = {"state": "STARTED", "pytest_exit_code": int(session.exitstatus)}
        _write_diagnostic(session.config, "shutdown.json", record)
        try:
            app.close(wait_for_replicator=False, skip_cleanup=False,
                      exit_code=int(session.exitstatus))
        except BaseException:
            record.update(state="ERROR", traceback=traceback.format_exc())
            failure_status = int(session.exitstatus) or 1
            record["exit_code_after_cleanup_failure"] = failure_status
            _write_diagnostic(session.config, "shutdown.json", record)
            print(record["traceback"], file=sys.stderr, flush=True)
            # Isaac 6.0 handles a nonzero fast-shutdown status before extension
            # cleanup. An automatic later close(default=0) must not hide this
            # error. If Isaac already marked itself exiting, close returns and
            # the original exception still propagates below.
            app.close(wait_for_replicator=False, skip_cleanup=False,
                      exit_code=failure_status)
            raise
        else:
            record["state"] = "RETURNED"
        finally:
            _write_diagnostic(session.config, "shutdown.json", record)


@pytest.fixture(scope="module")
def loaded_model(simulation_app):
    from protected_robot_controller.simulation.model import load_model, read_manifest

    manifest = read_manifest()
    world, robot, stage, indices = load_model(manifest)
    yield manifest, world, robot, stage, indices
    world.stop()
    world.clear()
    world.clear_instance()


@pytest.fixture
def evidence_dir(pytestconfig):
    return _evidence_directory(pytestconfig)
