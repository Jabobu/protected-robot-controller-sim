"""Pytest integration regressions only; the stub is never physics evidence."""

import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest


@pytest.mark.parametrize("scenario", [
    "pass", "assertion", "setup", "teardown", "startup", "shutdown", "shutdown_once", "sessionfinish",
])
def test_isaac_fixture_preserves_pytest_results(tmp_path, scenario):
    # Exercise the actual acceptance fixture in an isolated child pytest run.
    # The tiny fake application checks argument isolation and report ordering;
    # it neither loads a model nor implements any actuator/sensor operations.
    fixture = Path(__file__).resolve().parents[1] / "acceptance/conftest.py"
    (tmp_path / "conftest.py").write_text(fixture.read_text())
    (tmp_path / "isaacsim.py").write_text('''
import json
import atexit
from pathlib import Path
import os
import sys
import xml.etree.ElementTree as ET

class SimulationApp:
    def __init__(self, config):
        assert len(sys.argv) == 1, "pytest arguments leaked into Kit"
        assert config["fast_shutdown"] is True
        if os.environ["PRC_LIFECYCLE_SCENARIO"] == "startup":
            raise RuntimeError("intentional startup failure")
        self._exiting = False
        self._cleanup_calls = 0
        self._automatic = False
        atexit.register(self._atexit_close)

    def _atexit_close(self):
        if not self._exiting:
            self._automatic = True
            self.close(wait_for_replicator=False)

    def close(self, *, wait_for_replicator, skip_cleanup=False, exit_code=0):
        if self._exiting:
            return
        suite = ET.parse("results.xml").getroot().find("testsuite")
        assert len(suite.findall("testcase")) == 1, "JUnit not flushed"
        assert not skip_cleanup and not wait_for_replicator
        Path("closed.json").write_text(json.dumps({"exit_code": exit_code, "automatic": self._automatic}))
        # Match Isaac 6.0: nonzero fast shutdown precedes cleanup. Default-zero
        # atexit retries would otherwise hide an earlier cleanup/hook exception.
        if exit_code:
            self._exiting = True
            os._exit(exit_code)
        self._cleanup_calls += 1
        scenario = os.environ["PRC_LIFECYCLE_SCENARIO"]
        if scenario == "shutdown" or (scenario == "shutdown_once" and self._cleanup_calls == 1):
            raise RuntimeError("intentional shutdown failure")
        # Model the supported fast-shutdown API's process termination. JUnit
        # must already be complete and nonzero test results must survive.
        self._exiting = True
        os._exit(exit_code)
''')
    (tmp_path / "session_failure.py").write_text('''
import os
import pytest

@pytest.hookimpl(wrapper=True)
def pytest_sessionfinish(session, exitstatus):
    result = yield
    if os.environ["PRC_LIFECYCLE_SCENARIO"] == "sessionfinish":
        raise RuntimeError("intentional sessionfinish failure")
    return result
''')
    (tmp_path / "test_probe.py").write_text('''
import os
import sys
import pytest

@pytest.fixture
def setup_probe(simulation_app):
    if os.environ["PRC_LIFECYCLE_SCENARIO"] == "setup":
        raise RuntimeError("intentional setup failure")
    yield
    if os.environ["PRC_LIFECYCLE_SCENARIO"] == "teardown":
        raise RuntimeError("intentional teardown failure")

def test_probe(setup_probe):
    assert "-q" in sys.argv, "pytest argv was not restored"
    assert "--junitxml=results.xml" in sys.argv
    assert os.environ["PRC_LIFECYCLE_SCENARIO"] != "assertion", "intentional assertion"
''')
    env = dict(os.environ, PRC_LIFECYCLE_SCENARIO=scenario, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               PYTEST_PLUGINS="session_failure")
    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_probe.py", "--junitxml=results.xml"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    expected_exit = 0 if scenario == "pass" else (3 if scenario == "sessionfinish" else 1)
    assert run.returncode == expected_exit, run.stdout + run.stderr
    suite = ET.parse(tmp_path / "results.xml").getroot().find("testsuite")
    # Pinned pytest 9.1.1 counts the testcase once, including a teardown error.
    # Error/failure counts below must still reflect the deliberate fault.
    assert int(suite.attrib["tests"]) == 1
    assert int(suite.attrib["failures"]) == int(scenario == "assertion")
    assert int(suite.attrib["errors"]) == int(scenario in {"setup", "teardown", "startup"})
    assert int(suite.attrib["skipped"]) == 0
    if scenario in {"assertion", "setup", "teardown", "startup"}:
        assert f"intentional {scenario}" in ET.tostring(suite, encoding="unicode")
    if scenario in {"shutdown", "shutdown_once"}:
        assert "intentional shutdown failure" in run.stdout + run.stderr
    if scenario == "sessionfinish":
        assert "intentional sessionfinish failure" in run.stdout + run.stderr
        assert "intentional sessionfinish failure" in (tmp_path / "s1/session_finish_error.json").read_text()
    if scenario == "startup":
        assert not (tmp_path / "closed.json").exists()
        assert json.loads((tmp_path / "s1/shutdown.json").read_text()) == {"state": "NOT_REQUESTED"}
    else:
        closed = json.loads((tmp_path / "closed.json").read_text())
        assert closed["exit_code"] == expected_exit
        assert not closed["automatic"], "cleanup was incorrectly left to default-zero atexit"
        shutdown = json.loads((tmp_path / "s1/shutdown.json").read_text())
        cleanup_failed = scenario in {"shutdown", "shutdown_once"}
        assert shutdown["pytest_exit_code"] == (0 if cleanup_failed else expected_exit)
        assert shutdown["state"] == ("ERROR" if cleanup_failed else "STARTED")
        if cleanup_failed:
            assert shutdown["exit_code_after_cleanup_failure"] == 1
            assert "intentional shutdown failure" in shutdown["traceback"]

    phases = json.loads((tmp_path / "s1/pytest_phases.json").read_text())
    assert all(p["nodeid"] == "test_probe.py::test_probe" for p in phases)
    assert [p["phase"] for p in phases] == (
        ["setup", "teardown"] if scenario in {"setup", "startup"}
        else ["setup", "call", "teardown"])
    failures = [p for p in phases if p["outcome"] == "failed"]
    if scenario in {"assertion", "setup", "teardown", "startup"}:
        assert len(failures) == 1
        assert f"intentional {scenario}" in failures[0]["traceback"]
    else:
        assert failures == []
