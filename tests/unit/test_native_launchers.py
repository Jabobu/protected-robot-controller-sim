"""Exercise launcher path and identity handling without starting Isaac or ROS."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def stub_launcher(path):
    path.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$PRC_RUNTIME_KIND" "${PRC_RUNTIME_IMAGE-unset}" "$PYTHONPATH" "$@"\n')
    path.chmod(0o755)


def test_scene_launcher_resolves_relative_python_and_clears_image(tmp_path):
    stub_launcher(tmp_path / 'python.sh')
    env = {**os.environ, 'ISAAC_PYTHON': './python.sh', 'PRC_RUNTIME_IMAGE': 'sha256:' + 'a' * 64,
           'PYTHONPATH': ''}
    result = subprocess.run([str(ROOT / 'tools/run_scene_native.sh'), 'normal'], cwd=tmp_path,
                            env=env, capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    assert lines[:2] == ['native', 'unset']
    assert lines[3:] == ['-m', 'tools.run_scene_examples', '--scenario', 'normal', '--no-record']


def test_ros_launcher_resolves_relative_install_paths(tmp_path):
    stub_launcher(tmp_path / 'python.sh')
    for directory in ('exts/isaacsim.ros2.core/jazzy/rclpy', 'exts/isaacsim.ros2.core/jazzy/lib',
                      'ros/lib/python3.12/site-packages/prc_interfaces'):
        (tmp_path / directory).mkdir(parents=True)
    env = {**os.environ, 'ISAAC_PYTHON': './python.sh', 'PRC_ROS_PREFIX': './ros',
           'PRC_RUNTIME_IMAGE': 'sha256:' + 'a' * 64, 'PYTHONPATH': ''}
    result = subprocess.run([str(ROOT / 'tools/run_ros2_native.sh'), 'example', 'normal'], cwd=tmp_path,
                            env=env, capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()
    assert lines[:2] == ['native', 'unset']
    assert str(tmp_path / 'ros/lib/python3.12/site-packages') in lines[2].split(':')
    assert lines[3:] == ['-m', 'tools.run_scene_examples', '--scenario', 'normal', '--no-record', '--ros2']
