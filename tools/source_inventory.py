"""Retain the source file inventory associated with a scene run."""
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source_inventory(root=ROOT):
    root = Path(root)
    paths = [p for folder in ("protected_robot_controller", "tools", "tests", "scenes", "docs")
             for p in sorted((root / folder).rglob("*"))
             if p.is_file() and p.suffix in (".py", ".json", ".md")]
    paths += [root / p for p in ("assets/b601_rs.usda", "artifacts/model_manifest.json")]
    return {str(p.relative_to(root)): sha256(p.read_bytes()).hexdigest() for p in paths}
