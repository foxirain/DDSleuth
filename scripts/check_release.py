#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise SystemExit(f"release metadata check failed: {message}")


def load_package_version() -> str:
    init_path = ROOT / "src/ddsleuth/__init__.py"
    specification = importlib.util.spec_from_file_location("ddsleuth_release_version", init_path)
    if specification is None or specification.loader is None:
        fail("cannot load src/ddsleuth/__init__.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return str(module.__version__)


def cff_value(name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}:\s*[\"']?([^\"'\n]+)", re.MULTILINE)
    match = pattern.search((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    if match is None:
        fail(f"CITATION.cff has no {name!r}")
    return match.group(1).strip()


def main() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    versions = {
        "pyproject.toml": str(project["version"]),
        "src/ddsleuth/__init__.py": load_package_version(),
    }
    if len(set(versions.values())) != 1:
        fail(f"Python versions disagree: {versions}")

    python_version = next(iter(versions.values()))
    release_version = cff_value("version")
    expected_release_version = python_version.replace("a", "-alpha.")
    if release_version != expected_release_version:
        fail(
            f"CITATION.cff version {release_version!r} does not match "
            f"Python version {python_version!r}"
        )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {release_version} —" not in changelog:
        fail(f"CHANGELOG.md has no {release_version!r} release heading")

    required = [
        "LICENSE",
        "NOTICE",
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "CITATION.cff",
        "MANIFEST.in",
    ]
    missing = [name for name in required if not (ROOT / name).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")

    old_markers = ("DDS Security Lab", "dds-security-lab", "ddssec_lab", "DDSSEC_")
    checked_roots = ["README.md", "docs", "examples", "probes", "schemas", "src", "tests"]
    for relative in checked_roots:
        path = ROOT / relative
        paths = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
        for item in paths:
            try:
                text = item.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for marker in old_markers:
                if marker in text:
                    fail(f"legacy marker {marker!r} remains in {item.relative_to(ROOT)}")

    print(f"release metadata is consistent for DDSleuth {release_version}")


if __name__ == "__main__":
    main()
