#!/usr/bin/env python3
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


FORBIDDEN_PARTS = {".git", ".runs", ".deps", ".release", "private-cases", "__pycache__"}
FORBIDDEN_SUFFIXES = {".key", ".pem", ".csr", ".smime", ".p7s", ".pyc"}


def validate_names(archive: Path, names: list[str]) -> None:
    if not names:
        raise ValueError(f"{archive.name} is empty")
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive path in {archive.name}: {name}")
        if FORBIDDEN_PARTS.intersection(path.parts):
            raise ValueError(f"private/generated path in {archive.name}: {name}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"sensitive or generated suffix in {archive.name}: {name}")


def main() -> None:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--sdist-only"):
        raise SystemExit("usage: verify_artifacts.py DIST_DIRECTORY [--sdist-only]")
    distribution = Path(sys.argv[1])
    wheels = sorted(distribution.glob("*.whl"))
    source_archives = sorted(distribution.glob("*.tar.gz"))
    sdist_only = len(sys.argv) == 3
    if len(source_archives) != 1 or (not sdist_only and len(wheels) != 1):
        raise SystemExit("expected one source archive and, unless --sdist-only, one wheel")

    if not sdist_only:
        with zipfile.ZipFile(wheels[0]) as wheel:
            wheel_names = wheel.namelist()
            validate_names(wheels[0], wheel_names)
            required_wheel_suffixes = (
                "ddsleuth/__init__.py",
                ".dist-info/entry_points.txt",
                ".dist-info/licenses/LICENSE",
            )
            for suffix in required_wheel_suffixes:
                if not any(name.endswith(suffix) for name in wheel_names):
                    raise ValueError(f"wheel is missing {suffix}")

    with tarfile.open(source_archives[0], "r:gz") as source:
        source_names = source.getnames()
        validate_names(source_archives[0], source_names)
        required_source_suffixes = (
            "/LICENSE",
            "/README.md",
            "/SECURITY.md",
            "/scripts/release-check.sh",
            "/tests/test_scenario.py",
            "/probes/fastdds_instrumentation/fastdds-f6376882-ddsleuth-observer.patch",
        )
        for suffix in required_source_suffixes:
            if not any(name.endswith(suffix) for name in source_names):
                raise ValueError(f"source archive is missing {suffix}")

    if sdist_only:
        print(f"verified source archive {source_archives[0].name}")
    else:
        print(f"verified {wheels[0].name} and {source_archives[0].name}")


if __name__ == "__main__":
    main()
