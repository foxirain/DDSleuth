from __future__ import annotations

from pathlib import Path
from typing import Mapping, Protocol

from ..evidence import EvidenceBundle
from ..models import Scenario


class ImplementationAdapter(Protocol):
    name: str

    def run(
        self,
        scenario: Scenario,
        run_dir: Path,
        environment: Mapping[str, str],
        *,
        allow_external: bool = False,
        overwrite: bool = False,
    ) -> EvidenceBundle:
        ...
