from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .models import JsonValue


@dataclass(frozen=True, slots=True)
class ManifestCase:
    index: int
    scenario_id: str
    scenario_digest: str
    scenario_path: Path
    assignments: Mapping[str, JsonValue]
