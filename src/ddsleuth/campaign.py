from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .adapters.fastdds import FastDDSAdapter
from .campaign_types import ManifestCase
from .candidates import discover_candidates, write_candidates
from .evidence import load_evidence, write_evidence
from .identity import IdentityArtifacts, materialize_identities
from .models import JsonValue, Scenario
from .oracles.evaluate import EvaluationReport, evaluate
from .policy import materialize_policies
from .reporting import write_report
from .scenario import load_scenario


class CampaignError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyMaterializationConfig:
    subject_names: Mapping[str, str]
    signer_cert: Path | None = None
    signer_key: Path | None = None
    not_before: str = "2020-01-01T00:00:00"
    not_after: str = "2038-01-01T00:00:00"


@dataclass(frozen=True, slots=True)
class IdentityMaterializationConfig:
    ca_subject: str = "/CN=DDSleuth Ephemeral Identity CA"
    validity_days: int = 7


@dataclass(frozen=True, slots=True)
class CampaignCaseResult:
    index: int
    repetition: int
    scenario_id: str
    scenario_digest: str
    assignments: Mapping[str, JsonValue]
    status: str
    verdict: str
    run_dir: str
    violations: int
    failed_processes: Mapping[str, int]
    incomplete_processes: tuple[str, ...]
    capabilities: Mapping[str, str]
    resumed: bool
    duration_seconds: float
    configuration_binding: str
    error: Mapping[str, str] | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "index": self.index,
            "repetition": self.repetition,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "assignments": dict(self.assignments),
            "status": self.status,
            "verdict": self.verdict,
            "run_dir": self.run_dir,
            "violations": self.violations,
            "failed_processes": dict(self.failed_processes),
            "incomplete_processes": list(self.incomplete_processes),
            "capabilities": dict(self.capabilities),
            "resumed": self.resumed,
            "duration_seconds": self.duration_seconds,
            "configuration_binding": self.configuration_binding,
        }
        if self.error is not None:
            result["error"] = dict(self.error)
        return result


@dataclass(frozen=True, slots=True)
class CampaignReport:
    schema_version: int
    manifest_digest: str
    case_count: int
    repetitions: int
    trial_count: int
    counts: Mapping[str, int]
    cases: tuple[CampaignCaseResult, ...]
    scenario_summaries: tuple[Mapping[str, JsonValue], ...]
    selection: Mapping[str, JsonValue] | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        value: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "manifest_digest": self.manifest_digest,
            "case_count": self.case_count,
            "repetitions": self.repetitions,
            "trial_count": self.trial_count,
            "counts": dict(self.counts),
            "cases": [case.to_dict() for case in self.cases],
            "scenario_summaries": [dict(summary) for summary in self.scenario_summaries],
        }
        if self.selection is not None:
            value["selection"] = dict(self.selection)
        return value


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"{context} must be a non-empty string")
    return value


def _safe_child(root: Path, relative: str, context: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute():
        raise CampaignError(f"{context} must be relative to the manifest")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise CampaignError(f"{context} escapes the manifest directory")
    return resolved


def load_manifest(path: Path) -> tuple[str, tuple[ManifestCase, ...]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise CampaignError(f"cannot read matrix manifest {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise CampaignError(f"invalid matrix manifest {path}: {error}") from error
    if not isinstance(raw, Mapping) or raw.get("schema_version") != 1:
        raise CampaignError("matrix manifest schema_version must be 1")
    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise CampaignError("matrix manifest cases must be a non-empty array")
    if raw.get("case_count") != len(raw_cases):
        raise CampaignError("matrix manifest case_count does not match cases")

    cases: list[ManifestCase] = []
    seen_ids: set[str] = set()
    seen_paths: set[Path] = set()
    for index, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, Mapping):
            raise CampaignError(f"matrix manifest cases[{index}] must be an object")
        scenario_id = _require_string(raw_case.get("id"), f"cases[{index}].id")
        scenario_digest = _require_string(raw_case.get("digest"), f"cases[{index}].digest")
        if not re.fullmatch(r"[0-9a-f]{64}", scenario_digest):
            raise CampaignError(f"cases[{index}].digest must be a lowercase SHA-256 digest")
        relative_path = _require_string(raw_case.get("file"), f"cases[{index}].file")
        scenario_path = _safe_child(path.parent, relative_path, f"cases[{index}].file")
        assignments = raw_case.get("assignments", {})
        if not isinstance(assignments, Mapping):
            raise CampaignError(f"cases[{index}].assignments must be an object")
        if scenario_id in seen_ids:
            raise CampaignError(f"duplicate matrix scenario id: {scenario_id}")
        if scenario_path in seen_paths:
            raise CampaignError(f"duplicate matrix scenario file: {relative_path}")
        seen_ids.add(scenario_id)
        seen_paths.add(scenario_path)
        cases.append(
            ManifestCase(
                index=index,
                scenario_id=scenario_id,
                scenario_digest=scenario_digest,
                scenario_path=scenario_path,
                assignments=dict(assignments),
            )
        )
    return _canonical_digest(raw), tuple(cases)


def _validate_case(case: ManifestCase) -> Scenario:
    scenario = load_scenario(case.scenario_path)
    if scenario.scenario_id != case.scenario_id:
        raise CampaignError(
            f"manifest id {case.scenario_id!r} does not match {scenario.scenario_id!r}"
        )
    if scenario.digest != case.scenario_digest:
        raise CampaignError(f"scenario digest mismatch for {case.scenario_id}")
    return scenario


def _case_directory(
    run_root: Path,
    case: ManifestCase,
    repetition: int,
    repetitions: int,
) -> Path:
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", case.scenario_id).strip("-")[:96]
    case_root = run_root / f"{case.index:04d}-{slug or 'case'}"
    return case_root if repetitions == 1 else case_root / f"trial-{repetition:04d}"


def _result_from_report(
    case: ManifestCase,
    report: EvaluationReport,
    run_root: Path,
    run_dir: Path,
    *,
    repetition: int,
    resumed: bool,
    duration_seconds: float,
    configuration_binding: str,
) -> CampaignCaseResult:
    violations = sum(result.status.value == "violation" for result in report.oracle_results)
    return CampaignCaseResult(
        index=case.index,
        repetition=repetition,
        scenario_id=case.scenario_id,
        scenario_digest=case.scenario_digest,
        assignments=case.assignments,
        status="completed",
        verdict=report.verdict,
        run_dir=run_dir.relative_to(run_root).as_posix(),
        violations=violations,
        failed_processes=report.failed_processes,
        incomplete_processes=report.incomplete_processes,
        capabilities={
            "confidentiality": report.capabilities.confidentiality,
            "integrity": report.capabilities.integrity,
            "availability": report.capabilities.availability,
        },
        resumed=resumed,
        duration_seconds=round(duration_seconds, 6),
        configuration_binding=configuration_binding,
    )


def _error_result(
    case: ManifestCase,
    run_root: Path,
    run_dir: Path,
    error: Exception,
    duration_seconds: float,
    configuration_binding: str,
    repetition: int,
) -> CampaignCaseResult:
    return CampaignCaseResult(
        index=case.index,
        repetition=repetition,
        scenario_id=case.scenario_id,
        scenario_digest=case.scenario_digest,
        assignments=case.assignments,
        status="error",
        verdict="inconclusive",
        run_dir=run_dir.relative_to(run_root).as_posix(),
        violations=0,
        failed_processes={},
        incomplete_processes=(),
        capabilities={
            "confidentiality": "not_demonstrated",
            "integrity": "not_demonstrated",
            "availability": "not_demonstrated",
        },
        resumed=False,
        duration_seconds=round(duration_seconds, 6),
        configuration_binding=configuration_binding,
        error={"type": type(error).__name__, "message": str(error)},
    )


def _write_case_result(result: CampaignCaseResult, run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "case-result.json").write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _wilson_interval(successes: int, trials: int) -> tuple[float, float] | None:
    if trials == 0:
        return None
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    radius = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / trials + z * z / (4 * trials * trials)
        )
        / denominator
    )
    return max(0.0, center - radius), min(1.0, center + radius)


def _scenario_summaries(
    cases: tuple[ManifestCase, ...],
    results: list[CampaignCaseResult],
    repetitions: int,
) -> tuple[Mapping[str, JsonValue], ...]:
    summaries: list[Mapping[str, JsonValue]] = []
    for case in cases:
        trials = [result for result in results if result.index == case.index]
        violations = sum(result.verdict == "violation" for result in trials)
        passes = sum(result.verdict == "pass" for result in trials)
        inconclusive = sum(result.verdict == "inconclusive" for result in trials)
        errors = sum(result.status == "error" for result in trials)
        conclusive = violations + passes
        interval = _wilson_interval(violations, conclusive)
        outcomes = {
            "error" if result.status == "error" else result.verdict
            for result in trials
        }
        summaries.append(
            {
                "scenario_id": case.scenario_id,
                "scenario_digest": case.scenario_digest,
                "assignments": dict(case.assignments),
                "expected_trials": repetitions,
                "observed_trials": len(trials),
                "pass": passes,
                "violation": violations,
                "inconclusive": inconclusive,
                "error": errors,
                "violation_rate": violations / conclusive if conclusive else None,
                "violation_rate_wilson_95": list(interval) if interval else None,
                "flaky": len(outcomes) > 1,
            }
        )
    return tuple(summaries)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy_assignment(case: ManifestCase) -> bool:
    return any(
        path == "domain_id"
        or path == "governance"
        or path.startswith("governance.")
        or path == "topics"
        or path.startswith("topics.")
        or path == "policy"
        or path.startswith("policy.")
        or (path.startswith("participants.") and ".permissions" in path)
        for path in case.assignments
    )


def _identity_assignment(case: ManifestCase) -> bool:
    return any(
        path.startswith("participants.") and ".identity" in path
        for path in case.assignments
    )


def _materialize_case_policies(
    scenario: Scenario,
    run_dir: Path,
    config: PolicyMaterializationConfig,
    *,
    overwrite: bool,
) -> tuple[dict[str, str], dict[str, JsonValue]]:
    policy_dir = run_dir / "policies"
    artifacts = materialize_policies(
        scenario,
        policy_dir,
        config.subject_names,
        not_before=config.not_before,
        not_after=config.not_after,
        signer_cert=config.signer_cert,
        signer_key=config.signer_key,
        overwrite=overwrite,
    )
    binding: dict[str, JsonValue] = {
        "mode": "scenario_materialized",
        "scenario_digest": scenario.digest,
        "policy_artifacts": dict(artifacts.digests),
        "signed": artifacts.governance_smime is not None,
    }
    if config.signer_cert is not None:
        binding["signer_certificate_sha256"] = _file_digest(config.signer_cert)
    manifest_path = policy_dir / "policy-binding.json"
    manifest_path.write_text(
        json.dumps(binding, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    environment = {
        "DDSLEUTH_FASTDDS_POLICIES": str(policy_dir),
        "DDSLEUTH_POLICY_BINDING": str(manifest_path),
    }
    return environment, binding


def _materialize_case_identities(
    scenario: Scenario,
    run_dir: Path,
    config: IdentityMaterializationConfig,
    *,
    overwrite: bool,
) -> IdentityArtifacts:
    return materialize_identities(
        scenario,
        run_dir / "identities",
        ca_subject=config.ca_subject,
        validity_days=config.validity_days,
        overwrite=overwrite,
    )


def _verify_materialized_binding(
    scenario: Scenario,
    run_dir: Path,
    binding: Mapping[str, JsonValue],
) -> None:
    if binding.get("scenario_digest") != scenario.digest:
        raise CampaignError("evidence configuration binding has a different scenario digest")
    artifacts = binding.get("policy_artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise CampaignError("evidence configuration binding has no policy artifact digests")
    policy_dir = run_dir / "policies"
    for name, expected in artifacts.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise CampaignError("evidence configuration binding contains invalid artifact digests")
        artifact_path = _safe_child(policy_dir, name, f"policy artifact {name!r}")
        if not artifact_path.is_file():
            raise CampaignError(f"materialized policy artifact is missing: {name}")
        if _file_digest(artifact_path) != expected:
            raise CampaignError(f"materialized policy artifact digest mismatch: {name}")

    identity_manifest_digest = binding.get("identity_manifest_sha256")
    if identity_manifest_digest is None:
        return
    if not isinstance(identity_manifest_digest, str):
        raise CampaignError("evidence identity manifest digest is invalid")
    identity_dir = run_dir / "identities"
    identity_manifest = identity_dir / "identity-binding.json"
    if not identity_manifest.is_file():
        raise CampaignError("materialized identity manifest is missing")
    if _file_digest(identity_manifest) != identity_manifest_digest:
        raise CampaignError("materialized identity manifest digest mismatch")
    try:
        identity_binding = json.loads(identity_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignError(f"cannot verify identity manifest: {error}") from error
    if not isinstance(identity_binding, Mapping):
        raise CampaignError("materialized identity manifest is invalid")
    if identity_binding.get("scenario_digest") != scenario.digest:
        raise CampaignError("materialized identities have a different scenario digest")
    ca_file = identity_binding.get("identity_ca_certificate_file")
    ca_digest = identity_binding.get("identity_ca_certificate_sha256")
    if not isinstance(ca_file, str) or not isinstance(ca_digest, str):
        raise CampaignError("materialized identity CA binding is invalid")
    if _file_digest(_safe_child(identity_dir, ca_file, "identity CA certificate")) != ca_digest:
        raise CampaignError("materialized identity CA certificate digest mismatch")
    certificate_files = identity_binding.get("identity_certificate_files")
    certificate_digests = identity_binding.get("identity_certificates")
    if not isinstance(certificate_files, Mapping) or not isinstance(certificate_digests, Mapping):
        raise CampaignError("materialized participant identity binding is invalid")
    if set(certificate_files) != set(scenario.participants) or set(certificate_digests) != set(
        scenario.participants
    ):
        raise CampaignError("materialized participant identity set does not match scenario")
    for actor in scenario.participants:
        name = certificate_files[actor]
        expected = certificate_digests[actor]
        if not isinstance(name, str) or not isinstance(expected, str):
            raise CampaignError("materialized participant certificate binding is invalid")
        certificate = _safe_child(identity_dir, name, f"identity certificate for {actor}")
        if _file_digest(certificate) != expected:
            raise CampaignError(f"materialized identity certificate digest mismatch: {actor}")


def run_campaign(
    manifest_path: Path,
    run_root: Path,
    environment: Mapping[str, str],
    *,
    allow_external: bool = False,
    overwrite: bool = False,
    resume: bool = False,
    stop_on_error: bool = False,
    policy_config: PolicyMaterializationConfig | None = None,
    identity_config: IdentityMaterializationConfig | None = None,
    allow_unbound_configuration: bool = False,
    repetitions: int = 1,
    selection_strategy: str = "manifest",
    execution_budget: int | None = None,
    selection_seed: int = 0,
) -> CampaignReport:
    if overwrite and resume:
        raise CampaignError("--overwrite and --resume are mutually exclusive")
    if identity_config is not None and policy_config is not None:
        raise CampaignError("generated identities and explicit policy configuration are mutually exclusive")
    if repetitions <= 0 or repetitions > 1000:
        raise CampaignError("repetitions must be between 1 and 1000")
    manifest_digest, cases = load_manifest(manifest_path)
    if selection_strategy not in ("manifest", "coverage-guided"):
        raise CampaignError("selection strategy must be manifest or coverage-guided")
    if execution_budget is None:
        execution_budget = len(cases)
    if execution_budget <= 0 or execution_budget > len(cases):
        raise CampaignError("execution budget must be between 1 and the manifest case count")
    run_root = run_root.resolve()
    summary_path = run_root / "campaign-report.json"
    if summary_path.exists() and not (overwrite or resume):
        raise CampaignError(f"campaign output already exists: {summary_path}")
    run_root.mkdir(parents=True, exist_ok=True)

    results: list[CampaignCaseResult] = []
    adapter = FastDDSAdapter()
    stopped = False
    scheduler = None
    pending = list(cases)
    selected_cases: list[ManifestCase] = []
    if selection_strategy == "coverage-guided":
        from .coverage import CoverageGuidedScheduler

        scheduler = CoverageGuidedScheduler(cases, seed=selection_seed)

    while pending and len(selected_cases) < execution_budget:
        case = scheduler.choose(pending) if scheduler is not None else pending[0]
        pending.remove(case)
        selected_cases.append(case)
        case_evidence = []
        for repetition in range(repetitions):
            started = time.monotonic()
            run_dir = _case_directory(run_root, case, repetition, repetitions)
            binding_mode = "external_unverified"
            try:
                scenario = _validate_case(case)
                if scenario.implementation != adapter.name:
                    raise CampaignError(
                        f"no campaign adapter is registered for {scenario.implementation!r}"
                    )

                evidence_path = run_dir / "evidence.json"
                report_path = run_dir / "report.json"
                if resume and evidence_path.exists():
                    evidence = load_evidence(evidence_path)
                    raw_binding = evidence.metadata.get("configuration_binding", {})
                    if isinstance(raw_binding, Mapping):
                        mode = raw_binding.get("mode")
                        if isinstance(mode, str):
                            binding_mode = mode
                    if binding_mode == "scenario_materialized":
                        if not isinstance(raw_binding, Mapping):
                            raise CampaignError("invalid materialized configuration binding")
                        _verify_materialized_binding(scenario, run_dir, raw_binding)
                        if _identity_assignment(case) and "identity_manifest_sha256" not in raw_binding:
                            raise CampaignError(
                                "resumed identity matrix evidence is not bound to materialized identities"
                            )
                    elif (
                        _policy_assignment(case) or _identity_assignment(case)
                    ) and not allow_unbound_configuration:
                        raise CampaignError(
                            "resumed matrix evidence is not bound to materialized configuration"
                        )
                    report = evaluate(scenario, evidence)
                    write_report(report, report_path)
                    write_candidates(
                        discover_candidates(scenario, evidence, report),
                        run_dir / "candidates.json",
                    )
                    result = _result_from_report(
                        case,
                        report,
                        run_root,
                        run_dir,
                        repetition=repetition,
                        resumed=True,
                        duration_seconds=time.monotonic() - started,
                        configuration_binding=binding_mode,
                    )
                else:
                    case_environment = dict(environment)
                    role_environments: Mapping[str, Mapping[str, str]] | None = None
                    configuration_binding: Mapping[str, JsonValue] = {
                        "mode": "external_unverified",
                        "scenario_digest": scenario.digest,
                    }
                    effective_policy_config = policy_config
                    identities = None
                    if identity_config is not None:
                        identities = _materialize_case_identities(
                            scenario,
                            run_dir,
                            identity_config,
                            overwrite=overwrite or resume,
                        )
                        all_role_environments = identities.role_environments()
                        execution_actors = (
                            {role.actor for role in scenario.execution.roles}
                            if scenario.execution is not None
                            else set()
                        )
                        role_environments = {
                            actor: values
                            for actor, values in all_role_environments.items()
                            if actor in execution_actors
                        }
                        effective_policy_config = PolicyMaterializationConfig(
                            subject_names=identities.subject_names,
                            signer_cert=identities.ca_certificate,
                            signer_key=identities.ca_private_key,
                        )
                    if (
                        _identity_assignment(case)
                        and identities is None
                        and not allow_unbound_configuration
                    ):
                        raise CampaignError(
                            "identity-related matrix assignments require per-case identity "
                            "materialization; use generated identities or explicitly allow "
                            "an unbound diagnostic run"
                        )
                    if effective_policy_config is not None:
                        generated_environment, configuration_binding = _materialize_case_policies(
                            scenario,
                            run_dir,
                            effective_policy_config,
                            overwrite=overwrite or resume,
                        )
                        case_environment.update(generated_environment)
                        binding_mode = "scenario_materialized"
                        if identities is not None:
                            merged_binding = dict(configuration_binding)
                            merged_binding.update(identities.evidence_binding())
                            merged_binding["identity_manifest_sha256"] = _file_digest(
                                identities.manifest
                            )
                            configuration_binding = merged_binding
                    elif _policy_assignment(case) and not allow_unbound_configuration:
                        raise CampaignError(
                            "policy-related matrix assignments require per-case policy "
                            "materialization; use policy configuration or explicitly allow "
                            "an unbound diagnostic run"
                        )
                    evidence = adapter.run(
                        scenario,
                        run_dir,
                        case_environment,
                        allow_external=allow_external,
                        overwrite=overwrite,
                        configuration_binding=configuration_binding,
                        role_environments=role_environments,
                    )
                    write_evidence(evidence, evidence_path)
                    report = evaluate(scenario, evidence)
                    write_report(report, report_path)
                    write_candidates(
                        discover_candidates(scenario, evidence, report),
                        run_dir / "candidates.json",
                    )
                    result = _result_from_report(
                        case,
                        report,
                        run_root,
                        run_dir,
                        repetition=repetition,
                        resumed=False,
                        duration_seconds=time.monotonic() - started,
                        configuration_binding=binding_mode,
                    )
                if result.status == "completed":
                    case_evidence.append(evidence)
            except (OSError, ValueError, RuntimeError) as error:
                result = _error_result(
                    case,
                    run_root,
                    run_dir,
                    error,
                    time.monotonic() - started,
                    binding_mode,
                    repetition,
                )
            _write_case_result(result, run_dir)
            results.append(result)
            if stop_on_error and result.status == "error":
                stopped = True
                break
        if scheduler is not None:
            scheduler.observe(case, case_evidence)
        if stopped:
            break

    trial_count = execution_budget * repetitions
    counts = {
        "completed": sum(result.status == "completed" for result in results),
        "error": sum(result.status == "error" for result in results),
        "pass": sum(result.verdict == "pass" for result in results),
        "violation": sum(result.verdict == "violation" for result in results),
        "inconclusive": sum(result.verdict == "inconclusive" for result in results),
        "not_run": trial_count - len(results),
    }
    campaign = CampaignReport(
        schema_version=1,
        manifest_digest=manifest_digest,
        case_count=execution_budget,
        repetitions=repetitions,
        trial_count=trial_count,
        counts=counts,
        cases=tuple(results),
        scenario_summaries=_scenario_summaries(tuple(selected_cases), results, repetitions),
        selection=(
            scheduler.summary(len(cases), execution_budget)
            if scheduler is not None
            else None
        ),
    )
    summary_path.write_text(
        json.dumps(campaign.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return campaign
