from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from .adapters.fastdds import FastDDSAdapter, FastDDSLegacyTextImporter
from . import __version__
from .artifacts import discover_artifacts, write_artifacts
from .campaign import (
    IdentityMaterializationConfig,
    PolicyMaterializationConfig,
    load_campaign_report,
    run_campaign,
)
from .evidence import EvidenceBundle, load_evidence, write_evidence
from .identity import materialize_identities
from .matrix import parse_dimension, write_matrix
from .explorer import analyze_exploration
from .oracles.evaluate import evaluate
from .policy import materialize_policies
from .reporting import concise_summary, write_report
from .reduction import causal_action_prefilter
from .scenario import ScenarioError, load_scenario
from .trajectory import write_trajectory_manifest


def _key_value(values: Sequence[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"{label} must use NAME=VALUE: {value!r}")
        key, item = value.split("=", 1)
        if not key:
            raise ValueError(f"{label} name must not be empty")
        result[key] = item
    return result


def _write_or_print_json(value: object, output: str | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
    else:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")


def _cmd_validate(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    print(f"valid scenario: {scenario.scenario_id}")
    print(f"implementation: {scenario.implementation}")
    print(f"digest: {scenario.digest}")
    return 0


def _cmd_import_fastdds(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    log_values = _key_value(args.log, "--log")
    status_values = _key_value(args.status, "--status")
    logs = {actor: Path(path) for actor, path in log_values.items()}
    statuses = {actor: int(status) for actor, status in status_values.items()}
    importer = FastDDSLegacyTextImporter()
    events = importer.import_logs(logs, statuses)
    bundle = EvidenceBundle.create(
        run_id=args.run_id,
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest,
        implementation="fastdds",
        events=events,
        metadata={"source": "imported-fastdds-logs"},
    )
    write_evidence(bundle, args.output)
    print(f"imported {len(bundle.events)} events into {args.output}")
    return 0


def _cmd_evaluate(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    evidence = load_evidence(args.evidence)
    report = evaluate(scenario, evidence)
    artifacts = discover_artifacts(scenario, evidence)
    if args.output:
        write_report(report, args.output)
    else:
        _write_or_print_json(report.to_dict(), None)
    if args.artifacts_output:
        write_artifacts(artifacts, args.artifacts_output)
    if args.candidates_output:
        from .candidates import discover_candidates, write_candidates

        write_candidates(
            discover_candidates(scenario, evidence, report),
            args.candidates_output,
        )
    print(concise_summary(report))
    if report.failed_processes or report.incomplete_processes:
        return 3
    return 2 if args.fail_on_violation and report.verdict == "violation" else 0


def _cmd_extract_artifacts(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    evidence = load_evidence(args.evidence)
    bundle = discover_artifacts(scenario, evidence)
    write_artifacts(bundle, args.output)
    print(f"artifacts={len(bundle.artifacts)}")
    print(f"output={args.output}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    environment = dict(os.environ)
    environment.update(_key_value(args.env, "--env"))
    if scenario.implementation != "fastdds":
        raise ValueError(f"no adapter is registered for {scenario.implementation!r}")

    run_dir = Path(args.run_dir)
    adapter = FastDDSAdapter()
    evidence = adapter.run(
        scenario,
        run_dir,
        environment,
        allow_external=args.allow_external,
        overwrite=args.overwrite,
    )
    evidence_path = run_dir / "evidence.json"
    report_path = run_dir / "report.json"
    write_evidence(evidence, evidence_path)
    report = evaluate(scenario, evidence)
    write_report(report, report_path)
    artifacts_path = run_dir / "artifacts.json"
    write_artifacts(discover_artifacts(scenario, evidence), artifacts_path)
    print(concise_summary(report))
    print(f"evidence={evidence_path}")
    print(f"report={report_path}")
    print(f"artifacts={artifacts_path}")
    if report.failed_processes or report.incomplete_processes:
        return 3
    return 2 if args.fail_on_violation and report.verdict == "violation" else 0


def _cmd_materialize_policies(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    subjects = _key_value(args.subject, "--subject")
    signer_cert = Path(args.signer_cert) if args.signer_cert else None
    signer_key = Path(args.signer_key) if args.signer_key else None
    artifacts = materialize_policies(
        scenario,
        Path(args.output_dir),
        subjects,
        not_before=args.not_before,
        not_after=args.not_after,
        signer_cert=signer_cert,
        signer_key=signer_key,
        overwrite=args.overwrite,
    )
    for name, digest in artifacts.digests.items():
        print(f"{digest}  {name}")
    return 0


def _cmd_expand_matrix(args: argparse.Namespace) -> int:
    dimensions = [parse_dimension(specification) for specification in args.dimension]
    manifest = write_matrix(
        Path(args.scenario),
        Path(args.output_dir),
        dimensions,
        max_cases=args.max_cases,
        overwrite=args.overwrite,
        strategy=args.strategy,
    )
    print(f"manifest={manifest}")
    return 0


def _cmd_materialize_identities(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    artifacts = materialize_identities(
        scenario,
        Path(args.output_dir),
        ca_subject=args.ca_subject,
        validity_days=args.validity_days,
        overwrite=args.overwrite,
    )
    print(f"{artifacts.ca_certificate_sha256}  {artifacts.ca_certificate.name}")
    for actor, identity in artifacts.participants.items():
        print(f"{identity.certificate_sha256}  {actor}  {identity.subject_name}")
    print(f"manifest={artifacts.manifest}")
    return 0


def _cmd_run_matrix(args: argparse.Namespace) -> int:
    environment = dict(os.environ)
    environment.update(_key_value(args.env, "--env"))
    policy_config = None
    if args.materialize_identities and args.materialize_policies:
        raise ValueError("--materialize-identities and --materialize-policies are mutually exclusive")
    if args.materialize_policies:
        subjects = _key_value(args.subject, "--subject")
        if not subjects:
            raise ValueError("--materialize-policies requires at least one --subject")
        signer_cert = Path(args.signer_cert) if args.signer_cert else None
        signer_key = Path(args.signer_key) if args.signer_key else None
        policy_config = PolicyMaterializationConfig(
            subject_names=subjects,
            signer_cert=signer_cert,
            signer_key=signer_key,
            not_before=args.not_before,
            not_after=args.not_after,
        )
    identity_config = None
    if args.materialize_identities:
        identity_config = IdentityMaterializationConfig(
            ca_subject=args.identity_ca_subject,
            validity_days=args.identity_validity_days,
        )
    campaign = run_campaign(
        Path(args.manifest),
        Path(args.run_root),
        environment,
        allow_external=args.allow_external,
        overwrite=args.overwrite,
        resume=args.resume,
        stop_on_error=args.stop_on_error,
        policy_config=policy_config,
        identity_config=identity_config,
        allow_unbound_configuration=args.allow_unbound_configuration,
        repetitions=args.repetitions,
    )
    print(f"cases={campaign.case_count}")
    print(f"repetitions={campaign.repetitions}")
    print(f"trials={campaign.trial_count}")
    for name in ("completed", "error", "pass", "violation", "inconclusive", "not_run"):
        print(f"{name}={campaign.counts[name]}")
    print(f"report={Path(args.run_root) / 'campaign-report.json'}")
    if campaign.counts["error"] or campaign.counts["inconclusive"]:
        return 3
    return 2 if args.fail_on_violation and campaign.counts["violation"] else 0


def _cmd_explore(args: argparse.Namespace) -> int:
    environment = dict(os.environ)
    environment.update(_key_value(args.env, "--env"))
    if args.materialize_identities and args.materialize_policies:
        raise ValueError("--materialize-identities and --materialize-policies are mutually exclusive")

    policy_config = None
    if args.materialize_policies:
        subjects = _key_value(args.subject, "--subject")
        if not subjects:
            raise ValueError("--materialize-policies requires at least one --subject")
        policy_config = PolicyMaterializationConfig(
            subject_names=subjects,
            signer_cert=Path(args.signer_cert) if args.signer_cert else None,
            signer_key=Path(args.signer_key) if args.signer_key else None,
            not_before=args.not_before,
            not_after=args.not_after,
        )
    identity_config = None
    if args.materialize_identities:
        identity_config = IdentityMaterializationConfig(
            ca_subject=args.identity_ca_subject,
            validity_days=args.identity_validity_days,
        )

    output_root = Path(args.output_root)
    pool_size = args.pool_size
    if pool_size is None:
        pool_size = (
            min(4096, max(args.budget, args.budget * 4))
            if args.strategy in ("artifact-guided", "coverage-guided")
            else args.budget
        )
    if pool_size < args.budget:
        raise ValueError("--pool-size cannot be smaller than --budget")
    manifest = write_trajectory_manifest(
        Path(args.scenario),
        output_root / "trajectories",
        dimensions=[parse_dimension(value) for value in args.dimension],
        dimension_strategy=args.dimension_strategy,
        spacings_ms=args.spacing_ms or (0, 25, 250),
        barrier_modes=args.barrier_mode or ("preserve", "relaxed"),
        action_jitters_ms=args.action_jitter_ms or (0, 10, 50),
        boundary_offsets_ms=args.boundary_offset_ms or (0, -50, -10, 10, 50),
        budget=pool_size,
        execution_budget=args.budget,
        seed=args.seed,
        overwrite=args.overwrite or args.resume,
    )
    manifest_raw = json.loads(manifest.read_text(encoding="utf-8"))
    execution_budget = int(manifest_raw["execution_budget"])
    campaign = run_campaign(
        manifest,
        output_root / "runs",
        environment,
        allow_external=args.allow_external,
        overwrite=args.overwrite,
        resume=args.resume,
        stop_on_error=args.stop_on_error,
        policy_config=policy_config,
        identity_config=identity_config,
        allow_unbound_configuration=args.allow_unbound_configuration,
        repetitions=args.repetitions,
        baseline_repetitions=args.baseline_repetitions,
        confirmation_repetitions=args.confirmation_repetitions,
        selection_strategy=args.strategy,
        execution_budget=execution_budget,
        selection_seed=args.seed,
        plateau_window=args.plateau_window,
        corpus_path=(
            Path(args.corpus)
            if args.corpus
            else output_root / "artifact-corpus.json"
        ),
    )
    exploration_path = output_root / "exploration-report.json"
    exploration = analyze_exploration(
        manifest,
        output_root / "runs",
        campaign,
        exploration_path,
    )
    print(f"trajectories={exploration['generated_trajectories']}")
    print(f"trials={exploration['expected_trials']}")
    print(f"analyzed={exploration['analyzed_trials']}")
    print(f"artifact_clusters={exploration['artifact_cluster_count']}")
    print(f"semantic_artifact_clusters={exploration['semantic_artifact_cluster_count']}")
    print(f"context_clusters={exploration['context_cluster_count']}")
    print(f"mutation_only_artifacts={exploration['mutation_only_artifact_clusters']}")
    print(f"confirmed_artifacts={exploration['confirmed_artifact_clusters']}")
    print(f"report={exploration_path}")
    if campaign.counts["error"]:
        return 3
    if (args.fail_on_artifact or args.fail_on_candidate) and exploration["artifact_cluster_count"]:
        return 2
    return 0


def _cmd_analyze_exploration(args: argparse.Namespace) -> int:
    campaign = load_campaign_report(args.campaign_report)
    report = analyze_exploration(
        Path(args.manifest),
        Path(args.run_root),
        campaign,
        Path(args.output),
    )
    print(f"artifact_clusters={report['artifact_cluster_count']}")
    print(f"novel_artifacts={report['novel_artifact_clusters']}")
    print(f"output={args.output}")
    return 0


def _cmd_plan_reduction(args: argparse.Namespace) -> int:
    scenario = load_scenario(args.scenario)
    evidence = load_evidence(args.evidence)
    artifacts = discover_artifacts(scenario, evidence).artifacts
    artifact = next(
        (item for item in artifacts if item.fingerprint == args.fingerprint),
        None,
    )
    if artifact is None:
        raise ValueError("target fingerprint is not present in the supplied evidence")
    plan = causal_action_prefilter(scenario.raw, evidence, artifact)
    _write_or_print_json(plan, args.output)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ddsleuth",
        description="Runtime artifact discovery for DDS security boundaries",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate and identify a scenario")
    validate.add_argument("scenario")
    validate.set_defaults(handler=_cmd_validate)

    import_fastdds = subparsers.add_parser(
        "import-fastdds-logs",
        help="normalize logs from the original Fast DDS harness",
    )
    import_fastdds.add_argument("scenario")
    import_fastdds.add_argument("--log", action="append", default=[], metavar="ACTOR=PATH", required=True)
    import_fastdds.add_argument(
        "--status", action="append", default=[], metavar="ACTOR=CODE", required=True
    )
    import_fastdds.add_argument("--run-id", default="imported-fastdds-run")
    import_fastdds.add_argument("--output", required=True)
    import_fastdds.set_defaults(handler=_cmd_import_fastdds)

    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate normalized evidence")
    evaluate_parser.add_argument("scenario")
    evaluate_parser.add_argument("evidence")
    evaluate_parser.add_argument("--output")
    evaluate_parser.add_argument("--artifacts-output")
    evaluate_parser.add_argument("--candidates-output")
    evaluate_parser.add_argument("--fail-on-violation", action="store_true")
    evaluate_parser.set_defaults(handler=_cmd_evaluate)

    extract_artifacts = subparsers.add_parser(
        "extract-artifacts",
        help="extract neutral runtime artifacts from normalized evidence",
    )
    extract_artifacts.add_argument("scenario")
    extract_artifacts.add_argument("evidence")
    extract_artifacts.add_argument("--output", required=True)
    extract_artifacts.set_defaults(handler=_cmd_extract_artifacts)

    run = subparsers.add_parser("run", help="run a scenario with its implementation adapter")
    run.add_argument("scenario")
    run.add_argument("--run-dir", required=True)
    run.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    run.add_argument("--overwrite", action="store_true")
    run.add_argument("--allow-external", action="store_true")
    run.add_argument("--fail-on-violation", action="store_true")
    run.set_defaults(handler=_cmd_run)

    policies = subparsers.add_parser(
        "materialize-policies",
        help="generate Governance and Permissions documents from a scenario",
    )
    policies.add_argument("scenario")
    policies.add_argument("--output-dir", required=True)
    policies.add_argument(
        "--subject", action="append", default=[], metavar="ACTOR=SUBJECT_NAME", required=True
    )
    policies.add_argument("--not-before", default="2020-01-01T00:00:00")
    policies.add_argument("--not-after", default="2038-01-01T00:00:00")
    policies.add_argument("--signer-cert")
    policies.add_argument("--signer-key")
    policies.add_argument("--overwrite", action="store_true")
    policies.set_defaults(handler=_cmd_materialize_policies)

    identities = subparsers.add_parser(
        "materialize-identities",
        help="generate an ephemeral CA and one identity certificate per participant",
    )
    identities.add_argument("scenario")
    identities.add_argument("--output-dir", required=True)
    identities.add_argument(
        "--ca-subject",
        default="/CN=DDSleuth Ephemeral Identity CA",
    )
    identities.add_argument("--validity-days", type=int, default=7)
    identities.add_argument("--overwrite", action="store_true")
    identities.set_defaults(handler=_cmd_materialize_identities)

    matrix = subparsers.add_parser(
        "expand-matrix",
        help="expand scenario fields into a deterministic Cartesian test matrix",
    )
    matrix.add_argument("scenario")
    matrix.add_argument("--output-dir", required=True)
    matrix.add_argument(
        "--dimension",
        action="append",
        required=True,
        metavar='DOTTED.PATH=["value1","value2"]',
    )
    matrix.add_argument("--max-cases", type=int, default=256)
    matrix.add_argument("--strategy", choices=("cartesian", "pairwise"), default="cartesian")
    matrix.add_argument("--overwrite", action="store_true")
    matrix.set_defaults(handler=_cmd_expand_matrix)

    run_matrix = subparsers.add_parser(
        "run-matrix",
        help="run and summarize every scenario in a matrix manifest",
    )
    run_matrix.add_argument("manifest")
    run_matrix.add_argument("--run-root", required=True)
    run_matrix.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    run_matrix.add_argument("--overwrite", action="store_true")
    run_matrix.add_argument("--resume", action="store_true")
    run_matrix.add_argument("--stop-on-error", action="store_true")
    run_matrix.add_argument("--allow-external", action="store_true")
    run_matrix.add_argument("--fail-on-violation", action="store_true")
    run_matrix.add_argument("--repetitions", type=int, default=1)
    run_matrix.add_argument("--materialize-policies", action="store_true")
    run_matrix.add_argument("--materialize-identities", action="store_true")
    run_matrix.add_argument(
        "--identity-ca-subject",
        default="/CN=DDSleuth Ephemeral Identity CA",
    )
    run_matrix.add_argument("--identity-validity-days", type=int, default=7)
    run_matrix.add_argument("--subject", action="append", default=[], metavar="ACTOR=SUBJECT_NAME")
    run_matrix.add_argument("--signer-cert")
    run_matrix.add_argument("--signer-key")
    run_matrix.add_argument("--not-before", default="2020-01-01T00:00:00")
    run_matrix.add_argument("--not-after", default="2038-01-01T00:00:00")
    run_matrix.add_argument(
        "--allow-unbound-configuration",
        action="store_true",
        help="allow policy matrix cases to use external policies (diagnostic only)",
    )
    run_matrix.set_defaults(handler=_cmd_run_matrix)

    explore = subparsers.add_parser(
        "explore",
        help="discover runtime artifacts across stateful DDS security boundaries",
    )
    explore.add_argument("scenario")
    explore.add_argument("--output-root", required=True)
    explore.add_argument("--budget", type=int, default=64)
    explore.add_argument(
        "--strategy",
        choices=("artifact-guided", "coverage-guided", "manifest"),
        default="artifact-guided",
        help="select trajectories from artifact novelty feedback or manifest order",
    )
    explore.add_argument(
        "--pool-size",
        type=int,
        help="trajectory pool (default: 4x execution budget for guided runs)",
    )
    explore.add_argument("--seed", type=int, default=0)
    explore.add_argument(
        "--corpus",
        help="persistent cross-run artifact corpus (default: OUTPUT_ROOT/artifact-corpus.json)",
    )
    explore.add_argument(
        "--plateau-window",
        type=int,
        default=20,
        help="stop after this many trajectories add no runtime artifact features (0 disables)",
    )
    explore.add_argument("--spacing-ms", action="append", type=int)
    explore.add_argument(
        "--barrier-mode",
        action="append",
        choices=("preserve", "relaxed"),
    )
    explore.add_argument(
        "--action-jitter-ms",
        action="append",
        type=int,
        help="stable per-action timing perturbation included in the trajectory pool",
    )
    explore.add_argument(
        "--boundary-offset-ms",
        action="append",
        type=int,
        help="shift only revoke/rekey/reconnect/lifecycle/transport actions",
    )
    explore.add_argument("--dimension", action="append", default=[])
    explore.add_argument(
        "--dimension-strategy",
        choices=("cartesian", "pairwise"),
        default="pairwise",
    )
    explore.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    explore.add_argument("--overwrite", action="store_true")
    explore.add_argument("--resume", action="store_true")
    explore.add_argument("--stop-on-error", action="store_true")
    explore.add_argument("--allow-external", action="store_true")
    explore.add_argument("--fail-on-artifact", action="store_true")
    explore.add_argument(
        "--fail-on-candidate",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    explore.add_argument("--repetitions", type=int, default=1)
    explore.add_argument(
        "--baseline-repetitions",
        type=int,
        default=3,
        help="repeat matched control trajectories to measure normal runtime variance",
    )
    explore.add_argument(
        "--confirmation-repetitions",
        type=int,
        default=2,
        help="automatically rerun an exact trajectory when it yields a new semantic artifact",
    )
    explore.add_argument("--materialize-policies", action="store_true")
    explore.add_argument("--materialize-identities", action="store_true")
    explore.add_argument(
        "--identity-ca-subject",
        default="/CN=DDSleuth Ephemeral Identity CA",
    )
    explore.add_argument("--identity-validity-days", type=int, default=7)
    explore.add_argument("--subject", action="append", default=[], metavar="ACTOR=SUBJECT_NAME")
    explore.add_argument("--signer-cert")
    explore.add_argument("--signer-key")
    explore.add_argument("--not-before", default="2020-01-01T00:00:00")
    explore.add_argument("--not-after", default="2038-01-01T00:00:00")
    explore.add_argument("--allow-unbound-configuration", action="store_true")
    explore.set_defaults(handler=_cmd_explore)

    analyze = subparsers.add_parser(
        "analyze-exploration",
        help="rebuild artifact clusters from an existing trajectory campaign",
    )
    analyze.add_argument("manifest")
    analyze.add_argument("--run-root", required=True)
    analyze.add_argument("--campaign-report", required=True)
    analyze.add_argument("--output", required=True)
    analyze.set_defaults(handler=_cmd_analyze_exploration)

    reduce_plan = subparsers.add_parser(
        "plan-reduction",
        help="build a causal action prefilter for later artifact-preserving ddmin",
    )
    reduce_plan.add_argument("scenario")
    reduce_plan.add_argument("evidence")
    reduce_plan.add_argument("fingerprint")
    reduce_plan.add_argument("--output")
    reduce_plan.set_defaults(handler=_cmd_plan_reduction)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, ScenarioError) as error:
        parser.error(str(error))
    return 2
