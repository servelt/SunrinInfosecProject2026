from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = 1


def stable_id(prefix: str, *parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]}"


def as_json(value: object) -> dict[str, Any]:
    def convert(item: object) -> object:
        if isinstance(item, StringEnum):
            return str(item)
        if isinstance(item, Path):
            return str(item)
        if dataclasses.is_dataclass(item):
            return {f.name: convert(getattr(item, f.name)) for f in dataclasses.fields(item)}
        if isinstance(item, dict):
            return {str(k): convert(v) for k, v in item.items()}
        if isinstance(item, (list, tuple, set)):
            return [convert(v) for v in item]
        return item

    converted = convert(value)
    if not isinstance(converted, dict):
        raise TypeError("top-level value must serialize to an object")
    return converted


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class Verdict(StringEnum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"


class CheckStatus(StringEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class AttackerFeasibility(StringEnum):
    """How realistic it is for the input-controlling subject to be an attacker."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    IMPLAUSIBLE = "IMPLAUSIBLE"
    UNKNOWN = "UNKNOWN"


class AttackAccess(StringEnum):
    UNAUTHENTICATED_REMOTE = "UNAUTHENTICATED_REMOTE"
    AUTHENTICATED_ORDINARY_USER = "AUTHENTICATED_ORDINARY_USER"
    LOCAL_ORDINARY_USER = "LOCAL_ORDINARY_USER"
    PRIVILEGED_USER = "PRIVILEGED_USER"
    TRUSTED_COMPONENT_CONTROL = "TRUSTED_COMPONENT_CONTROL"
    IMPLAUSIBLE = "IMPLAUSIBLE"
    UNKNOWN = "UNKNOWN"


class ImpactScope(StringEnum):
    ORDINARY_USER_PROCESS = "ORDINARY_USER_PROCESS"
    SENSITIVE_DATA = "SENSITIVE_DATA"
    PRIVILEGED_PROCESS = "PRIVILEGED_PROCESS"
    SYSTEM_WIDE = "SYSTEM_WIDE"
    UNKNOWN = "UNKNOWN"


class HarnessDisposition(StringEnum):
    KEEP = "KEEP"
    DISCARD = "DISCARD"


class EntrySiteKind(StringEnum):
    DIRECT_ACQUISITION = "DIRECT_ACQUISITION"
    PROCESS_START = "PROCESS_START"
    EXPORTED_API = "EXPORTED_API"
    EXTERNAL_CALLBACK = "EXTERNAL_CALLBACK"


@dataclass(slots=True)
class ProjectSpec:
    source_root: Path
    output_root: Path
    name: str = "project"
    fuzz_introspector: Path | None = None
    require_fuzz_introspector: bool = True
    language: str = "c_cpp"
    # ``oss-fuzz`` is the paper-comparable path: generated code replaces a
    # real OSS-Fuzz target and is built/run/covered in that project's image.
    # ``command`` is retained for projects without an OSS-Fuzz integration,
    # but cannot by itself claim QuartetFuzz parity.
    verification_backend: str = "command"
    build_command: list[str] = field(default_factory=list)
    harness_binary: str | Path | None = None
    harness_source_filename: str = "fuzz_target.cc"
    oss_fuzz_project: str | None = None
    oss_fuzz_fuzzer: str | None = None
    # Absolute directory inside the OSS-Fuzz builder image that contains the
    # application checkout.  HarnessCreator overlays ``source_root`` here so
    # verification measures the repository the user actually requested, not
    # whichever revision the upstream Dockerfile happens to clone.
    oss_fuzz_source_path: str | None = None
    oss_fuzz_dir: Path | None = None
    oss_fuzz_revision: str | None = None
    # Set only after the pinned canonical harness has been built and executed
    # against this exact local source overlay during CLI preflight.
    canonical_oss_fuzz_preflight_passed: bool = False
    quartet_root: Path | None = None
    fuzz_seconds: int = 300
    max_context_functions: int = 16
    context_depth: int = 3
    entry_batch_size: int = 32

    def normalized(self) -> "ProjectSpec":
        source = self.source_root.expanduser().resolve()
        output = self.output_root.expanduser().resolve()
        if not source.is_dir():
            raise ValueError(f"source root is not a directory: {source}")
        if output == source:
            raise ValueError("output root must not be the project source root")
        if self.fuzz_seconds < 1:
            raise ValueError("fuzz_seconds must be positive")
        if self.context_depth < 1 or self.max_context_functions < 1 or self.entry_batch_size < 1:
            raise ValueError("context depth, function budget, and entry batch size must be positive")
        if self.verification_backend not in {"command", "oss-fuzz"}:
            raise ValueError("verification_backend must be 'command' or 'oss-fuzz'")
        if self.verification_backend == "oss-fuzz":
            if not self.oss_fuzz_project or not self.oss_fuzz_fuzzer:
                raise ValueError("oss-fuzz verification requires project and fuzzer names")
            if not re.fullmatch(r"[A-Za-z0-9._+-]+", self.oss_fuzz_project):
                raise ValueError("oss_fuzz_project is not a valid OSS-Fuzz project identifier")
            if not re.fullmatch(r"[A-Za-z0-9._+-]+", self.oss_fuzz_fuzzer):
                raise ValueError("oss_fuzz_fuzzer is not a valid binary identifier")
            container_source = PurePosixPath(self.oss_fuzz_source_path or "")
            if (
                not self.oss_fuzz_source_path
                or not container_source.is_absolute()
                or ".." in container_source.parts
                or not str(container_source).startswith("/src/")
                or not re.fullmatch(r"/src/[A-Za-z0-9._/-]+", str(container_source))
            ):
                raise ValueError(
                    "oss_fuzz_source_path must be an absolute application checkout under /src"
                )
        source_filename = Path(self.harness_source_filename).name
        if source_filename != self.harness_source_filename or Path(source_filename).suffix.lower() not in {
            ".c", ".cc", ".cpp", ".cxx"
        }:
            raise ValueError("harness_source_filename must be a C/C++ basename")
        oss_fuzz_dir = self.oss_fuzz_dir.expanduser().resolve() if self.oss_fuzz_dir else None
        quartet_root = self.quartet_root.expanduser().resolve() if self.quartet_root else None
        binary: str | Path | None = self.harness_binary
        if binary and not any(token in str(binary) for token in ("{harness}", "{source_root}", "{output}")):
            binary = Path(binary).expanduser().resolve()
        return dataclasses.replace(
            self,
            source_root=source,
            output_root=output,
            harness_binary=binary,
            harness_source_filename=source_filename,
            oss_fuzz_source_path=(
                str(PurePosixPath(self.oss_fuzz_source_path))
                if self.oss_fuzz_source_path
                else None
            ),
            oss_fuzz_dir=oss_fuzz_dir,
            quartet_root=quartet_root,
        )


@dataclass(slots=True)
class CallEdge:
    edge_id: str
    caller_id: str
    callee_id: str
    line: int | None = None
    kind: str = "direct"
    confidence: float = 1.0
    providers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FunctionMetadata:
    function_id: str
    name: str
    qualified_name: str
    signature: str
    language: str
    file: str
    start_line: int
    end_line: int
    source: str
    declaration: str = ""
    headers: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    build_targets: list[str] = field(default_factory=list)
    globals_read: list[str] = field(default_factory=list)
    globals_written: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        name: str,
        signature: str,
        file: str,
        start_line: int,
        end_line: int,
        source: str,
        language: str = "c_cpp",
        qualified_name: str | None = None,
        provider: str = "source-metadata",
    ) -> "FunctionMetadata":
        qualified = qualified_name or name
        identifier = stable_id("fn", language, qualified, file, start_line)
        return cls(
            function_id=identifier,
            name=name,
            qualified_name=qualified,
            signature=signature,
            language=language,
            file=file,
            start_line=start_line,
            end_line=end_line,
            source=source,
            providers=[provider],
        )


@dataclass(slots=True)
class AnalysisBundle:
    functions: dict[str, FunctionMetadata]
    edges: list[CallEdge]
    completeness: dict[str, Any] = field(default_factory=dict)

    def function_list(self) -> list[FunctionMetadata]:
        return sorted(self.functions.values(), key=lambda f: (f.file, f.start_line, f.name))


@dataclass(slots=True)
class Evidence:
    kind: str
    function_id: str
    file: str
    line: int | None
    detail: str


@dataclass(slots=True)
class EntryCandidate:
    candidate_id: str
    function_id: str
    source_api: str
    line: int | None
    channel_hint: str
    rationale: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    site_kind: EntrySiteKind = EntrySiteKind.DIRECT_ACQUISITION
    boundary_subject: str = "unknown"
    first_acquisition: bool = True


@dataclass(slots=True)
class EntryRecord:
    entry_id: str
    candidate_id: str
    status: Verdict
    entry_function_id: str
    source_api: str
    channel_kind: str
    attacker_control: str
    provenance_path: list[dict[str, str]]
    consumer_hints: list[str]
    evidence: list[Evidence]
    unknowns: list[str]
    verifier_confidence: float
    entry_line: int | None = None
    rationale: str = ""
    site_kind: EntrySiteKind = EntrySiteKind.DIRECT_ACQUISITION
    boundary_subject: str = "unknown"
    first_acquisition_confirmed: bool = False
    inspected_function_ids: list[str] = field(default_factory=list)
    verification_rounds: int = 0

    def validate(self) -> None:
        if self.status is Verdict.VERIFIED and not self.evidence:
            raise ValueError("VERIFIED entry must contain source or graph evidence")
        if self.status is Verdict.VERIFIED and not self.first_acquisition_confirmed:
            raise ValueError("VERIFIED entry must confirm the first external acquisition site")
        if not 0 <= self.verifier_confidence <= 1:
            raise ValueError("verifier_confidence must be between zero and one")


@dataclass(slots=True)
class SmallFeatureSpec:
    small_feature_id: str
    name: str
    description: str
    root_entries: list[str]
    supporting_entries: list[str]
    harness_anchor: str
    anchor_rationale: str
    boundary_preserved: bool
    preconditions: list[str]
    initialization: list[str]
    required_functions: list[str]
    actions: list[dict[str, Any]]
    input_bindings: list[dict[str, str]]
    cleanup_success: list[str]
    cleanup_failure: list[str]
    stable_post_state: str
    completion_oracle: str
    evidence: list[Evidence]
    unknowns: list[str]
    confidence: float
    channel_kind: str = "unknown"
    build_target: str = "default"
    isolation_mode: str = "in_process_reset"
    input_binding_proven: bool = True
    entry_paths_complete: bool = True
    anchor_action_complete: bool = True
    action_order_complete: bool = True
    function_references_complete: bool = True
    entry_call_order: list[str] = field(default_factory=list)
    entry_order_complete: bool = True
    planning_complete: bool = True
    planning_blockers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LargeFeaturePriority:
    """Security priority of a Large Feature's real input-controlling subject.

    The score is derived by code rather than accepted from the model.  Attacker
    access and credible impact alone determine ranking.  Relative capabilities
    are retained for the explicit discard policy and audit evidence.
    """

    input_subject: str = "unknown"
    subject_capabilities: list[str] = field(default_factory=list)
    comparison_subjects: list[dict[str, Any]] = field(default_factory=list)
    capability_ratio: float | None = None
    capability_scarcity_score: int = 50
    attack_access: AttackAccess = AttackAccess.UNKNOWN
    access_score: int | None = None
    impact_scope: ImpactScope = ImpactScope.UNKNOWN
    impact_score: int | None = None
    base_risk_score: int = 50
    priority_score: int = 50
    attacker_feasibility: AttackerFeasibility = AttackerFeasibility.UNKNOWN
    capability_superset_of_all_others: bool = False
    disposition: HarnessDisposition = HarnessDisposition.KEEP
    rationale: str = "subject comparison was unavailable"
    discard_reason: str = ""
    confidence: float = 0.0


@dataclass(slots=True)
class LargeFeatureSpec:
    large_feature_id: str
    name: str
    description: str
    small_feature_ids: list[str]
    small_feature_names: list[str]
    common_anchor: str
    common_initialization: list[str]
    common_cleanup: list[str]
    common_cleanup_failure: list[str]
    prerequisite_state: list[str]
    fixture_fingerprint: str
    isolation_mode: str
    isolation_rationale: str
    dispatch_strategy: str
    variants: list[dict[str, str]]
    entry_call_graph: dict[str, list[dict[str, Any]]]
    required_functions: list[str]
    evidence: list[Evidence]
    security_priority: LargeFeaturePriority = field(default_factory=LargeFeaturePriority)


def large_feature_schedule_key(
    feature: LargeFeatureSpec,
) -> tuple[bool, int, int, str]:
    """Sort by attacker access tier, then combined access/impact score."""

    priority = feature.security_priority
    access_score = priority.access_score
    return (
        priority.disposition is HarnessDisposition.DISCARD,
        -(access_score if access_score is not None else 0),
        -priority.priority_score,
        feature.large_feature_id,
    )


@dataclass(slots=True)
class HarnessManifest:
    harness_id: str
    large_feature_id: str
    source_file: str
    build_target: str
    engine: str
    sanitizers: list[str]
    execution_model: str
    headers: list[str]
    libraries: list[str]
    min_size: int
    max_size: int
    dispatch_strategy: str
    expected_anchors: list[str]
    expected_consumers: list[str]
    variant_count: int = 1
    variant_targets: list[dict[str, str]] = field(default_factory=list)
    verification_backend: str = "command"
    backend_target: str | None = None
    build_command: list[str] = field(default_factory=list)
    binary: str | None = None


@dataclass(slots=True)
class HarnessDraft:
    manifest: HarnessManifest
    code: str
    self_audit: list[dict[str, str]] = field(default_factory=list)
    generation_blockers: list[str] = field(default_factory=list)
    context_function_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SeedSpec:
    name: str
    data_hex: str
    rationale: str
    check_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class GateCheck:
    check_id: str
    name: str
    status: CheckStatus
    evidence: str
    remediation: str = ""


@dataclass(slots=True)
class GateReport:
    checks: list[GateCheck]

    @property
    def passed(self) -> bool:
        # A harness gate is an acceptance gate, not an advisory report.  In
        # particular, WARN must not silently become PASS: the Quartet-style
        # workflow requires every principle to be affirmatively established
        # before the draft advances to build/runtime verification.
        return bool(self.checks) and all(
            check.status is CheckStatus.PASS for check in self.checks
        )

    @property
    def has_failures(self) -> bool:
        """Whether deterministic evidence establishes a contract violation.

        WARN is intentionally not included.  A lexical/static heuristic may
        be unable to prove an indirect lifecycle path; the independent agent
        review and the real build/reach/runtime gates must adjudicate that
        uncertainty instead of treating it as a known defect.
        """

        return not self.checks or any(
            check.status is CheckStatus.FAIL for check in self.checks
        )


@dataclass(slots=True)
class CommandReport:
    argv: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


@dataclass(slots=True)
class VerificationResult:
    qualified: bool
    build: CommandReport | None
    replays: list[CommandReport]
    fuzz: CommandReport | None
    harness_faults: list[str]
    target_findings: list[str]
    coverage_grew: bool | None
    reason: str
    reachability: list[CommandReport] = field(default_factory=list)
    reachable_seed_count: int = 0
    harness_fault_seeds: list[SeedSpec] = field(default_factory=list)
    target_finding_seeds: list[SeedSpec] = field(default_factory=list)
    build_ok: bool = False
    backend: str = "command"
    coverage_metrics: dict[str, Any] = field(default_factory=dict)
    infrastructure_error: str | None = None


@dataclass(slots=True)
class RunSummary:
    run_id: str
    analysis_functions: int
    analysis_provider: str
    analysis_authoritative: bool
    fuzz_introspector_used: bool
    candidates: int
    verified_entries: int
    unresolved_entries: int
    small_features: int
    harness_ready_small_features: int
    large_features: int
    discarded_large_features: int
    generation_attempts: int
    harnesses_generated: int
    harnesses_static_passed: int
    harnesses_build_passed: int
    harnesses_blocked: int
    harnesses_qualified: int
    status: str
    output_root: str
    initial_unresolved_entries: int = 0
    promoted_entries_during_small_feature: int = 0
    dropped_entries_after_small_feature: int = 0
    verification_infrastructure_failures: int = 0


def evidence_from_dict(raw: dict[str, Any], fallback: FunctionMetadata) -> Evidence:
    return Evidence(
        kind=str(raw.get("kind", "source")),
        function_id=str(raw.get("function_id", fallback.function_id)),
        file=str(raw.get("file", fallback.file)),
        line=int(raw["line"]) if raw.get("line") is not None else fallback.start_line,
        detail=str(raw.get("detail", "model-provided evidence")),
    )


def dump_json(value: object) -> str:
    payload: object
    if dataclasses.is_dataclass(value):
        payload = as_json(value)
    elif isinstance(value, list):
        payload = [as_json(v) if dataclasses.is_dataclass(v) else v for v in value]
    else:
        payload = value
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def unique_strings(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
