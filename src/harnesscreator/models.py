from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from .analysis.declarations import SourceDeclaration


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
            result: dict[str, object] = {}
            for f in dataclasses.fields(item):
                raw = getattr(item, f.name)
                if f.metadata.get("json_omit_empty") and raw in {"", None}:
                    continue
                result[f.name] = convert(raw)
            return result
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


class VerificationFailureKind(StringEnum):
    """Deterministic verification phase that prevented qualification.

    These phases mirror the build/run/reachability/coverage boundaries used by
    QuartetFuzz's SystemCheck pipeline.  They are deliberately not free-form
    LLM labels: retry routing must not depend on wording in ``reason``.
    """

    NONE = "NONE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    BUILD = "BUILD"
    HARNESS_FAULT = "HARNESS_FAULT"
    REACHABILITY = "REACHABILITY"
    COVERAGE = "COVERAGE"
    RUNTIME_DISABLED = "RUNTIME_DISABLED"
    DIFFERENTIAL = "DIFFERENTIAL"


class RetryDisposition(StringEnum):
    ACCEPT = "ACCEPT"
    STOP = "STOP"
    REGENERATE_HARNESS = "REGENERATE_HARNESS"
    REFINE_SEEDS = "REFINE_SEEDS"
    REPLAN_FEATURE = "REPLAN_FEATURE"


class AnalysisDisposition(StringEnum):
    """Terminal meaning of an Entry analysis attempt.

    ``Verdict`` deliberately answers only a semantic question: whether a site
    is a verified input Entry, a disproven Entry, or still unresolved.  It must
    not be overloaded with an operational outcome such as an app-server loss
    or an exhausted source walk.  Keeping this separate prevents a transport
    failure from being serialized as evidence that an Entry does not exist.
    """

    COMPLETE = "COMPLETE"
    DEFERRED = "DEFERRED"
    INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"


class ProofStatus(StringEnum):
    """Evidence state of a fact required by a later workflow stage.

    ``POSSIBLE`` is deliberately weaker than proof.  In particular, an
    indirect-call target reported by points-to analysis may create an
    obligation, but it cannot silently satisfy one.
    """

    OPEN = "OPEN"
    POSSIBLE = "POSSIBLE"
    PROVEN_STATIC = "PROVEN_STATIC"
    PROVEN_RUNTIME = "PROVEN_RUNTIME"
    REFUTED = "REFUTED"


class ObligationOwner(StringEnum):
    """The first workflow stage that is responsible for resolving a fact."""

    SMALL_FEATURE = "SMALL_FEATURE"
    LARGE_FEATURE = "LARGE_FEATURE"
    HARNESS_GENERATOR = "HARNESS_GENERATOR"
    BUILD = "BUILD"
    RUNTIME = "RUNTIME"


class ScenarioStatus(StringEnum):
    """Evidence state of an externally executable request scenario.

    A model or a static analysis is never allowed to emit
    ``PROVEN_RUNTIME``.  That value is reserved for the original-program
    executor after every request in the scenario has been observed to
    complete under the configured success oracle.
    """

    CANDIDATE = "CANDIDATE"
    # The protocol response and the Entry-to-handler breakpoint chain were
    # observed in the same isolated run, but no request-level identifier
    # connects them. This must never count as a PROVEN_RUNTIME witness.
    OBSERVED_RUNTIME = "OBSERVED_RUNTIME"
    # A real response was replayed, but no Entry/handler identity was established.
    REPLAYED_RUNTIME = "REPLAYED_RUNTIME"
    PROVEN_RUNTIME = "PROVEN_RUNTIME"
    REJECTED = "REJECTED"
    UNPROVEN = "UNPROVEN"
    INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"


class CrashReproductionStatus(StringEnum):
    ORIGINAL_REPRODUCED = "ORIGINAL_REPRODUCED"
    # One unsuccessful replay cannot establish a harness-owned defect.
    UNCONFIRMED = "UNCONFIRMED"
    HARNESS_ARTIFACT = "HARNESS_ARTIFACT"
    NO_CRASH_TO_REPRODUCE = "NO_CRASH_TO_REPRODUCE"
    INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"


class EntrySiteKind(StringEnum):
    DIRECT_ACQUISITION = "DIRECT_ACQUISITION"
    PROCESS_START = "PROCESS_START"
    EXPORTED_API = "EXPORTED_API"
    EXTERNAL_CALLBACK = "EXTERNAL_CALLBACK"


class ActionActor(StringEnum):
    """Subject that supplies one external action.

    Direction is evidence, not a name-based convenience label.  In
    particular a backend response read by a proxy is not interchangeable with
    a request sent by the configured client-side scenario executor.
    """

    INBOUND_CLIENT = "INBOUND_CLIENT"
    OUTBOUND_PEER = "OUTBOUND_PEER"
    LOCAL_PROCESS_INPUT = "LOCAL_PROCESS_INPUT"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class CrashSignature:
    """Stable crash identity shared by harness and original-program replay."""

    sanitizer_family: str = ""
    bug_class: str = ""
    signal: str = ""
    normalized_frames: list[str] = field(default_factory=list)
    digest: str = ""


@dataclass(slots=True)
class UsageArtifact:
    """Project-supplied example of how external input is constructed/used.

    Usage artifacts are intentionally separate from the product Entry graph:
    tests, clients and protocol examples may teach request layout and ordering
    but must never become product attack-surface Entries.
    """

    path: str
    kind: str
    function_ids: list[str] = field(default_factory=list)
    sha256: str = ""
    rationale: str = ""


@dataclass(slots=True)
class OperationSeed:
    """Static, source-located syntax hint for input-flow inspection.

    A branch does not imply one Action: several branches can implement one
    externally expressible operation, or one branch can contain multiple
    operations. The active semantic workflow does not enumerate these seeds;
    retained legacy records are navigation/audit hints only and cannot
    schedule an Action merely because a branch exists.
    """

    operation_seed_id: str
    dispatcher_function_id: str
    discriminator: str
    line: int
    handler_function_ids: list[str] = field(default_factory=list)
    evidence_kind: str = "switch_case"
    status: ProofStatus = ProofStatus.POSSIBLE
    # Deterministic call-graph path from the verified Entry to this
    # dispatcher.  It is an inspection worklist, not reachability proof.
    entry_path_function_ids: list[str] = field(default_factory=list)
    # Call spellings (or an indirect-expression marker) present in this branch
    # but not uniquely resolved by source syntax.  This distinguishes an
    # intentional default/error branch from a callback branch whose points-to
    # target is still missing.
    unresolved_call_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ProjectSpec:
    source_root: Path
    output_root: Path
    name: str = "project"
    # Action and source-backed state dependencies are the active workflow.
    workflow_mode: str = "action"
    fuzz_introspector: Path | None = None
    require_fuzz_introspector: bool = True
    # Fuzz Introspector's build-free graph cannot reliably resolve function
    # pointers.  The optional locked SVF stage adds possible indirect targets;
    # it never turns those possibilities into runtime proof.
    svf_enabled: bool = True
    require_svf: bool = False
    svf_bitcode: list[Path] = field(default_factory=list)
    svf_callgraph: Path | None = None
    language: str = "c_cpp"
    # Optional compiled executable used only to prioritize byte-identical
    # DWARF source units during Entry discovery. It never filters functions.
    analysis_binary: Path | None = None
    # Optional build-produced compile_commands.json for source AST analysis.
    # It supplies actual include paths and macros, not link or runtime proof.
    analysis_compile_database: Path | None = None
    # ``oss-fuzz`` is the paper-comparable path: generated code replaces a
    # real OSS-Fuzz target and is built/run/covered in that project's image.
    # ``command`` is retained for projects without an OSS-Fuzz integration,
    # but cannot by itself claim QuartetFuzz parity.
    verification_backend: str = "command"
    build_command: list[str] = field(default_factory=list)
    # True only when the CLI selected the bundled native builder. Its main
    # renaming is a build capability, not evidence that a link will succeed.
    native_default_build: bool = False
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
    # Set only after a canonical build is attempted and succeeds against the
    # requested local source. Runtime validation is NOT implied.
    canonical_oss_fuzz_preflight_passed: bool = False
    fuzz_seconds: int = 300
    # Optional, explicitly configured process-level network harness. It is
    # reported separately from in-process libFuzzer qualification.
    network_harness_config: Path | None = None
    # Zero means no arbitrary function-count cutoff. A positive value is an
    # operator-selected work budget, never evidence that context is complete.
    max_context_functions: int = 0
    context_depth: int = 3
    entry_batch_size: int = 32
    # Optional output produced by the unmodified (or export-only patched)
    # research implementations.  HarnessCreator consumes these files through
    # process/data adapters; it does not reimplement their analyses.
    fuzzgen_evidence: list[Path] = field(default_factory=list)
    hopper_constraints: list[Path] = field(default_factory=list)
    winnie_evidence: list[Path] = field(default_factory=list)
    rubick_a2dg: list[Path] = field(default_factory=list)
    rubick_nfa: list[Path] = field(default_factory=list)
    # NetLifter is consumed as an upstream grammar provider.  The workflow
    # accepts the original Popeye BNF output instead of reimplementing its
    # LLVM/Z3 analysis in Python.
    netlifter_bnf: list[Path] = field(default_factory=list)
    research_repos_root: Path | None = None
    # Trusted original-program runner used to prove normal request sequences.
    # This command is supplied by the user/CLI and is always executed without
    # a shell.  Model output can never alter it.
    scenario_command: list[str] = field(default_factory=list)
    # auto detects an individual candidate's transport; it does not
    # constrain global source discovery. disabled is retained for API users.
    scenario_channel: str = "auto"
    scenario_input_env: str = ""
    scenario_host: str = "127.0.0.1"
    scenario_port: int | None = None
    # Pathname AF_UNIX stream endpoint for original-program replay. An
    # isolated path is generated per run when the trusted command contains
    # {scenario_socket_path} and no fixed path was supplied.
    scenario_socket_path: str = ""
    scenario_startup_timeout: float = 10.0
    scenario_step_timeout: float = 2.0
    scenario_response_limit: int = 65_536
    scenario_response_protocol: str = "markers"
    # gdb: temporal breakpoint observations; trace: exact request-correlated
    # JSONL emitted by a cooperatively instrumented original build.
    scenario_attribution: str = "gdb"
    # An explicit requirement fails preflight if the backend cannot perform
    # the comparison. Compatible command/trace runs attempt it automatically
    # before final qualification even when this flag is false.
    require_differential_validation: bool = False
    scenario_environment: dict[str, str] = field(default_factory=dict)
    # Explicit protocol traces, clients, tests, corpora or specifications that
    # may be mined as usage evidence.  Directories are allowed and remain
    # separate from product Entry discovery.
    scenario_evidence_paths: list[Path] = field(default_factory=list)
    # Runtime proof is deliberately fail-closed. The CLI never exposes this
    # switch. The raw-input preflight may disable probes on an isolated copy
    # solely to observe a hypothesis; the returned witness cannot be proven.
    scenario_require_target_reach: bool = True
    # Explicitly opt in to building non-qualified drafts from observed but
    # unattributed original executions. Strict proof remains the default.
    scenario_exploratory_drafts: bool = False
    # Zero means try every materialized raw input. A positive value is an
    # explicit limit on early runtime trials, not an Entry count or proof cap.
    max_exploratory_entries: int = 0
    # Zero accepts source-backed raw inputs of any size. A positive value is
    # an operator-selected execution resource limit, never a format claim.
    max_input_trial_bytes: int = 0
    # Zero: search until the independently reported work-state budget ends.
    max_scenario_steps: int = 0
    max_scenario_candidates: int = 256
    # Zero adds no independent per-Action cutoff. The run-wide candidate
    # work budget still bounds alternate sequences and records exhaustion.
    max_scenario_variants_per_action: int = 0
    max_scenario_search_states: int = 4096
    # Build producer→consumer scenarios with the producer as the mutated step.
    scenario_post_fuzz: bool = False
    # Produce explicitly UNQUALIFIED C drafts for source-proven scenarios when
    # the original executor is unconfigured or cannot yet be replayed.
    scenario_source_drafts: bool = False
    max_source_drafts: int = 32
    # Boundary work budgets limit resource use, never imply path absence.
    boundary_task_seconds: int = 900
    boundary_total_seconds: int = 7200
    # Zero delegates to the indexed-function cycle guard; a positive value is
    # an explicit resource budget, never a claim that source is complete.
    boundary_function_turns: int = 0
    resume_run_id: str = ""
    entry_artifacts_from: Path | None = None

    def normalized(self) -> "ProjectSpec":
        source = self.source_root.expanduser().resolve()
        output = self.output_root.expanduser().resolve()
        if self.workflow_mode not in {"action", "legacy_scenario"}:
            raise ValueError("workflow_mode must be action or legacy_scenario")
        if self.resume_run_id or self.entry_artifacts_from:
            raise ValueError(
                "Action workflow does not support --resume-run-id or "
                "--entry-artifacts-from; use a fresh output run"
            )
        if not source.is_dir():
            raise ValueError(f"source root is not a directory: {source}")
        if (self.analysis_compile_database is not None
            and not self.analysis_compile_database.is_file()):
            raise ValueError(
                "analysis compile database does not exist: "
                f"{self.analysis_compile_database}"
            )
        if output == source:
            raise ValueError("output root must not be the project source root")
        if self.fuzz_seconds < 1:
            raise ValueError("fuzz_seconds must be positive")
        if min(self.boundary_task_seconds, self.boundary_total_seconds) < 1:
            raise ValueError("boundary time budgets must be positive")
        if self.boundary_function_turns < 0:
            raise ValueError("boundary function-turn budget cannot be negative")
        if self.resume_run_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", self.resume_run_id):
            raise ValueError("resume_run_id must be a safe run directory name")
        if self.context_depth < 1 or self.max_context_functions < 0 or self.entry_batch_size < 1:
            raise ValueError("context depth and entry batch size must be positive; function budget cannot be negative")
        if self.scenario_channel not in {"auto", "disabled", "stdin", "tcp", "udp", "unix_stream", "file", "argv", "env"}:
            raise ValueError("scenario_channel must be auto, disabled, stdin, tcp, udp, unix_stream, file, argv, or env")
        # Source-only runs without an executor are valid discovery runs; they
        # cannot manufacture runtime witnesses or QUALIFIED harnesses.
        if self.scenario_channel == "disabled" and self.scenario_command:
            raise ValueError("disabled executor cannot have a scenario command")
        if self.scenario_input_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.scenario_input_env):
            raise ValueError("scenario_input_env must be a valid environment name")
        if any(not token or "\x00" in token for token in self.scenario_command):
            raise ValueError("scenario_command contains an empty or NUL-bearing argument")
        if not self.scenario_host or "\x00" in self.scenario_host:
            raise ValueError("scenario_host must be a non-empty host name or address")
        for name, value in self.scenario_environment.items():
            if not isinstance(name, str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*", name
            ):
                raise ValueError(f"invalid scenario environment name: {name!r}")
            if not isinstance(value, str) or "\x00" in value:
                raise ValueError(f"scenario environment value contains NUL: {name}")
        if self.scenario_channel in {"tcp", "udp"} and not (
            self.scenario_port is not None and 1 <= self.scenario_port <= 65535
        ):
            raise ValueError("tcp/udp scenario execution requires a valid scenario_port")
        if self.scenario_socket_path and (
            not Path(self.scenario_socket_path).is_absolute()
            or "\x00" in self.scenario_socket_path
        ):
            raise ValueError("scenario_socket_path must be an absolute pathname without NUL")
        if (self.scenario_channel == "unix_stream"
            and not self.scenario_socket_path
            and not any("{scenario_socket_path}" in token for token in self.scenario_command)):
            raise ValueError(
                "unix_stream execution requires --scenario-socket-path or "
                "{scenario_socket_path} in --scenario-command"
            )
        if self.scenario_startup_timeout <= 0 or self.scenario_step_timeout <= 0:
            raise ValueError("scenario timeouts must be positive")
        if self.scenario_attribution not in {"gdb", "trace"}:
            raise ValueError("scenario_attribution must be gdb or trace")
        if self.scenario_response_protocol not in {"markers", "memcached_ascii"}:
            raise ValueError("unsupported scenario response protocol")
        if self.scenario_response_protocol == "memcached_ascii" and self.scenario_channel not in {"tcp", "auto"}:
            raise ValueError("memcached_ascii response protocol requires TCP or auto detection")
        if self.scenario_response_limit < 1:
            raise ValueError("scenario_response_limit must be positive")
        if (
            self.max_exploratory_entries < 0
            or self.max_input_trial_bytes < 0
            or self.max_scenario_steps < 0
            or self.max_scenario_candidates < 1
            or self.max_scenario_variants_per_action < 0
            or self.max_scenario_search_states < 1
            or self.max_source_drafts < 0
        ):
            raise ValueError("scenario search bounds must be positive")
        if self.require_differential_validation and (
            self.verification_backend != "command" or self.scenario_attribution != "trace"
        ):
            raise ValueError("differential validation requires command backend and request-correlated trace")
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
        svf_bitcode = [path.expanduser().resolve() for path in self.svf_bitcode]
        missing_bitcode = [path for path in svf_bitcode if not path.is_file()]
        if missing_bitcode:
            raise ValueError(f"svf_bitcode file does not exist: {missing_bitcode[0]}")
        svf_callgraph = (
            self.svf_callgraph.expanduser().resolve()
            if self.svf_callgraph
            else None
        )
        if svf_callgraph is not None and not svf_callgraph.is_file():
            raise ValueError(f"svf_callgraph file does not exist: {svf_callgraph}")
        evidence_paths = {
            "fuzzgen_evidence": [path.expanduser().resolve() for path in self.fuzzgen_evidence],
            "hopper_constraints": [path.expanduser().resolve() for path in self.hopper_constraints],
            "winnie_evidence": [path.expanduser().resolve() for path in self.winnie_evidence],
            "rubick_a2dg": [path.expanduser().resolve() for path in self.rubick_a2dg],
            "rubick_nfa": [path.expanduser().resolve() for path in self.rubick_nfa],
            "netlifter_bnf": [path.expanduser().resolve() for path in self.netlifter_bnf],
        }
        for option, paths in evidence_paths.items():
            missing = [path for path in paths if not path.is_file()]
            if missing:
                raise ValueError(f"{option} file does not exist: {missing[0]}")
        research_repos_root = (
            self.research_repos_root.expanduser().resolve()
            if self.research_repos_root
            else None
        )
        if research_repos_root is not None and not research_repos_root.is_dir():
            raise ValueError(
                f"research_repos_root is not a directory: {research_repos_root}"
            )
        network_harness_config = (
            self.network_harness_config.expanduser().resolve()
            if self.network_harness_config else None
        )
        if network_harness_config is not None and not network_harness_config.is_file():
            raise ValueError(
                f"network_harness_config file does not exist: {network_harness_config}"
            )
        scenario_evidence_paths = [
            path.expanduser().resolve() for path in self.scenario_evidence_paths
        ]
        entry_artifacts_from = (
            self.entry_artifacts_from.expanduser().resolve()
            if self.entry_artifacts_from else None
        )
        if entry_artifacts_from is not None and not entry_artifacts_from.is_dir():
            raise ValueError(f"Entry artifact run does not exist: {entry_artifacts_from}")
        if entry_artifacts_from is not None and self.resume_run_id:
            raise ValueError("entry_artifacts_from and resume_run_id are mutually exclusive")
        missing_scenario_evidence = [
            path for path in scenario_evidence_paths if not path.exists()
        ]
        if missing_scenario_evidence:
            raise ValueError(
                "scenario_evidence_path does not exist: "
                f"{missing_scenario_evidence[0]}"
            )
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
            svf_bitcode=svf_bitcode,
            svf_callgraph=svf_callgraph,
            fuzzgen_evidence=evidence_paths["fuzzgen_evidence"],
            hopper_constraints=evidence_paths["hopper_constraints"],
            winnie_evidence=evidence_paths["winnie_evidence"],
            rubick_a2dg=evidence_paths["rubick_a2dg"],
            rubick_nfa=evidence_paths["rubick_nfa"],
            netlifter_bnf=evidence_paths["netlifter_bnf"],
            research_repos_root=research_repos_root,
            network_harness_config=network_harness_config,
            scenario_evidence_paths=scenario_evidence_paths,
            entry_artifacts_from=entry_artifacts_from,
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
    # Compiler-resolved external calls, including macro expansion sites where
    # the API spelling is absent from the function's original source text.
    # Dicts keep persisted analysis JSON backward compatible.
    external_call_sites: list[dict[str, Any]] = field(default_factory=list)
    # Compiler-resolved calls to project functions and the declaration IDs of
    # their direct arguments. A matching spelling alone is not value flow.
    direct_call_sites: list[dict[str, Any]] = field(default_factory=list)
    # Clang-resolved control guards and nested direct calls. These are
    # navigation evidence only; they do not establish request feasibility.
    guarded_call_sites: list[dict[str, Any]] = field(default_factory=list)
    # File-scope declarations directly referenced by this function, with
    # source locations confirmed by a parsed Clang AST.  These are source
    # context for indirect dispatch, not executable call edges.
    referenced_global_declarations: list[dict[str, Any]] = field(default_factory=list)
    # Source-located indirect calls through a referenced file-scope array.
    # Initializer members are possible targets for navigation, never calls.
    indirect_table_call_sites: list[dict[str, Any]] = field(default_factory=list)
    # Expanded, source-located object macros used by this parsed function.
    # A textual #define elsewhere is never enough to populate this field.
    referenced_macro_definitions: list[dict[str, Any]] = field(default_factory=list)
    # Clang declaration identities for function parameters. These permit
    # source-navigation through a consumer's own guards without matching a
    # shadowed local by spelling. They do not prove interprocedural flow.
    ast_parameter_declarations: list[dict[str, str]] = field(default_factory=list)
    parameter_output_positions: list[int] = field(default_factory=list)
    # Compiler-reported external linkage identity. Empty when unavailable;
    # matches across translation units are navigation, never proof of linking.
    linkage_symbol: str = ""
    linkage_type: str = ""
    linkage_external: bool = False

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
    declarations: list[SourceDeclaration] = field(default_factory=list)

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
    # A source-linked next function is retained when an explicit work budget
    # stops the verifier. It is not a negative Entry verdict.
    pending_function_ids: list[str] = field(default_factory=list)
    # ``status=UNRESOLVED`` is a semantic result.  This field says whether the
    # remaining uncertainty is a normal evidence gap or an interrupted agent
    # session, and is intentionally preserved into the next analysis run.
    analysis_disposition: AnalysisDisposition = AnalysisDisposition.COMPLETE
    analysis_blocker: str = ""

    def validate(self) -> None:
        if self.status is Verdict.VERIFIED and not self.evidence:
            raise ValueError("VERIFIED entry must contain source or graph evidence")
        if self.status is Verdict.VERIFIED and not self.first_acquisition_confirmed:
            raise ValueError("VERIFIED entry must confirm the first external acquisition site")
        if not 0 <= self.verifier_confidence <= 1:
            raise ValueError("verifier_confidence must be between zero and one")


@dataclass(slots=True)
class InputFieldConstraint:
    """One source-proven field in an externally supplied request.

    ``binding`` names a value that must remain equal across requests (for
    example a key or object identifier).  The deterministic sequence planner
    uses byte offsets only; it never asks an LLM to rewrite a request.
    """

    name: str
    offset: int
    width: int
    encoding: str = "bytes"
    binding: str = ""
    relation: str = "opaque"
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ResponseBindingExtractor:
    """A source-proven fixed slice exported by one action response.

    Dynamic response values are deliberately restricted to fixed-width byte
    slices.  Variable-length extraction needs an independently proven framing
    and length-rewrite contract and therefore remains an obligation instead of
    being guessed by the harness generator.
    """

    binding: str
    offset: int
    width: int
    encoding: str = "bytes"
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class RequestBindingUse:
    """Patch a runtime-produced binding into a later request template."""

    binding: str
    offset: int
    width: int
    producer_step_index: int
    encoding: str = "bytes"


@dataclass(slots=True)
class ActionExample:
    data_hex: str
    bindings: dict[str, str] = field(default_factory=dict)
    rationale: str = ""
    origin: str = "model_candidate"
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ExternalActionSchema:
    """A statically reconstructed external action at a verified Entry.

    This is a protocol/action schema, not a feature grouping.  A dispatcher
    can yield many actions and an action can later participate in many
    scenarios.  For a branchless action, ``dispatcher_function_id`` stores
    the evidenced handler as an internal path anchor; it does not assert that
    a dispatcher exists. ``discriminator`` is empty when no selection value
    is evidenced.
    """

    action_id: str
    entry_id: str
    name: str
    description: str
    dispatcher_function_id: str
    handler_function_id: str
    discriminator: str
    channel_kind: str
    fields: list[InputFieldConstraint]
    examples: list[ActionExample]
    success_markers_hex: list[str]
    failure_markers_hex: list[str]
    evidence: list[Evidence]
    inspected_function_ids: list[str]
    operation_seed_ids: list[str] = field(default_factory=list)
    status: ProofStatus = ProofStatus.POSSIBLE
    unknowns: list[str] = field(default_factory=list)
    confidence: float = 0.0
    source_api: str = ""
    success_evidence: list[Evidence] = field(default_factory=list)
    failure_evidence: list[Evidence] = field(default_factory=list)
    response_bindings: list[ResponseBindingExtractor] = field(default_factory=list)
    actor: ActionActor = ActionActor.UNKNOWN
    direction: str = "unknown"
    entry_function_id: str = ""
    # Copied deterministically from the verified Entry and OperationSeed.
    # Runtime proof uses these exact acquisition/dispatch lines rather than
    # treating a function-entry breakpoint as proof that the site executed.
    entry_probe_evidence: list[Evidence] = field(default_factory=list)
    dispatch_probe_evidence: list[Evidence] = field(default_factory=list)
    # A source-located, line-framed server message expected before the first
    # client write on a new stream connection. This is an execution hypothesis
    # until independently observed in the original program.
    connection_prelude_marker_hex: str = ""


@dataclass(slots=True)
class StateRequirement:
    """A state predicate consumed or produced by one external action."""

    resource: str
    binding: str = ""
    predicate: str = "exists"
    evidence: list[Evidence] = field(default_factory=list)
    status: ProofStatus = ProofStatus.POSSIBLE
    # Initial state tied to an action binding is unusable unless the concrete
    # value is known. ``None`` means unknown; an empty string is a proven
    # zero-length value.
    binding_value_hex: str | None = None
    # Scope prevents the planner from unifying a global resource with a
    # session- or connection-owned resource of the same name.
    scope: str = "global"
    owner_binding: str = ""


@dataclass(slots=True)
class ActionStateContract:
    action_id: str
    consumes: list[StateRequirement]
    produces: list[StateRequirement]
    invalidates: list[StateRequirement]
    success_condition: str
    evidence: list[Evidence]
    inspected_function_ids: list[str]
    status: ProofStatus = ProofStatus.POSSIBLE
    unknowns: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ActionOrderingConstraint:
    """An upstream-tool ordering fact mapped to concrete external actions.

    Only exact and unique function mappings are admitted. ``REQUIRED`` means
    the predecessor must already have executed; ``FORBIDDEN`` means that
    predecessor must not have executed before the successor.
    """

    constraint_id: str
    predecessor_action_id: str
    successor_action_id: str
    strength: str
    provider: str
    rationale: str


@dataclass(slots=True)
class StateDependencyGraph:
    contracts: list[ActionStateContract]
    initial_resources: list[StateRequirement]
    open_obligations: list[str]
    evidence_providers: list[str] = field(default_factory=list)
    ordering_constraints: list[ActionOrderingConstraint] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioStep:
    index: int
    action_id: str
    entry_id: str
    request_hex: str
    bindings: dict[str, str]
    expected_success_markers_hex: list[str]
    # ``request_template_hex`` is the pre-substitution request.  It equals
    # request_hex for ordinary steps.  Runtime verification replaces the
    # listed uses with values extracted from earlier responses and records the
    # resulting concrete bytes in request_hex.
    request_template_hex: str = ""
    request_binding_uses: list[RequestBindingUse] = field(default_factory=list)
    response_binding_extractors: list[ResponseBindingExtractor] = field(default_factory=list)
    connection_prelude_marker_hex: str = ""


@dataclass(slots=True)
class ScenarioCandidate:
    scenario_id: str
    target_action_id: str
    steps: list[ScenarioStep]
    required_entries: list[str]
    satisfied_resources: list[str]
    planning_evidence: list[str]
    status: ScenarioStatus = ScenarioStatus.CANDIDATE
    blocker: str = ""
    # -1 means the final request is fuzzed (legacy behavior).
    fuzz_step_index: int = -1


@dataclass(slots=True)
class RuntimeStepObservation:
    index: int
    action_id: str
    request_hex: str
    response_hex: str
    success: bool
    detail: str
    duration_seconds: float
    # The local transport accepted the complete request write. This is not
    # evidence that the peer read, parsed, or accepted those bytes.
    request_write_completed: bool = False
    # Keep the protocol oracle separate from the final step verdict.  A
    # server may emit the expected bytes even when the request reached a
    # different handler; ``success`` is therefore the conjunction of the
    # response/binding checks and the ordered Entry -> handler observation.
    response_success: bool = False
    extracted_bindings: dict[str, str] = field(default_factory=dict)
    target_function_id: str = ""
    target_reached: bool = False
    # Diagnostic observation only. An ordered breakpoint chain is not
    # necessarily caused by this particular request in a concurrent daemon.
    target_observed: bool = False
    target_probe: str = ""
    entry_function_id: str = ""
    entry_reached: bool = False
    probe_trace: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ObservedActionBinding:
    """One request bound to the exact product action observed at runtime."""

    step_index: int
    action_id: str
    entry_id: str
    actor: ActionActor
    direction: str
    channel: str
    request_hex: str
    entry_function_id: str
    entry_reached: bool
    target_function_id: str
    target_reached: bool
    response_success: bool
    state_observation: str
    probe: str
    probe_trace: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScenarioWitness:
    witness_id: str
    scenario_id: str
    target_action_id: str
    steps: list[ScenarioStep]
    observations: list[RuntimeStepObservation]
    command: list[str]
    channel: str
    process_returncode: int | None
    status: ScenarioStatus
    rationale: str
    original_program_crashed: bool = False
    sanitizer_output: str = ""
    action_bindings: list[ObservedActionBinding] = field(default_factory=list)
    target_trace: list[str] = field(default_factory=list)
    crash_signature: CrashSignature | None = None
    fuzz_step_index: int = -1
    # Measured launch-to-TCP-connect time for this original-program trial.
    # It is one observation, not a safe startup delay for future runs.
    tcp_connect_after_launch_seconds: float | None = None
    connection_prelude_hex: str = ""


@dataclass(slots=True)
class HarnessPlan:
    """One runtime witness transformed into one fuzz-harness contract."""

    plan_id: str
    witness_id: str
    scenario_id: str
    target_action_id: str
    setup_steps: list[ScenarioStep]
    fuzz_step: ScenarioStep
    required_function_ids: list[str]
    entry_function_ids: list[str]
    input_mapping: str
    reset_strategy: str
    build_target: str
    min_size: int
    max_size: int
    setup_entry_function_ids: list[str] = field(default_factory=list)
    fuzz_entry_function_id: str = ""
    # After-fuzz steps can observe state modifications caused by the fuzz input.
    post_steps: list[ScenarioStep] = field(default_factory=list)
    post_entry_function_ids: list[str] = field(default_factory=list)
    fuzz_step_index: int = -1
    boundary_contract: dict[str, object] = field(default_factory=dict)
    request_rules: list[dict[str, object]] = field(default_factory=list)
    # Source files reached by selected Entry/handler. A build-system link
    # closure must cover them; filenames are evidence, never compile commands.
    required_source_files: list[str] = field(default_factory=list)


@dataclass(slots=True)
class OriginalCrashReplay:
    replay_id: str
    harness_id: str
    seed: SeedSpec
    lifted_steps: list[ScenarioStep]
    status: CrashReproductionStatus
    observation: ScenarioWitness | None
    rationale: str
    expected_signature: CrashSignature | None = None
    observed_signature: CrashSignature | None = None
    signature_matched: bool = False
    # A matching original-process crash is an observation. This stronger
    # flag means the fuzzed bytes were also acquired at the intended Entry
    # under a request-correlated original trace. Neither flag alone proves
    # exploitability or that a crash is a security vulnerability.
    input_attributed: bool = False


@dataclass(slots=True)
class ScenarioRunSummary:
    run_id: str
    analysis_functions: int
    analysis_provider: str
    analysis_authoritative: bool
    fuzz_introspector_used: bool
    svf_status: str
    svf_used: bool
    svf_indirect_edges_reported: int
    svf_indirect_edges_mapped: int
    svf_indirect_edges_unmapped: int
    candidates: int
    verified_entries: int
    unresolved_entries: int
    action_schemas: int
    state_contracts: int
    scenario_candidates: int
    scenario_witnesses: int
    unproven_scenarios: int
    harness_plans: int
    generation_attempts: int
    harnesses_generated: int
    harnesses_static_passed: int
    harnesses_build_passed: int
    harnesses_blocked: int
    harnesses_qualified: int
    original_crashes_reproduced: int
    harness_artifacts: int
    status: str
    output_root: str
    agent_infrastructure_failures: int = 0
    verification_infrastructure_failures: int = 0
    harnesses_static_deferred: int = 0
    operation_inventory_obligations: int = 0
    state_dependency_obligations: int = 0
    unproven_target_actions: int = 0
    scenario_planning_obligations: int = 0
    in_scope_unresolved_entries: int = 0
    scenario_skipped_entries: int = 0
    exploratory_scenarios: int = 0
    observed_scenarios: int = 0
    harnesses_backend_qualified: int = 0
    exploratory_builds: int = 0
    entry_generator_uninspected_functions: int = 0
    input_surface_cases: int = 0
    input_surface_runtime_trials: int = 0
    input_surface_obligations: int = 0
    behavior_candidates: int = 0
    execution_contracts: int = 0
    boundary_trials: int = 0
    network_harness_status: str = "NOT_CONFIGURED"
    network_harness_seed_count: int = 0
    # Draft source written during the early Entry walk is retained even when
    # no later scenario obtains a qualified runtime witness. It is separate
    # from harnesses_generated, which counts ordinary generation output.
    early_harness_drafts: int = 0
    transport_compatible_scenarios: int = 0


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
    # Action whose execution establishes the feature's completion oracle.
    # List order cannot distinguish the semantic operation from a trailing
    # response-release or cleanup action.
    completion_action_id: str = ""
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
    # A Small Feature owns semantic operation order, while ``actions`` owns the
    # executable calls.  Keeping the evidence-backed relation explicitly makes
    # state prerequisites such as SET-before-GET distinguishable from process
    # initialization and prevents the Harness Generator from guessing either.
    dependencies: list["FeatureDependency"] = field(default_factory=list)
    # Semantic discovery and executable-harness planning are intentionally
    # separate.  A real operation remains available to Large Feature planning
    # even when its input delivery, build target, or completion proof still
    # needs to be resolved by P2/harness generation.
    semantic_complete: bool = True
    semantic_blockers: list[str] = field(default_factory=list)
    proof_obligations: list["ProofObligation"] = field(default_factory=list)
    operation_seed_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FeatureDependency:
    dependency_id: str
    provider: str
    relation: str
    strength: str
    producer_action_id: str
    consumer_action_id: str
    condition: str
    source: str = ""
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class ProofObligation:
    """A durable, auditable missing fact instead of an early-drop reason."""

    obligation_id: str
    owner: ObligationOwner
    kind: str
    description: str
    required_for: str
    status: ProofStatus = ProofStatus.OPEN
    source_feature_ids: list[str] = field(default_factory=list)
    producer_id: str = ""
    consumer_id: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    attempts: int = 0


@dataclass(slots=True)
class LargeFeatureDependency:
    """A producer/consumer relation that crosses Small Feature boundaries."""

    dependency_id: str
    producer_small_feature_id: str
    consumer_small_feature_id: str
    relation: str
    condition: str
    status: ProofStatus = ProofStatus.OPEN
    evidence: list[Evidence] = field(default_factory=list)


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
    # Cross-operation state (for example SET before a GET-hit variant) belongs
    # to the Large Feature contract, not to per-Entry discovery.
    dependencies: list[LargeFeatureDependency] = field(default_factory=list)
    proof_obligations: list[ProofObligation] = field(default_factory=list)
    protocol_ready: bool = False


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
    variant_targets: list[dict[str, Any]] = field(default_factory=list)
    verification_backend: str = "command"
    backend_target: str | None = None
    build_command: list[str] = field(default_factory=list)
    binary: str | None = None
    scenario_id: str = ""
    # Read compatibility for pre-scenario artifacts.  The active workflow
    # never populates or serializes this field.
    large_feature_id: str = field(default="", metadata={"json_omit_empty": True})


@dataclass(slots=True)
class HarnessDraft:
    manifest: HarnessManifest
    code: str
    self_audit: list[dict[str, str]] = field(default_factory=list)
    generation_blockers: list[str] = field(default_factory=list)
    context_function_ids: list[str] = field(default_factory=list)
    # Source-validated protocol metadata retained for verifier diagnostics.
    operation_protocols: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class SeedSpec:
    name: str
    data_hex: str
    rationale: str
    check_ids: list[str] = field(default_factory=list)
    crash_signature: CrashSignature | None = None


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
        # A WARN never becomes a static PASS. The scenario orchestrator has
        # one explicit, separately counted route for HC08/HC10 uncertainty:
        # independent review followed by built-harness differential evidence.
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
    failure: "VerificationFailure | None" = None

    def __post_init__(self) -> None:
        # Every verifier path, including direct unit/custom-backend use, gets a
        # typed outcome.  This avoids silently falling back to matching mutable
        # English error text in the orchestrator.
        if self.failure is None:
            self.failure = _classify_verification_failure(self)


@dataclass(slots=True)
class VerificationFailure:
    kind: VerificationFailureKind
    phase: str
    disposition: RetryDisposition
    signature: str
    evidence: list[str] = field(default_factory=list)


def _classify_verification_failure(
    result: VerificationResult,
) -> VerificationFailure:
    """Map verifier facts to a stable repair boundary.

    QuartetFuzz separates building, adversarial execution, target reachability,
    and coverage collection.  HarnessCreator uses the same observable phase
    boundaries here.  The human-readable ``reason`` remains diagnostic text;
    it is not the value that controls the retry loop.
    """

    evidence = unique_strings([
        *result.harness_faults,
        *([result.infrastructure_error] if result.infrastructure_error else []),
    ])
    reason = result.reason.strip()

    if result.qualified:
        kind = VerificationFailureKind.NONE
        phase = "qualified"
        disposition = RetryDisposition.ACCEPT
    elif result.infrastructure_error:
        kind = VerificationFailureKind.INFRASTRUCTURE
        phase = _verification_phase_from_reason(reason, default="infrastructure")
        disposition = RetryDisposition.STOP
    elif (
        "runtime qualification was disabled" in reason.casefold()
        or "dynamic verification was not run" in reason.casefold()
    ):
        kind = VerificationFailureKind.RUNTIME_DISABLED
        phase = "runtime"
        disposition = RetryDisposition.STOP
    elif reason.casefold().startswith("differential validation"):
        kind = VerificationFailureKind.DIFFERENTIAL
        phase = "differential"
        disposition = RetryDisposition.STOP
    elif result.build is None:
        kind = VerificationFailureKind.INFRASTRUCTURE
        phase = "build"
        disposition = RetryDisposition.STOP
    elif (
        result.build.timed_out
        or result.build.returncode not in {0, None}
        or not result.build_ok
    ):
        kind = VerificationFailureKind.BUILD
        phase = "build"
        disposition = RetryDisposition.REGENERATE_HARNESS
        build_detail = (result.build.stderr or result.build.stdout).strip()
        if build_detail:
            evidence = unique_strings([*evidence, build_detail[-4000:]])
    elif "reachability" in reason.casefold():
        kind = VerificationFailureKind.REACHABILITY
        phase = "reachability"
        # One bounded seed-refinement pass is performed by the orchestrator.
        # Persisting the initial disposition makes that action auditable; a
        # second miss is promoted to REPLAN_FEATURE by the orchestrator.
        disposition = RetryDisposition.REFINE_SEEDS
    elif "coverage" in reason.casefold():
        kind = VerificationFailureKind.COVERAGE
        phase = "coverage"
        # Missing fresh coverage is a harness/corpus observation. It does not
        # establish that the recovered program feature is wrong.
        disposition = RetryDisposition.STOP
    elif result.harness_faults or result.harness_fault_seeds:
        kind = VerificationFailureKind.HARNESS_FAULT
        phase = _verification_phase_from_reason(reason, default="runtime")
        disposition = RetryDisposition.REGENERATE_HARNESS
    elif result.coverage_grew is False:
        kind = VerificationFailureKind.COVERAGE
        phase = "coverage"
        disposition = RetryDisposition.STOP
    else:
        # A built harness that failed an unclassified runtime condition is not
        # safe to regenerate eight times blindly.  Treat it as a harness-local
        # failure once; the orchestrator's repeated-signature guard then stops.
        kind = VerificationFailureKind.HARNESS_FAULT
        phase = _verification_phase_from_reason(reason, default="runtime")
        disposition = RetryDisposition.REGENERATE_HARNESS

    signature_material = "\n".join([
        str(kind),
        phase,
        reason,
        *evidence,
    ])
    # Addresses, attempt directories, and timing counters vary between equal
    # failures.  Removing them makes no-progress detection stable without
    # discarding compiler/function diagnostics that identify the actual cause.
    signature_material = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", signature_material)
    signature_material = re.sub(r"attempt-\d+", "attempt-N", signature_material)
    signature_material = re.sub(r"\b\d+(?:\.\d+)?s\b", "TIME", signature_material)
    signature = stable_id("verification-failure", signature_material)
    return VerificationFailure(
        kind=kind,
        phase=phase,
        disposition=disposition,
        signature=signature,
        evidence=evidence,
    )


def _verification_phase_from_reason(reason: str, *, default: str) -> str:
    folded = reason.casefold()
    for phase in ("build", "replay", "reachability", "fuzz", "coverage", "attribution"):
        if phase in folded:
            return phase
    return default


@dataclass(slots=True)
class RunSummary:
    run_id: str
    analysis_functions: int
    analysis_provider: str
    analysis_authoritative: bool
    fuzz_introspector_used: bool
    svf_status: str
    svf_used: bool
    svf_indirect_edges_reported: int
    svf_indirect_edges_mapped: int
    svf_indirect_edges_unmapped: int
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
    deferred_entries_after_small_feature: int = 0
    verification_infrastructure_failures: int = 0
    agent_infrastructure_failures: int = 0
    large_feature_eligible_small_features: int = 0
    open_proof_obligations: int = 0
    operation_seeds: int = 0
    unresolved_operation_seeds: int = 0


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
