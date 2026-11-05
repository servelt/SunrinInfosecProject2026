from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from ..models import AnalysisBundle, CallEdge, FunctionMetadata, stable_id, unique_strings


SVF_SCHEMA = "harnesscreator.svf.indirect-calls.v2"
SVF_PROVIDER = "SVF-Andersen"
SVF_REQUIRED_COMMIT = "12ad599425dfceaec71803d62c9b31b002052118"
SVF_DOCKER_IMAGE_PREFIX = "harnesscreator-svf"


class SVFError(RuntimeError):
    """Raised when the external SVF analysis cannot produce usable evidence."""


def default_svf_cache_root(source_root: Path) -> Path:
    """Share SVF results across run directories for one source checkout.

    The runner's content digest still includes bitcode bytes, compiled-source
    identities, the locked SVF revision, and the toolchain recipe. A changed
    build therefore gets a different report inside this source-scoped cache.
    """
    source = source_root.expanduser().resolve()
    key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / "harnesscreator-svf-cache" / key


@dataclass(slots=True, frozen=True)
class SVFIndirectEdge:
    caller_symbol: str
    callee_symbol: str
    callsite_id: str = ""


@dataclass(slots=True)
class SVFEvidence:
    source: Path
    edges: list[SVFIndirectEdge]
    compiled_sources: list[str] = field(default_factory=list)
    provider: str = SVF_PROVIDER
    revision: str = ""
    analysis: str = "AndersenWaveDiff_WPA"


@dataclass(slots=True, frozen=True)
class SVFRunResult:
    report: Path
    cache_hit: bool
    revision: str
    bitcode_modules: int
    indirect_edges: int
    duration_seconds: float


@dataclass(slots=True, frozen=True)
class SVFAugmentationResult:
    bundle: AnalysisBundle
    mapped_edges: int
    mapping_failures: tuple[dict[str, Any], ...]


class SVFRunner:
    """Run the unmodified SVF ``wpa`` executable and adapt its DOT output.

    SVF remains an out-of-process AGPL tool.  HarnessCreator does not copy or
    reimplement its pointer analysis: it supplies LLVM bitcode or build-captured
    preprocessed translation units, asks the upstream
    ``wpa -ander -dump-callgraph`` command for its final call graph, and
    converts only red (indirect) DOT edges into a small JSON interchange file.
    The JSON never upgrades a possible target to a proven runtime call.
    """

    def __init__(
        self,
        source_root: Path,
        cache_root: Path,
        research_repos_root: Path,
        *,
        progress: Callable[[str], None] | None = None,
        timeout_seconds: int = 3600,
        dockerfile: Path | None = None,
    ) -> None:
        self.source_root = source_root.resolve()
        self.cache_root = cache_root.resolve()
        self.research_repos_root = research_repos_root.resolve()
        self.progress = progress or (lambda _message: None)
        self.timeout_seconds = timeout_seconds
        self.dockerfile = (
            dockerfile.resolve()
            if dockerfile
            else Path(__file__).resolve().parents[1] / "tools" / "svf.Dockerfile"
        )

    @property
    def svf_root(self) -> Path:
        return self.research_repos_root / "SVF"

    def run(
        self,
        bitcode: Iterable[Path],
        *,
        compiled_sources: Iterable[str] = (),
    ) -> SVFRunResult:
        modules = [path.expanduser().resolve() for path in bitcode]
        if not modules:
            raise SVFError("SVF requires at least one analysis input")
        missing = [path for path in modules if not path.is_file()]
        if missing:
            raise SVFError(f"SVF analysis input does not exist: {missing[0]}")
        unsupported = [
            path for path in modules
            if path.suffix.casefold() not in {".bc", ".i", ".ii"}
        ]
        if unsupported:
            raise SVFError(
                "SVF analysis input must be LLVM bitcode or a captured "
                f"preprocessed translation unit: {unsupported[0]}"
            )
        revision = self._validated_revision()
        source_list = sorted(unique_strings(str(item) for item in compiled_sources))
        recipe_digest = self._recipe_digest()
        digest = self._digest(
            modules, source_list, revision, recipe_digest, self.source_root,
        )
        target = self.cache_root / digest
        report = target / "indirect-calls.json"
        if _valid_svf_report(report, revision):
            evidence = load_svf_evidence(report)
            self.progress(
                f"SVF cache hit: {len(evidence.edges)} indirect target edge(s); {report}"
            )
            return SVFRunResult(
                report=report,
                cache_hit=True,
                revision=revision,
                bitcode_modules=len(modules),
                indirect_edges=len(evidence.edges),
                duration_seconds=0.0,
            )

        self.cache_root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{digest}-", dir=self.cache_root))
        input_dir = staging / "input"
        output_dir = staging / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        copied: list[Path] = []
        for index, module in enumerate(modules):
            destination = input_dir / f"module-{index:05d}{module.suffix.casefold()}"
            shutil.copy2(module, destination)
            copied.append(destination)

        image = self._ensure_image(revision)
        command = [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "-v",
            f"{input_dir}:/input:ro",
            "-v",
            f"{output_dir}:/output",
            "-w",
            "/output",
            image,
            "/opt/harnesscreator/run-svf.sh",
        ]
        started = time.monotonic()
        self.progress(
            f"SVF Andersen analysis started: {len(copied)} analysis unit(s)"
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SVFError(
                f"SVF analysis timed out after {self.timeout_seconds}s"
            ) from exc
        duration = time.monotonic() - started
        (staging / "svf-run.json").write_text(
            json.dumps(
                {
                    "provider": SVF_PROVIDER,
                    "revision": revision,
                    "image": image,
                    "command": command,
                    "returncode": completed.returncode,
                    "duration_seconds": duration,
                    "stdout_tail": completed.stdout[-12000:],
                    "stderr_tail": completed.stderr[-12000:],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if completed.returncode != 0:
            detail = _last_nonempty_line(completed.stderr) or _last_nonempty_line(
                completed.stdout
            )
            raise SVFError(
                f"SVF wpa failed with exit {completed.returncode}"
                + (f": {detail}" if detail else "")
                + f"; artifacts={staging}"
            )
        dot = output_dir / "callgraph_final.dot"
        if not dot.is_file():
            candidates = sorted(output_dir.glob("*callgraph*.dot"))
            if candidates:
                dot = candidates[-1]
        if not dot.is_file():
            raise SVFError(
                f"SVF completed without a final callgraph DOT file; artifacts={staging}"
            )
        edges = parse_svf_callgraph_dot(dot.read_text(encoding="utf-8", errors="replace"))
        payload = {
            "schema": SVF_SCHEMA,
            "provider": SVF_PROVIDER,
            "analysis": "AndersenWaveDiff_WPA",
            "svf_revision": revision,
            "toolchain_recipe": recipe_digest,
            "source_root": str(self.source_root),
            "compiled_sources": source_list,
            "edges": [
                {
                    "caller_symbol": edge.caller_symbol,
                    "callee_symbol": edge.callee_symbol,
                    "callsite_id": edge.callsite_id,
                    "kind": "indirect_possible",
                }
                for edge in edges
            ],
        }
        generated = staging / report.name
        generated.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if target.exists():
            shutil.rmtree(staging)
        else:
            os.replace(staging, target)
        self.progress(
            f"SVF Andersen analysis completed: {len(edges)} indirect target edge(s); {report}"
        )
        return SVFRunResult(
            report=report,
            cache_hit=False,
            revision=revision,
            bitcode_modules=len(modules),
            indirect_edges=len(edges),
            duration_seconds=duration,
        )

    def _validated_revision(self) -> str:
        if not (self.svf_root / ".git").exists():
            raise SVFError(
                f"locked SVF checkout is missing: {self.svf_root}; "
                "clone the repository listed in research-repos/LOCK.json"
            )
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.svf_root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        revision = result.stdout.strip()
        if result.returncode != 0 or not revision:
            raise SVFError(f"cannot read SVF revision from {self.svf_root}")
        if revision != SVF_REQUIRED_COMMIT:
            raise SVFError(
                "SVF checkout revision does not match the locked integration: "
                f"expected {SVF_REQUIRED_COMMIT}, got {revision}"
            )
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=self.svf_root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if dirty.returncode != 0 or dirty.stdout.strip():
            raise SVFError(
                "locked SVF checkout has tracked modifications; restore the exact "
                f"revision before analysis: {self.svf_root}"
            )
        return revision

    def _ensure_image(self, revision: str) -> str:
        docker = shutil.which("docker")
        if not docker:
            raise SVFError("Docker is required to run the locked SVF toolchain")
        if not self.dockerfile.is_file():
            raise SVFError(f"SVF container recipe is missing: {self.dockerfile}")
        recipe = self._recipe_digest()
        image = f"{SVF_DOCKER_IMAGE_PREFIX}:{revision[:12]}-{recipe[:12]}"
        inspect = subprocess.run(
            [docker, "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if inspect.returncode == 0:
            return image
        self.progress(
            f"SVF locked toolchain image build started: {image} (one-time cache)"
        )
        try:
            built = subprocess.run(
                [
                    docker,
                    "build",
                    "--label",
                    f"org.harnesscreator.svf.revision={revision}",
                    "--label",
                    f"org.harnesscreator.svf.recipe={recipe}",
                    "-f",
                    str(self.dockerfile),
                    "-t",
                    image,
                    str(self.svf_root),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SVFError(
                f"SVF toolchain image build timed out after {self.timeout_seconds}s"
            ) from exc
        if built.returncode != 0:
            detail = _last_nonempty_line(built.stderr) or _last_nonempty_line(
                built.stdout
            )
            raise SVFError(
                "SVF toolchain image build failed"
                + (f": {detail}" if detail else "")
            )
        self.progress(f"SVF locked toolchain image build completed: {image}")
        return image

    def _recipe_digest(self) -> str:
        return hashlib.sha256(self.dockerfile.read_bytes()).hexdigest()

    @staticmethod
    def _digest(
        modules: list[Path],
        sources: list[str],
        revision: str,
        recipe_digest: str,
        source_root: Path,
    ) -> str:
        digest = hashlib.sha256()
        digest.update(
            f"{SVF_SCHEMA}\0{revision}\0{recipe_digest}\0".encode()
        )
        # Bitcode captured from a compilation database lives in a fresh
        # temporary directory on each run. Its pathname is not an analysis
        # input. Keep the source root to avoid reusing a report whose source
        # identities belong to another checkout, and hash the module bytes
        # in order so a changed build or compiler invalidates the cache.
        digest.update(str(source_root.resolve()).encode())
        digest.update(b"\0")
        for module in modules:
            digest.update(module.suffix.casefold().encode())
            digest.update(b"\0")
            with module.open("rb") as handle:
                while block := handle.read(1024 * 1024):
                    digest.update(block)
            digest.update(b"\0")
        for source in sources:
            digest.update(source.encode())
            digest.update(b"\0")
        return digest.hexdigest()[:24]


def load_svf_evidence(path: Path) -> SVFEvidence:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise SVFError(f"SVF evidence does not exist: {path}")
    if path.suffix.casefold() == ".dot":
        return SVFEvidence(
            source=path,
            edges=parse_svf_callgraph_dot(
                path.read_text(encoding="utf-8", errors="replace")
            ),
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SVFError(f"invalid SVF evidence JSON {path}: {exc}") from exc
    if payload.get("schema") != SVF_SCHEMA:
        raise SVFError(
            f"SVF evidence must use schema {SVF_SCHEMA}: {path}"
        )
    edges: list[SVFIndirectEdge] = []
    for raw in payload.get("edges", []):
        if not isinstance(raw, dict):
            continue
        if str(raw.get("kind", "indirect_possible")) != "indirect_possible":
            continue
        caller = str(raw.get("caller_symbol", "")).strip()
        callee = str(raw.get("callee_symbol", "")).strip()
        if caller and callee:
            edges.append(
                SVFIndirectEdge(
                    caller_symbol=caller,
                    callee_symbol=callee,
                    callsite_id=str(raw.get("callsite_id", "")),
                )
            )
    return SVFEvidence(
        source=path,
        edges=_deduplicate_svf_edges(edges),
        compiled_sources=[
            str(item) for item in payload.get("compiled_sources", [])
            if isinstance(item, str) and item.strip()
        ],
        provider=str(payload.get("provider") or SVF_PROVIDER),
        revision=str(payload.get("svf_revision") or ""),
        analysis=str(payload.get("analysis") or "AndersenWaveDiff_WPA"),
    )


def parse_svf_callgraph_dot(text: str) -> list[SVFIndirectEdge]:
    """Extract only indirect (red) edges from SVF's official DOT dump."""

    statements = _dot_statements(text)
    node_symbols: dict[str, str] = {}
    for statement in statements:
        if "->" in statement:
            continue
        # The first declaration may share a semicolon-delimited statement
        # with ``digraph ... {``.  Search within the statement instead of
        # requiring the node token at byte zero.
        node_match = re.search(r'(?:^|[\s{])"?(Node[^"\s\[]+)"?\s*\[', statement)
        if not node_match:
            continue
        label = _dot_attribute(statement, "label")
        symbol_match = re.search(r"\\?\{fun:\s*(.*?)(?:\\?\})", label)
        if symbol_match:
            node_symbols[node_match.group(1)] = _unescape_dot(symbol_match.group(1).strip())

    result: list[SVFIndirectEdge] = []
    for statement in statements:
        edge_match = re.search(
            r'(?:^|[\s{])"?(Node[^"\s]+)"?\s*->\s*"?(Node[^"\s\[]+)"?', statement
        )
        if not edge_match:
            continue
        attributes = statement[edge_match.end():]
        if not re.search(r"\bcolor\s*=\s*\"?red\"?", attributes):
            continue
        caller_node, _, source_port = edge_match.group(1).partition(":")
        callee_node = edge_match.group(2).split(":", 1)[0]
        caller = node_symbols.get(caller_node)
        callee = node_symbols.get(callee_node)
        if not caller or not callee:
            continue
        result.append(
            SVFIndirectEdge(
                caller_symbol=caller,
                callee_symbol=callee,
                callsite_id=(
                    _unescape_dot(_dot_attribute(statement, "label"))
                    or source_port
                ),
            )
        )
    return _deduplicate_svf_edges(result)


def augment_analysis_with_svf(
    bundle: AnalysisBundle,
    evidence: SVFEvidence,
    *,
    source_root: Path,
) -> SVFAugmentationResult:
    """Merge SVF possible callees without treating them as proven calls."""

    compiled = _compiled_source_keys(evidence.compiled_sources, source_root)
    reported_pairs = {
        (edge.caller_symbol, edge.callee_symbol) for edge in evidence.edges
    }
    ast_table_sites = 0
    ast_table_sites_without_symbol_edges = 0
    for function in bundle.functions.values():
        if compiled and not _source_matches(function.file, compiled):
            continue
        for site in function.indirect_table_call_sites:
            ast_table_sites += 1
            targets = [bundle.functions.get(str(function_id)) for function_id
                       in site.get("candidate_function_ids", ())]
            if not any(
                (caller_symbol, target_symbol) in reported_pairs
                for caller_symbol in _function_symbols(function)
                for target in targets if target is not None
                for target_symbol in _function_symbols(target)
            ):
                ast_table_sites_without_symbol_edges += 1
    symbol_index: dict[str, list[FunctionMetadata]] = {}
    for function in bundle.functions.values():
        for symbol in _function_symbols(function):
            symbol_index.setdefault(symbol, []).append(function)

    mapping_failures: list[dict[str, Any]] = []
    additions: list[CallEdge] = []
    seen = {
        (edge.caller_id, edge.callee_id, edge.kind, edge.line)
        for edge in bundle.edges
    }
    for item in evidence.edges:
        caller, caller_reason = _resolve_svf_symbol(
            item.caller_symbol, symbol_index, compiled
        )
        callee, callee_reason = _resolve_svf_symbol(
            item.callee_symbol, symbol_index, compiled
        )
        if caller is None or callee is None:
            mapping_failures.append(
                {
                    "caller_symbol": item.caller_symbol,
                    "callee_symbol": item.callee_symbol,
                    "callsite_id": item.callsite_id,
                    "caller_mapping": caller_reason,
                    "callee_mapping": callee_reason,
                }
            )
            continue
        key = (caller.function_id, callee.function_id, "indirect_possible", None)
        if key in seen:
            continue
        seen.add(key)
        additions.append(
            CallEdge(
                edge_id=stable_id(
                    "edge-svf-indirect",
                    caller.function_id,
                    callee.function_id,
                    item.callsite_id,
                ),
                caller_id=caller.function_id,
                callee_id=callee.function_id,
                line=None,
                kind="indirect_possible",
                confidence=0.80,
                providers=[evidence.provider],
            )
        )

    bundle.edges.extend(additions)
    _populate_bundle_adjacency(bundle)
    provider = str(bundle.completeness.get("provider", "unknown"))
    if "svf-andersen" not in provider.casefold():
        provider += "+svf-andersen"
    bundle.completeness.update(
        {
            "provider": provider,
            "svf_used": True,
            "svf_status": "USED",
            "svf_provider": evidence.provider,
            "svf_analysis": evidence.analysis,
            "svf_revision": evidence.revision,
            "svf_report": str(evidence.source),
            "svf_indirect_edges_reported": len(evidence.edges),
            "svf_indirect_edges_mapped": len(additions),
            "svf_mapping_failures": mapping_failures,
            "indirect_callgraph": "partial",
            "clang_ast_indirect_table_sites": ast_table_sites,
            "svf_ast_table_sites_without_matching_symbol_edges": (
                ast_table_sites_without_symbol_edges
            ),
            "svf_semantics": (
                "possible indirect callees only; runtime reachability is required "
                "before selecting a concrete target"
            ),
        }
    )
    return SVFAugmentationResult(
        bundle=bundle,
        mapped_edges=len(additions),
        mapping_failures=tuple(mapping_failures),
    )


def mark_svf_unavailable(bundle: AnalysisBundle, reason: str) -> AnalysisBundle:
    bundle.completeness.update(
        {
            "svf_used": False,
            "svf_status": "UNAVAILABLE",
            "svf_reason": reason,
            "indirect_callgraph": "partial",
        }
    )
    return bundle


def mark_svf_disabled(bundle: AnalysisBundle) -> AnalysisBundle:
    bundle.completeness.update(
        {
            "svf_used": False,
            "svf_status": "DISABLED",
            "svf_reason": "disabled by project configuration",
            "indirect_callgraph": "partial",
        }
    )
    return bundle


def compiled_sources_from_bitcode(bitcode: Iterable[Path]) -> list[str]:
    """Read source identities emitted beside captured SVF analysis inputs."""

    result: list[str] = []
    for module in bitcode:
        candidates = (
            module.with_suffix(module.suffix + ".source"),
            module.with_suffix(".source"),
        )
        for candidate in candidates:
            if not candidate.is_file():
                continue
            result.extend(
                line.strip()
                for line in candidate.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if line.strip()
            )
            break
    return sorted(unique_strings(result))


def prepare_svf_analysis(
    bundle: AnalysisBundle,
    *,
    source_root: Path,
    cache_root: Path,
    research_repos_root: Path | None,
    enabled: bool,
    required: bool,
    evidence_path: Path | None = None,
    bitcode: Iterable[Path] = (),
    compile_database: Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> AnalysisBundle:
    """Apply the locked SVF adapter or record an explicit partial graph.

    This is deliberately a fail-closed orchestration layer.  A points-to edge
    remains ``indirect_possible`` and cannot itself verify an Entry or a
    concrete callback.  When ``required`` is true, missing/unusable evidence
    stops before any LLM work instead of silently reverting to FI's partial
    indirect call graph.
    """

    emit = progress or (lambda _message: None)
    if bundle.completeness.get("svf_status") == "USED":
        return bundle
    if not enabled:
        return mark_svf_disabled(bundle)
    try:
        mode = "explicit-report"
        if evidence_path is not None:
            evidence = load_svf_evidence(evidence_path)
        else:
            modules = [path.expanduser().resolve() for path in bitcode]
            if research_repos_root is None:
                raise SVFError(
                    "the locked SVF checkout root is not configured"
                )
            runner = SVFRunner(
                source_root, cache_root, research_repos_root, progress=emit,
            )
            if modules:
                mode = "configured-bitcode"
                result = runner.run(
                    modules, compiled_sources=compiled_sources_from_bitcode(modules),
                )
            elif compile_database is not None:
                from .bitcode_capture import (
                    BitcodeCaptureError, capture_bitcode_from_compile_database,
                )
                mode = "captured-compilation-database"
                cache_root.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(
                    prefix="svf-bitcode-", dir=cache_root,
                ) as temporary:
                    try:
                        captured = capture_bitcode_from_compile_database(
                            compile_database, source_root, Path(temporary),
                        )
                    except BitcodeCaptureError as exc:
                        raise SVFError(str(exc)) from exc
                    emit(
                        f"SVF captured {len(captured.modules)} target-specific "
                        "LLVM bitcode unit(s) from the compilation database"
                    )
                    result = runner.run(
                        captured.modules,
                        compiled_sources=captured.compiled_sources,
                    )
            else:
                modules = discover_bitcode(source_root)
                mode = "discovered-bitcode"
                if not modules:
                    raise SVFError(
                        "no LLVM bitcode, captured translation unit, or "
                        "compilation database was supplied for indirect-call analysis"
                    )
                result = runner.run(
                    modules, compiled_sources=compiled_sources_from_bitcode(modules),
                )
            evidence = load_svf_evidence(result.report)
        augmentation = augment_analysis_with_svf(
            bundle,
            evidence,
            source_root=source_root,
        )
        augmentation.bundle.completeness["svf_input_mode"] = mode
        emit(
            "SVF indirect-call augmentation completed: "
            f"reported={len(evidence.edges)}, mapped={augmentation.mapped_edges}, "
            f"unmapped={len(augmentation.mapping_failures)}"
        )
        unmatched = augmentation.bundle.completeness.get(
            "svf_ast_table_sites_without_matching_symbol_edges", 0
        )
        if unmatched:
            emit(
                f"WARNING: {unmatched} Clang AST function-table call site(s) "
                "have no matching SVF caller/target symbol edge; keep table "
                "members as source navigation candidates, not a complete call graph"
            )
        return augmentation.bundle
    except SVFError as exc:
        mark_svf_unavailable(bundle, str(exc))
        if required:
            raise
        emit(
            "WARNING: SVF indirect-call analysis unavailable; function-pointer "
            f"paths remain partial: {exc}"
        )
        return bundle


def discover_bitcode(source_root: Path) -> list[Path]:
    ignored = {".git", "runs", "harnesscreator-runs", ".fuzz-introspector"}
    result: list[Path] = []
    for directory, names, filenames in os.walk(
        source_root, topdown=True, followlinks=False
    ):
        names[:] = sorted(
            name for name in names
            if name not in ignored and not name.startswith("runs-")
        )
        for name in filenames:
            path = Path(directory) / name
            if path.suffix.casefold() in {".bc", ".i", ".ii"} and path.is_file():
                result.append(path.resolve())
    return sorted(result)


def _valid_svf_report(path: Path, revision: str) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        payload.get("schema") == SVF_SCHEMA
        and payload.get("svf_revision") == revision
        and isinstance(payload.get("edges"), list)
    )


def _dot_statements(text: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote = False
    escaped = False
    for character in text:
        current.append(character)
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quote = not quote
        elif character == ";" and not quote:
            statements.append("".join(current))
            current = []
    if current:
        statements.append("".join(current))
    return statements


def _dot_attribute(statement: str, name: str) -> str:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*\"((?:\\.|[^\"])*)\"",
        statement,
        re.DOTALL,
    )
    if match:
        return match.group(1)
    bare = re.search(
        rf"\b{re.escape(name)}\s*=\s*([^,\]\s]+)", statement
    )
    return bare.group(1) if bare else ""


def _unescape_dot(value: str) -> str:
    return (
        value.replace(r"\l", " ")
        .replace(r"\n", " ")
        .replace(r"\{", "{")
        .replace(r"\}", "}")
        .replace(r'\"', '"')
        .replace(r"\\", "\\")
        .strip()
    )


def _deduplicate_svf_edges(edges: Iterable[SVFIndirectEdge]) -> list[SVFIndirectEdge]:
    result: dict[tuple[str, str, str], SVFIndirectEdge] = {}
    for edge in edges:
        result[(edge.caller_symbol, edge.callee_symbol, edge.callsite_id)] = edge
    return sorted(
        result.values(),
        key=lambda edge: (edge.caller_symbol, edge.callsite_id, edge.callee_symbol),
    )


def _function_symbols(function: FunctionMetadata) -> set[str]:
    symbols = {function.name, function.qualified_name}
    qualified = function.qualified_name.split("(", 1)[0].strip()
    if qualified:
        symbols.add(qualified)
    return {symbol for symbol in symbols if symbol}


def _resolve_svf_symbol(
    symbol: str,
    index: dict[str, list[FunctionMetadata]],
    compiled_sources: set[str],
) -> tuple[FunctionMetadata | None, str]:
    candidates = list({
        function.function_id: function
        for function in index.get(symbol, [])
    }.values())
    if compiled_sources:
        filtered = [
            function for function in candidates
            if _source_matches(function.file, compiled_sources)
        ]
        if filtered:
            candidates = filtered
        else:
            return None, "no indexed definition belongs to the compiled source set"
    if len(candidates) == 1:
        return candidates[0], "unique symbol/source match"
    if not candidates:
        return None, "symbol is absent from indexed project functions"
    return None, (
        "ambiguous symbol: "
        + ", ".join(
            f"{function.file}:{function.start_line}" for function in candidates[:8]
        )
    )


def _compiled_source_keys(sources: Iterable[str], source_root: Path) -> set[str]:
    result: set[str] = set()
    root = source_root.resolve()
    for value in sources:
        normalized = str(PurePosixPath(str(value).replace("\\", "/")))
        result.add(normalized)
        try:
            result.add(str(Path(value).resolve().relative_to(root)).replace("\\", "/"))
        except (OSError, ValueError):
            pass
    return result


def _source_matches(function_file: str, compiled_sources: set[str]) -> bool:
    normalized = str(PurePosixPath(function_file.replace("\\", "/")))
    return any(
        source == normalized or source.endswith("/" + normalized)
        for source in compiled_sources
    )


def _populate_bundle_adjacency(bundle: AnalysisBundle) -> None:
    callers: dict[str, list[str]] = {identifier: [] for identifier in bundle.functions}
    callees: dict[str, list[str]] = {identifier: [] for identifier in bundle.functions}
    for edge in bundle.edges:
        if edge.caller_id not in callees or edge.callee_id not in callers:
            continue
        callees[edge.caller_id].append(edge.callee_id)
        callers[edge.callee_id].append(edge.caller_id)
    for identifier, function in bundle.functions.items():
        function.callers = sorted(unique_strings(callers[identifier]))
        function.callees = sorted(unique_strings(callees[identifier]))


def _last_nonempty_line(value: str) -> str:
    return next((line.strip() for line in reversed(value.splitlines()) if line.strip()), "")
