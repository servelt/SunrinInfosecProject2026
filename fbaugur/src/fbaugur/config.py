"""Run configuration, stored as RUN/config.json so tool servers see the same values."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

# FuzzingBrain V2 Table 1 assigns roles to three model tiers (T1 reasoning, T2 main,
# T3 utils).  The Code Augur roles follow the tier of the FBv2 role closest to them.
# SP generation is moved from T2 to T3 at the user's request (fast first pass).
ROLE_TIER = {
    "threat_model": 1,        # Code Augur §4.1, global context like FBv2's Direction Generator (T1)
    "direction": 1,           # FBv2 Direction Generator (T1)
    "seed": 2,                # FBv2 Seed Generator (T2)
    "sp_generator": 3,        # FBv2 SP Generator (T2 in FBv2; T3 here)
    "delta_sp_generator": 2,  # FBv2 DeltaSPGenerator (pov_delta.py pins CLAUDE_SONNET_4_5)
    "sp_verifier": 1,         # FBv2 SP Verifier (T1)
    "pov": 2,                 # FBv2 PoC Generator (T2)
    "report": 2,              # FBv2 Report Agent (T2)
    "vuln_validator": 1,      # ours: is the finding a vulnerability (reasoning tier, like the SP Verifier)
    "invariant_recorder": 2,  # Code Augur invariant commit
    "invariant_repair": 2,    # Code Augur REPAIRASSERTION
    "triage": 1,              # Code Augur Violation Triage
    "refine": 1,              # Code Augur REFINEINVARIANT
    "sp_dedup": 3,            # FBv2 core/sp_dedup.py (a small fast model: gpt-4o-mini)
}

# Turn limits.  FBv2 defaults: FullSPGenerator max_iterations=5, SPVerifier 15,
# SeedAgent 20, POV agent max_pov_attempts=20 (40 in the docstring).
DEFAULT_MAX_TURNS = {
    "threat_model": 40, "direction": 40, "seed": 20, "sp_generator": 10, "sp_verifier": 20,
    "delta_sp_generator": 50, "vuln_validator": 25,                       # FBv2 POVDeltaStrategy: max_iterations=50
    "pov": 60, "report": 20, "invariant_recorder": 15, "invariant_repair": 8, "triage": 25, "refine": 12,
}


# Models per tier for each LLM back end.  Claude: Opus / Sonnet / Haiku.  The others are the
# closest counterparts available to this installation: a strong reasoning model, a main coding
# model and a fast model (Codex: models_cache of codex-cli 0.167; Ollama: the cloud models
# HarnessCreator already routes its roles to).
PROVIDERS = ("claude", "codex", "ollama")
# Every Codex request runs with Daybreak (/daybreak) enabled: --ignore-user-config drops the
# user's `daybreak = true`, so it is set here explicitly.
CODEX_DAYBREAK = ["-c", "daybreak=true", "--enable", "cli_daybreak"]
PROVIDER_MODELS = {
    "claude": {"1": "claude-opus-5-5", "2": "claude-sonnet-5-5", "3": "claude-haiku-5-5"},
    "codex": {"1": "gpt-6-sol", "2": "gpt-6-sol", "3": "gpt-6-luna"},
    "ollama": {"1": "glm-5.3:cloud", "2": "kimi-k2.7-code:cloud", "3": "glm-5.3-flash:cloud"},
}


@dataclasses.dataclass
class RunConfig:
    run_dir: str
    hc_run: str
    context_id: str
    deliveries: list[str]
    sanitizer: str = "address+undefined"
    models: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "1": "claude-opus-5-5", "2": "claude-sonnet-5-5", "3": "claude-haiku-5-5"})
    efforts: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "1": "high", "2": "medium", "3": "medium"})
    claude_executable: str = "claude"
    provider: str = "claude"            # claude | codex | ollama
    codex_executable: str = "codex"
    ollama_url: str = "http://localhost:11434"
    python: str = ""
    max_hours: float = 4.0
    fuzz_after_drain_minutes: float = 0.0   # 0 = fuzz until max_hours runs out
    claude_concurrency: int = 5
    sp_generator_agents: int = 3
    verifier_agents: int = 2
    pov_agents: int = 2
    max_turns: dict[str, int] = dataclasses.field(default_factory=lambda: dict(DEFAULT_MAX_TURNS))
    agent_timeout_seconds: float = 1800.0
    pov_min_score: float = 0.5           # FBv2 PipelineConfig.pov_min_score
    max_pov_attempts: int = 20           # FBv2 POVAgent max_pov_attempts
    trace_unlock_after: int = 3          # FBv2: trace_pov after 3 failed attempts
    max_directions: int = 5              # FBv2 §3.4.1
    sp_fuzz_seconds: int = 120
    max_sp_fuzzers: int = 2
    harness_timeout_seconds: int = 10
    reach_probe_seeds: int = 12           # verified normal inputs used to measure assertion reach
    reach_probe_corpus: int = 24          # plus this many fuzzer corpus inputs, spread evenly
    max_repairs: int = 2
    max_refinements: int = 3
    rebuild_min_interval_seconds: float = 120.0
    max_function_analyses: int = 0       # 0 = every function in the pools
    skip_threat_model: bool = False
    diff_path: str = ""                 # delta scan: unified diff to analyse instead of the whole program
    msan: bool = True                   # add a MemorySanitizer fuzzing worker per harness when it builds
    native_extra_cflags: str = ""       # appended to the harness rebuild (e.g. -fcommon for older C)
    daemon_command: str = ""            # the real program, ASan build, started as a server (validation)
    daemon_msan_command: str = ""       # the same with MemorySanitizer, for findings of the MSan worker
    daemon_cwd: str = ""
    daemon_plain_command: str = ""    # the real program WITHOUT sanitizers: what the finding does in a normal build
    plain_replays: int = 200          # requests sent to it, one after another, on new connections
    daemon_port: int = 0                # 0 = the harness's port
    product_version: str = ""           # the tested version, for the advisory's affected versions
    validation_replays: int = 5
    # Scan directories of contexts already analysed in this pipeline run.  A crash that repeats a
    # finding of one of them is a duplicate, not a new finding (one bug, one advisory).
    prior_scans: list[str] = dataclasses.field(default_factory=list)
    # After the deadline: time allowed to confirm and validate crashes the fuzzers recorded while
    # they were being stopped, or that a cancelled lane left half-done.
    final_drain_minutes: float = 10.0

    def model_for(self, role: str) -> tuple[str, str]:
        tier = str(ROLE_TIER[role])
        return self.models[tier], self.efforts[tier]

    def save(self) -> None:
        path = Path(self.run_dir) / "config.json"
        path.write_text(json.dumps(dataclasses.asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, run_dir: Path) -> "RunConfig":
        data: dict[str, Any] = json.loads((Path(run_dir) / "config.json").read_text(encoding="utf-8"))
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})
