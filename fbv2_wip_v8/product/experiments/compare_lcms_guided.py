"""Bounded, nonblind Little CMS assertion-feedback comparison.

This experiment is deliberately separate from the blind scan and product code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from vulnerabilityanalysis.assertions import instrument_copy


EXPRESSION = "EntryColorSpace != cmsSig1colorData || ((InputFormat >> 3) & 15) == 1"
ASSERTION_ID = "paper-named-color-count"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def audit_saved_corpora(output: Path) -> None:
    """Replay a fixed sample; reach counts describe only sampled saved inputs."""
    path = output / "comparison.json"
    summary = json.loads(path.read_text())
    for trial in summary["trials"]:
        mode, repeat = trial["mode"], trial["repeat"]
        binary = output / mode / "cms_transform_fuzzer"
        corpus = output / mode / f"trial-{repeat}" / "corpus"
        files = [corpus / "initial-seed"] + [p for p in sorted(corpus.iterdir())
                                              if p.is_file() and p.name != "initial-seed"][:8]
        reached = violated = 0
        for saved in files:
            replay = run([str(binary), str(saved), "-runs=1"],
                         env={**os.environ, "VA_ASSERT_TRACE": "1"}, timeout=15)
            reached += "VA_ASSERTION_HIT:" + ASSERTION_ID in replay.stderr
            violated += "VA_ASSERTION_VIOLATION:" + ASSERTION_ID in replay.stderr
        trial["saved_corpus_replay"] = {"sampled": len(files), "reached": reached,
                                         "violated": violated,
                                         "scope": "initial seed plus first eight sorted saved corpus files"}
    path.write_text(json.dumps(summary, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--old-witness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=5)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.target = args.target.resolve()
    args.harness = args.harness.resolve()
    args.seed = args.seed.resolve()
    args.old_witness = args.old_witness.resolve()
    if args.repeats < 2 or not 1 <= args.seconds <= 30:
        raise ValueError("bounded comparison requires 2+ repeats and 1-30 seconds each")
    seed_hash, witness_hash = sha(args.seed), sha(args.old_witness)
    if seed_hash == witness_hash or args.seed.read_bytes() == args.old_witness.read_bytes():
        raise ValueError("known violation witness may not be an initial seed")
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.target / "src/cmsxform.c"
    source_paths = sorted((args.target / "src").glob("*.c"))
    summary: dict = {
        "kind": "NONBLIND_PAPER_INVARIANT_FUZZING_FUNCTIONAL_COMPARISON",
        "target_commit": run(["git", "-C", str(args.target), "rev-parse", "HEAD"]).stdout.strip(),
        "source": str(source), "source_sha256": sha(source),
        "harness": str(args.harness), "harness_sha256": sha(args.harness),
        "initial_seed": str(args.seed), "initial_seed_sha256": seed_hash,
        "initial_seed_bytes": args.seed.stat().st_size,
        "excluded_old_witness_sha256": witness_hash,
        "assertion_id": ASSERTION_ID, "expression": EXPRESSION,
        "source_line": 1170, "repeats": args.repeats, "seconds_per_trial": args.seconds,
        "sanitizer": "address", "optimization": "O0", "distance_feedback": "UNSUPPORTED",
        "trials": [],
    }
    binaries: dict[str, Path] = {}
    for mode in ("normal", "guided"):
        mode_dir = args.output / mode
        mode_dir.mkdir()
        copy = instrument_copy(source, 1170, EXPRESSION, mode_dir / "cmsxform.c",
                               ASSERTION_ID, guided=mode == "guided")
        if mode == "normal":
            # Keep the same assertion, but avoid a HIT log for every libFuzzer
            # execution. Guided instrumentation already gates HIT on this env var.
            code = copy.read_text()
            code = code.replace('fprintf(stderr, "VA_ASSERTION_HIT:%s\\n", ID);',
                                'if (getenv("VA_ASSERT_TRACE")) fprintf(stderr, "VA_ASSERTION_HIT:%s\\n", ID);')
            copy.write_text(code)
        binary = mode_dir / "cms_transform_fuzzer"
        command = ["clang", "-g", "-O0", "-fsanitize=fuzzer,address",
                   "-I" + str(args.target / "include"),
                   "-I" + str(args.target / "src"), str(copy),
                   *[str(p) for p in source_paths if p != source],
                   str(args.harness), "-lm", "-o", str(binary)]
        t0 = time.monotonic()
        built = run(command, timeout=90)
        (mode_dir / "build.log").write_text(built.stdout + built.stderr)
        if built.returncode or not binary.is_file():
            raise RuntimeError(f"{mode} build failed; see {mode_dir / 'build.log'}")
        summary.setdefault("builds", {})[mode] = {
            "command": command, "elapsed_seconds": round(time.monotonic() - t0, 3),
            "binary_sha256": sha(binary), "instrumented_source_sha256": sha(copy),
        }
        binaries[mode] = binary
        probe = run([str(binary), str(args.seed), "-runs=1"],
                    env={**os.environ, "VA_ASSERT_TRACE": "1"}, timeout=15)
        (mode_dir / "initial-probe.log").write_text(probe.stdout + probe.stderr)
        if probe.returncode or "VA_ASSERTION_HIT:" + ASSERTION_ID not in probe.stderr or "VA_ASSERTION_VIOLATION:" in probe.stderr:
            raise RuntimeError(f"{mode} initial seed failed reach/hold probe")
        summary["builds"][mode]["initial_seed_assertion_reached_and_held"] = True
        summary["builds"][mode]["extra_counters_loaded"] = "16 Extra Counters" in probe.stderr
    for repeat in range(args.repeats):
        for mode in ("normal", "guided"):
            trial = args.output / mode / f"trial-{repeat + 1}"
            corpus, artifacts = trial / "corpus", trial / "artifacts"
            corpus.mkdir(parents=True)
            artifacts.mkdir()
            (corpus / "initial-seed").write_bytes(args.seed.read_bytes())
            fixed_seed = 20261010 + repeat
            argv = [str(binaries[mode]), str(corpus), f"-seed={fixed_seed}",
                    f"-max_total_time={args.seconds}", "-print_final_stats=1",
                    f"-artifact_prefix={artifacts}/"]
            t0 = time.monotonic()
            log_path = trial / "fuzzer.log"
            first_artifact_seconds = None
            with log_path.open("w") as log_stream:
                process = subprocess.Popen(argv, stdout=log_stream, stderr=log_stream,
                                           text=True, cwd=trial)
                while process.poll() is None:
                    if first_artifact_seconds is None and any(artifacts.iterdir()):
                        first_artifact_seconds = round(time.monotonic() - t0, 3)
                    time.sleep(0.03)
                    if time.monotonic() - t0 > args.seconds + 15:
                        process.kill()
                        break
                process.wait()
            elapsed = round(time.monotonic() - t0, 3)
            err = log_path.read_text()
            witness_files = sorted(artifacts.iterdir())
            if witness_files and first_artifact_seconds is None:
                first_artifact_seconds = elapsed
            violations = []
            for witness in witness_files:
                replay = run([str(binaries[mode]), str(witness), "-runs=1"], timeout=15)
                (trial / f"replay-{witness.name}.log").write_text(replay.stdout + replay.stderr)
                if "VA_ASSERTION_VIOLATION:" + ASSERTION_ID in replay.stderr:
                    violations.append({"path": str(witness), "sha256": sha(witness),
                                       "bytes": witness.stat().st_size,
                                       "matches_old_witness": sha(witness) == witness_hash})
            corpus_rows = [{"sha256": sha(p), "bytes": p.stat().st_size}
                           for p in sorted(corpus.iterdir()) if p.is_file()]
            counts = re.findall(r"stat::number_of_executed_units:\s*(\d+)", err)
            features = re.findall(r"\bcov:\s*(\d+)\s+ft:\s*(\d+)", err)
            summary["trials"].append({
                "mode": mode, "repeat": repeat + 1, "random_seed": fixed_seed,
                "command": argv, "elapsed_seconds": elapsed,
                "executions": int(counts[-1]) if counts else None,
                "first_assertion_violation_elapsed_upper_bound_seconds": first_artifact_seconds if violations else None,
                "first_assertion_violation_execution_upper_bound": int(counts[-1]) if counts and violations else None,
                "assertion_violation_found": bool(violations), "witnesses": violations,
                "corpus_files": len(corpus_rows), "corpus_sha256": corpus_rows,
                "old_witness_in_final_corpus": any(row["sha256"] == witness_hash for row in corpus_rows),
                "edge_feature_start_end": [features[0], features[-1]] if features else None,
                "extra_counters_loaded": "16 Extra Counters" in err,
                "returncode": process.returncode, "timed_out_externally": elapsed > args.seconds + 15,
                "log": str(trial / "fuzzer.log"),
            })
            (args.output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    # The old witness is a post-campaign functional replay, never a corpus input.
    for mode in ("normal", "guided"):
        replay = run([str(binaries[mode]), str(args.old_witness), "-runs=1"], timeout=15)
        (args.output / mode / "old-witness-post-campaign.log").write_text(replay.stdout + replay.stderr)
        summary.setdefault("old_witness_post_campaign_replay", {})[mode] = {
            "assertion_violation": "VA_ASSERTION_VIOLATION:" + ASSERTION_ID in replay.stderr,
            "exit_code": replay.returncode,
        }
    (args.output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    audit_saved_corpora(args.output)


if __name__ == "__main__":
    main()
