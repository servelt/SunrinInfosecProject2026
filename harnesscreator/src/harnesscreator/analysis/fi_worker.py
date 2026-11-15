from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HarnessCreator Fuzz Introspector worker")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-list", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from fuzz_introspector.frontends import frontend_c_cpp  # type: ignore[import-untyped]
    except ImportError as exc:
        raise SystemExit(
            "Fuzz Introspector Python package is unavailable in this interpreter"
        ) from exc

    source_root = args.source_root.resolve()
    raw_files = json.loads(args.source_list.read_text(encoding="utf-8"))
    source_files: list[str] = []
    for raw in raw_files:
        path = Path(str(raw)).resolve()
        try:
            path.relative_to(source_root)
        except ValueError as exc:
            raise SystemExit(f"source path escapes project root: {path}") from exc
        if not path.is_file():
            raise SystemExit(f"source path no longer exists: {path}")
        source_files.append(str(path))

    project = frontend_c_cpp.load_treesitter_trees(source_files)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    project.dump_module_logic(
        str(args.report),
        entry_function="",
        harness_name="harnesscreator",
        harness_source="harnesscreator-module-analysis",
        dump_output=True,
    )
    if not project.all_functions:
        raise SystemExit("Fuzz Introspector extracted zero C/C++ functions")
    print(
        json.dumps(
            {
                "provider": "fuzz-introspector-build-free-c-cpp",
                "source_files": len(source_files),
                "functions": len(project.all_functions),
                "report": str(args.report),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
