# -*- coding: utf-8 -*-
"""BLOCKING guard: the live scan and the golden/regen rescore must invoke the
scoring calculators through the SAME shared pipeline — never their own copies.

THE BUG CLASS THIS PREVENTS (2026-06-30 / 2026-07-01)
    `scanner.SecurityScanner.scan` (live) and
    `tooling/regen_outputs_from_cache._rescore` (what the golden regression
    replays) each used to hand-roll the RiskScorer -> RansomwareIndex ->
    FinancialImpactCalculator -> DataBreachIndex -> RemediationSimulator
    sequence. They drifted: the live scanner fed RSI the resolved ZAR revenue
    while the rescore fed it `annual_revenue OR annual_revenue_zar`, and the
    rescore dropped the WAF-status / regulatory / sub-industry / records /
    scan-completeness inputs entirely. That drift is exactly how the RSI-revenue
    size-multiplier bug shipped to production while the golden gate stayed green
    — golden was scoring a DIFFERENT code path than the one that runs live.

    The fix collapsed both onto scoring_pipeline.apply_risk_score /
    apply_insurance_analytics. This guard keeps them collapsed: it fails if
    either `scan` or `_rescore` constructs any scoring calculator directly
    (re-growing a second copy) or stops calling the shared pipeline functions.

Static + deterministic + offline (pure AST), so it runs in the pre-push hook.
Run: py tooling/verify_scoring_pipeline_unified.py   (exit 1 on any violation)
"""
import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(HERE)

# Calculators that must only ever be constructed inside scoring_pipeline (and
# scoring_analytics itself / independent verification harnesses) — NOT inlined
# into the live scan or the rescore.
FORBIDDEN_CONSTRUCTORS = {
    "RiskScorer", "RansomwareIndex", "FinancialImpactCalculator",
    "DataBreachIndex", "RemediationSimulator",
}
# The shared entry points both callers must go through.
REQUIRED_CALLS = {"apply_risk_score", "apply_insurance_analytics"}


def _call_name(node: ast.Call):
    """Return the simple name being called: `Foo()` -> 'Foo',
    `mod.Foo()` -> 'Foo', else None."""
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _find_function(tree: ast.AST, name: str, *, method: bool = False):
    """First FunctionDef named *name* (optionally nested inside any ClassDef)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _audit_callsite(tree: ast.AST, func_name: str, label: str) -> list:
    """Assert *func_name* constructs no forbidden calculator and calls every
    required shared-pipeline entry point. Returns a list of violation strings."""
    violations = []
    fn = _find_function(tree, func_name)
    if fn is None:
        return [f"{label}: function {func_name}() not found — guard may be "
                f"looking at the wrong file or the structure changed."]
    constructed = set()
    called = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            nm = _call_name(n)
            if nm in FORBIDDEN_CONSTRUCTORS:
                constructed.add(nm)
            if nm in REQUIRED_CALLS:
                called.add(nm)
    for nm in sorted(constructed):
        violations.append(
            f"{label}: {func_name}() constructs {nm}(...) directly — route it "
            f"through scoring_pipeline instead (a second copy re-opens the "
            f"live/golden drift).")
    for nm in sorted(REQUIRED_CALLS - called):
        violations.append(
            f"{label}: {func_name}() does not call {nm}(...) — it must invoke "
            f"the shared scoring_pipeline entry points.")
    return violations


def _audit_pipeline_defs(tree: ast.AST, label: str) -> list:
    """scoring_pipeline must define both shared entry points."""
    defined = {n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return [f"{label}: scoring_pipeline is missing {nm}() (the shared entry point)."
            for nm in sorted(REQUIRED_CALLS - defined)]


def _parse(path: str) -> ast.AST:
    with open(path, encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def main() -> None:
    # Optional overrides let the gate be pointed at synthetic copies for its own
    # fails-without/passes-with self-test; default to the real files.
    scanner = pipeline = regen = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--scanner" and i + 1 < len(args):
            scanner = args[i + 1]
        elif a == "--pipeline" and i + 1 < len(args):
            pipeline = args[i + 1]
        elif a == "--regen" and i + 1 < len(args):
            regen = args[i + 1]
    scanner = scanner or os.path.join(SEC, "scanner.py")
    pipeline = pipeline or os.path.join(SEC, "scoring_pipeline.py")
    regen = regen or os.path.join(SEC, "tooling", "regen_outputs_from_cache.py")

    violations = []
    violations += _audit_pipeline_defs(_parse(pipeline), "scoring_pipeline.py")
    violations += _audit_callsite(_parse(scanner), "scan", "scanner.py")
    violations += _audit_callsite(_parse(regen), "_rescore",
                                  "tooling/regen_outputs_from_cache.py")

    if violations:
        print(f"SCORING-PIPELINE UNIFICATION GUARD FAILED ({len(violations)}):")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)
    print("SCORING-PIPELINE UNIFICATION GUARD PASS — scan() and _rescore both "
          "invoke scoring_pipeline.apply_risk_score / apply_insurance_analytics "
          "and neither inlines a calculator (no live/golden drift).")


if __name__ == "__main__":
    main()
