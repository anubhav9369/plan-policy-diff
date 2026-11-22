#!/usr/bin/env python3
"""Diff two versions of a policy pack and classify what changed.

A policy pack is JSON: {"id", "version", "rules": [...]} where each rule has
"id", "category", "matcher", "params", "severity" and "description" (the
shape plan-policy-pack validates). This tool answers the two questions a
plain JSON diff cannot:

1. Did the pack get stricter or looser?
2. Do plans approved under the old pack need re-checking?

Every rule change is classified tightening / loosening / neutral. Any
tightening means a previously approved plan may no longer comply.

Usage:
    python3 policy_diff.py pack-v1.json pack-v2.json [--json] [--out FILE]

Exit codes: 0 = no tightening, 1 = at least one tightening change,
2 = invalid input.
"""
import argparse
import json
import sys

KNOWN_MATCHERS = {
    "forbid_action", "forbid_target", "require_gate", "require_reason",
    "require_estimate", "require_field", "max_total_cost",
}
CATEGORIES = {"security", "privacy", "org", "ethics"}
SEVERITIES = {"low": 1, "medium": 2, "high": 3}


class PackError(ValueError):
    """Raised when a pack file is unreadable or fails validation."""


def load_pack(path):
    """Load and validate a policy pack file."""
    try:
        with open(path, encoding="utf-8") as fh:
            pack = json.load(fh)
    except OSError as exc:
        raise PackError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PackError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(pack, dict):
        raise PackError(f"{path}: pack must be a JSON object")
    for field in ("id", "version", "rules"):
        if field not in pack:
            raise PackError(f"{path}: pack is missing {field!r}")
    if not isinstance(pack["rules"], list):
        raise PackError(f"{path}: 'rules' must be a list")
    seen = set()
    for rule in pack["rules"]:
        if not isinstance(rule, dict):
            raise PackError(f"{path}: every rule must be an object")
        for field in ("id", "category", "matcher", "params", "severity"):
            if field not in rule:
                raise PackError(f"{path}: rule {rule.get('id', '?')} is missing {field!r}")
        if rule["id"] in seen:
            raise PackError(f"{path}: duplicate rule id {rule['id']!r}")
        seen.add(rule["id"])
        if rule["category"] not in CATEGORIES:
            raise PackError(f"{path}: rule {rule['id']} has unknown category {rule['category']!r}")
        if rule["matcher"] not in KNOWN_MATCHERS:
            raise PackError(f"{path}: rule {rule['id']} has unknown matcher {rule['matcher']!r}")
        if rule["severity"] not in SEVERITIES:
            raise PackError(f"{path}: rule {rule['id']} has unknown severity {rule['severity']!r}")
        if not isinstance(rule["params"], dict):
            raise PackError(f"{path}: rule {rule['id']} 'params' must be an object")
    return pack


def _params_cover_more(matcher, old, new):
    """True if the new params restrict more than the old ones.

    Only max_total_cost has a numeric direction we can compare; for the
    forbid_/require_ matchers, adding a key or a value is more coverage,
    removing one is less. Anything else is treated as a rewording.
    """
    if matcher == "max_total_cost":
        try:
            return float(new["limit_usd"]) < float(old["limit_usd"])
        except (KeyError, TypeError, ValueError):
            return None
    old_keys, new_keys = set(old), set(new)
    if new_keys > old_keys:
        return True
    if old_keys > new_keys:
        return False
    if any(old[k] != new[k] for k in old_keys & new_keys):
        return None  # same keys, changed values: cannot tell direction
    return None


def classify_change(old, new):
    """Classify one rule that exists in both packs.

    Returns (kind, detail) where kind is 'tightening', 'loosening' or
    'neutral'. A matcher/category change is not a modification at all: the
    caller treats it as a removal plus an addition.
    """
    changes = []
    if old["matcher"] != new["matcher"] or old["category"] != new["category"]:
        return None  # handled as remove + add by diff_packs
    if old["params"] != new["params"]:
        more = _params_cover_more(old["matcher"], old["params"], new["params"])
        if more is True:
            changes.append(("tightening", f"params now cover more: {old['params']} -> {new['params']}"))
        elif more is False:
            changes.append(("loosening", f"params now cover less: {old['params']} -> {new['params']}"))
        else:
            changes.append(("neutral", f"params changed: {old['params']} -> {new['params']}"))
    old_sev, new_sev = SEVERITIES[old["severity"]], SEVERITIES[new["severity"]]
    if new_sev > old_sev:
        changes.append(("tightening", f"severity raised {old['severity']} -> {new['severity']}"))
    elif new_sev < old_sev:
        changes.append(("loosening", f"severity lowered {old['severity']} -> {new['severity']}"))
    if old.get("description") != new.get("description") and not changes:
        changes.append(("neutral", "description reworded"))
    if not changes:
        return ("neutral", "no effective change")
    # One rule can carry several changes; the strictest one wins.
    order = {"tightening": 0, "loosening": 1, "neutral": 2}
    changes.sort(key=lambda c: order[c[0]])
    kind = changes[0][0]
    detail = "; ".join(d for _, d in changes)
    return (kind, detail)


def diff_packs(old_pack, new_pack):
    """Diff two loaded packs. Returns a report dict."""
    old_rules = {r["id"]: r for r in old_pack["rules"]}
    new_rules = {r["id"]: r for r in new_pack["rules"]}
    findings = []

    for rid, rule in old_rules.items():
        if rid not in new_rules:
            findings.append({
                "rule": rid, "kind": "loosening",
                "change": "removed",
                "detail": f"rule {rid} ({rule['matcher']}) removed — a constraint is gone",
            })
    for rid, rule in new_rules.items():
        if rid not in old_rules:
            findings.append({
                "rule": rid, "kind": "tightening",
                "change": "added",
                "detail": f"rule {rid} ({rule['matcher']}) added — something newly forbidden or required",
            })
    for rid in sorted(set(old_rules) & set(new_rules)):
        old, new = old_rules[rid], new_rules[rid]
        if old["matcher"] != new["matcher"] or old["category"] != new["category"]:
            findings.append({
                "rule": rid, "kind": "loosening",
                "change": "removed",
                "detail": f"rule {rid} matcher/category changed ({old['matcher']} -> {new['matcher']}) — old rule removed",
            })
            findings.append({
                "rule": rid, "kind": "tightening",
                "change": "added",
                "detail": f"rule {rid} matcher/category changed ({old['matcher']} -> {new['matcher']}) — new rule added",
            })
            continue
        kind, detail = classify_change(old, new)
        if kind == "neutral" and detail == "no effective change":
            continue
        findings.append({
            "rule": rid, "kind": kind,
            "change": "modified",
            "detail": detail,
        })

    counts = {k: sum(1 for f in findings if f["kind"] == k)
              for k in ("tightening", "loosening", "neutral")}
    verdict = ("re-check approved plans" if counts["tightening"]
               else "no re-check needed")
    return {
        "old_pack": {"id": old_pack["id"], "version": old_pack["version"]},
        "new_pack": {"id": new_pack["id"], "version": new_pack["version"]},
        "counts": counts,
        "verdict": verdict,
        "findings": findings,
    }


def render_markdown(report):
    """Render a diff report as Markdown."""
    lines = [
        "# Policy pack diff",
        "",
        f"Old: {report['old_pack']['id']} v{report['old_pack']['version']}  ",
        f"New: {report['new_pack']['id']} v{report['new_pack']['version']}",
        "",
        f"**Verdict: {report['verdict']}** — "
        f"{report['counts']['tightening']} tightening, "
        f"{report['counts']['loosening']} loosening, "
        f"{report['counts']['neutral']} neutral.",
        "",
    ]
    if not report["findings"]:
        lines.append("No changes.")
        return "\n".join(lines) + "\n"
    lines.append("| Rule | Change | Kind | Detail |")
    lines.append("| --- | --- | --- | --- |")
    for f in report["findings"]:
        lines.append(f"| {f['rule']} | {f['change']} | {f['kind']} | {f['detail']} |")
    lines.append("")
    if report["counts"]["tightening"]:
        lines.append(
            "Plans approved under the old pack may no longer comply. "
            "Re-check them before they run."
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old_pack", help="path to the old policy pack JSON")
    parser.add_argument("new_pack", help="path to the new policy pack JSON")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--out", help="write the Markdown report to FILE")
    args = parser.parse_args(argv)

    try:
        old_pack = load_pack(args.old_pack)
        new_pack = load_pack(args.new_pack)
    except PackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = diff_packs(old_pack, new_pack)
    text = json.dumps(report, indent=2) if args.json else render_markdown(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text if args.json else render_markdown(report))
        print(f"wrote {args.out}")
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    return 1 if report["counts"]["tightening"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
