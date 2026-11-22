# plan-policy-diff

Diff two versions of a policy pack and say what changed for the humans who
approve plans under it.

Part of the trustworthy-agentic-AI prototype series for project
**BRJP26100123** (Building Trustworthy AI Systems through Explainability and
Human-in-the-Loop Control). Companion repos: `plan-policy-pack` (versioned
policy packs, validation, conformance runner), `plan-policy-check`
(validating a plan against a pack) and `plan-policy-override` (scoped,
expiring exceptions to findings).

## The problem

A policy pack is a living document: the spend limit drops from $5 to $2, a
new rule forbids scraping, a `require_reason` matcher is relaxed. When the
pack changes, two questions matter and neither is answered by a plain JSON
diff:

1. Did the pack get **stricter** or **looser**?
2. Do plans that were already approved under the old pack need to be
   **re-checked**?

`plan-policy-diff` answers both. Every rule change is classified as
**tightening**, **loosening** or **neutral**, and any tightening means
previously approved plans may no longer comply.

## Policy pack format

A pack is JSON, the same shape `plan-policy-pack` validates:

```json
{
  "id": "default",
  "version": "1.2.0",
  "rules": [
    {
      "id": "ORG-01",
      "category": "org",
      "matcher": "max_total_cost",
      "params": {"limit_usd": 5.0},
      "severity": "medium",
      "description": "Total plan cost must stay under the budget."
    }
  ]
}
```

Known matchers: `forbid_action`, `forbid_target`, `require_gate`,
`require_reason`, `require_estimate`, `require_field`, `max_total_cost`.
Categories: `security`, `privacy`, `org`, `ethics`.

## Usage

```bash
python3 policy_diff.py examples/pack-v1.json examples/pack-v2.json
python3 policy_diff.py pack-v1.json pack-v2.json --json
python3 policy_diff.py pack-v1.json pack-v2.json --out diff.md
```

Exit codes:

- `0` — no tightening. Nothing already approved is newly at risk.
- `1` — at least one tightening change. Re-check plans approved under the
  old pack before they run.
- `2` — invalid input (unreadable file, bad JSON, duplicate rule ids,
  unknown matcher, wrong pack shape).

## How a change is classified

| Change | Classification |
| --- | --- |
| Rule added | Tightening (something newly forbidden/required) |
| Rule removed | Loosening (a constraint is gone) |
| `max_total_cost` limit lowered | Tightening |
| `max_total_cost` limit raised | Loosening |
| Severity raised (low → medium → high) | Tightening |
| Severity lowered | Loosening |
| `forbid_*` / `require_*` params changed | Tightening if the new params cover more, loosening if they cover less, neutral if only reworded |
| Description-only change | Neutral |

A rule whose matcher or category changed is treated as the old rule removed
and the new rule added — it is never silently "the same rule".

## Example

`examples/pack-v1.json` → `examples/pack-v2.json`:

- `ORG-01` spend limit drops $5.00 → $2.00 — **tightening**
- `SEC-04` added, forbidding scraping — **tightening**
- `ETH-02` (`require_reason`) removed — **loosening**
- `SEC-01` severity raised medium → high — **tightening**

Verdict: **3 tightening, 1 loosening, 0 neutral — re-check approved plans**
(exit 1). The full report is in `examples/diff.md`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

9 tests, standard library only, no network.
