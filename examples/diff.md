# Policy pack diff

Old: default v1.1.0  
New: default v1.2.0

**Verdict: re-check approved plans** — 3 tightening, 1 loosening, 0 neutral.

| Rule | Change | Kind | Detail |
| --- | --- | --- | --- |
| ETH-02 | removed | loosening | rule ETH-02 (require_reason) removed — a constraint is gone |
| SEC-04 | added | tightening | rule SEC-04 (forbid_action) added — something newly forbidden or required |
| ORG-01 | modified | tightening | params now cover more: {'limit_usd': 5.0} -> {'limit_usd': 2.0} |
| SEC-01 | modified | tightening | severity raised medium -> high |

Plans approved under the old pack may no longer comply. Re-check them before they run.
