# `vulntriage.queue/v1`

The import format for VulnTriage. VulnFlow's `TriageLoader` writes it; anything else can too.

```json
{
  "schema": "vulntriage.queue/v1",
  "generated_at": "2026-11-06T22:00:00Z",
  "generator": "vulnflow 0.1.0",
  "filters": { "start": null, "end": null, "kev_only": false, "min_epss": 0.01, "min_cvss": null, "limit": 500 },
  "enrichment": { "kev": true, "epss": true, "cvss_flattened": true },
  "matched": 812,
  "count": 500,
  "items": [ ... ]
}
```

`matched` is the number of CVEs that passed the filters; `count` is how many were exported after the limit. Items are ranked KEV first, then EPSS, then CVSS.

## Item

| Field | Type | Notes |
|---|---|---|
| `id` | string | CVE ID. **Required**; items without it are skipped |
| `title` | string | KEV vulnerability name, else the description's first sentence |
| `description` | string \| null | |
| `published`, `modified` | ISO 8601 \| null | NVD dates |
| `nvd_status` | string \| null | `analyzed`, `modified`, `awaiting`, `deferred` |
| `product` | object | `vendor`, `name`, `fixed_in` (list of versions from the affected vendor's CPEs), `cpe_count` |
| `cvss` | object \| null | `version`, `score`, `severity`, `vector`, `metrics` (`{"AV": "N", ...}`), `source` |
| `cwe` | string[] | `["CWE-502"]` |
| `epss` | object \| null | `probability`, `percentile` (0 to 1), `date` |
| `kev` | object | `listed`, `date_added`, `due_date`, `ransomware`, `required_action` |
| `exploit_refs` | string[] | Reference URLs NVD tags `Exploit` |
| `references` | object[] | First 15: `url`, `tags` |
| `evidence` | object | Suggested SSVC values, below |

## Evidence

Each key is optional and holds `{ "value": ..., "reason": "..." }`. VulnTriage marks the matching option as "Evidence" and "Pre-fill from evidence" selects it. They are suggestions for the analyst to confirm.

| Key | Values | VulnFlow's rule |
|---|---|---|
| `exploitation` | `none`, `poc`, `active` | `active` if in KEV or CVSS v4 E:A; `poc` if a reference is tagged Exploit or E:P |
| `automatable` | `no`, `yes` | `yes` only with AV:N, AC:L, PR:N, UI:N; CVSS v4 AU wins when present |
| `technical_impact` | `partial`, `total` | `total` with high confidentiality and integrity impact |

The values match the option IDs of the CISA flow. In a custom flow, a decision point picks up evidence when its ID is `e`, `a` or `t` and its evidence source is not "Manual only".

## Other formats

- `vulntriage.decisions/v1`: Buckets › Export decisions. One entry per decided CVE with bucket, decision vector, answers, rationale and time.
- `vulntriage.flow/v1`: Configure › Export flow. Decision points, buckets, outcome policy and override rules; Import flow reads it back.
