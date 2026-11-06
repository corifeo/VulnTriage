# VulnTriage

An SSVC triage dashboard for vulnerability specialists. Pick a CVE from the queue, read the evidence, walk the SSVC decision points and move it into a bucket. The flow itself is configurable: decision points, options, buckets, the outcome policy and override rules.

**Status: first draft.** It runs entirely in the browser, keeps its state in `localStorage`, and has no backend.

## Run it

No build step and no dependencies.

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

Opening `index.html` straight from disk also works, except **Import › Load demo export**, which needs HTTP.

## What it does

| View | |
|---|---|
| **Triage queue** | Queue of untriaged CVEs with a filter. The centre walks each SSVC decision point, with evidence and a suggested value per point. "Move to bucket" records the decision, the decision vector and the analyst's rationale, then loads the next CVE. |
| **Buckets** | One column per bucket, plus untriaged. Open any card to re-triage it. Export decisions as JSON. |
| **Configure flow** | Rename or reorder decision points, add or remove options, add combined points (two questions resolving to one level, like CISA's Mission & well-being), edit buckets and their remediation targets, edit the outcome policy cell by cell, and add override rules such as "if Exploitation is Active, at least Attend". Starts from the CISA SSVC tree. Export and import flows as JSON. |

The right rail breaks down the CVSS vector into an attack path (entry point, complexity, privileges, interaction, scope) with C/I/A impact, EPSS and KEV.

## Importing vulnerabilities

VulnTriage reads `vulntriage.queue/v1` JSON, which [VulnFlow](https://github.com/corifeo/vulnflow)'s `TriageLoader` writes:

```python
from vulnflow.helpers import CacheBuilder
from vulnflow.loaders import TriageLoader

ds = CacheBuilder(recent_only=True).build()
TriageLoader("triage-queue.json", min_epss=0.01).load(ds)
```

Then **Import** in the top bar, and drop the file in. Imports are added to the queue (re-imported CVEs are updated, not duplicated), or can replace the sample data. Format: [`docs/queue-schema.md`](docs/queue-schema.md). A demo export with the real Log4Shell record is in [`examples/triage-queue-demo.json`](examples/triage-queue-demo.json).

Suggested values cover Exploitation, Automatable and Technical impact. Mission & well-being is always the analyst's call: no public feed knows your assets.

## Layout

```
index.html          the page and its template
src/runtime.js      ~200-line template renderer ({{holes}}, <sc-for>, <sc-if>, events)
src/app.js          state, SSVC engine, import, flow builder
docs/               file formats
examples/           demo export
```

## Known gaps

- The CISA outcome table is transcribed by hand; it needs tests against the CISA SSVC guide before anyone relies on it.
- State lives in one browser. Sharing a queue across a team needs a backend.
- The eight built-in sample CVEs are invented; they disappear once you import with "Replace the sample CVEs".
- Asset context (mission prevalence, well-being) is manual; an inventory import is the obvious next source.
