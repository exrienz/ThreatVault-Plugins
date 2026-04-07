# ThreatVault Plugins

This repository contains Python plugins that convert security tool output into the format ThreatVault expects.

If you are new to the project, think of a plugin as a translator:

1. A scanner exports a report as CSV, JSON, XML, or NDJSON.
2. Your plugin reads that file.
3. Your plugin returns a Polars `DataFrame` or `LazyFrame` with the exact ThreatVault schema.

That is the whole job.

## Start Here

If you are a junior engineer or intern, use this order:

1. Read this README fully once.
2. Open one sample plugin that looks similar to your tool.
3. Copy that sample into a new folder for your tool.
4. Replace the field mapping with your tool's columns.
5. Test the `process()` function with a real sample file.
6. Check the final column names, order, and types before opening a PR.

If you get stuck, do not invent a structure from scratch. Copy the nearest existing plugin and adapt it.

## What A Plugin Must Do

Every plugin must expose this function:

```python
import polars as pl


def process(file: bytes, file_type: str) -> pl.LazyFrame | pl.DataFrame:
    ...
```

ThreatVault will call `process()` and pass:

- `file`: the uploaded file contents as raw bytes
- `file_type`: the MIME type or short type string such as `text/csv`, `application/json`, `json`, or `xml`

Your plugin must:

- validate the incoming `file_type`
- parse the file
- map the source fields into the ThreatVault schema
- clean obvious bad values
- return a Polars `DataFrame` or `LazyFrame`

## Repository Layout

The repo is organized by data type first, then by tool family.

```text
Plugins/
├── Compliance/
│   ├── Nessus/
│   └── Cloud/AWS/SecurityHub/
└── VAPT/
    ├── VA/
    ├── SAST/
    ├── DAST/
    ├── SCA/
    ├── Cloud/AWS/Inspector/
    ├── AD/PurpleKnight/
    ├── EDR/Crowdstrike/
    └── BugBounty/YesWeHack/
```

Use the closest existing category. If your tool is:

- a network or infrastructure scanner, start under `Plugins/VAPT/VA/`
- a code scanner, start under `Plugins/VAPT/SAST/`
- a web or API scanner, start under `Plugins/VAPT/DAST/`
- a dependency or package scanner, start under `Plugins/VAPT/SCA/`
- a policy or benchmark checker, start under `Plugins/Compliance/`

## Which Sample Plugin Should You Copy?

Do not pick samples randomly. Start from the one that matches your input format and data shape.

| If your tool looks like this | Start from this sample | Why it is useful |
| --- | --- | --- |
| Flat CSV with columns already close to the target schema | [`Plugins/VAPT/VA/Nessus/nessus.py`](./Plugins/VAPT/VA/Nessus/nessus.py) | Smallest example of rename/filter/cleanup |
| CSV with extra parsing or derived fields | [`Plugins/VAPT/SAST/ThreatCode/threatcode.py`](./Plugins/VAPT/SAST/ThreatCode/threatcode.py) | Shows column normalization and derived values |
| Nested JSON with multiple supported shapes | [`Plugins/VAPT/VA/Trivy/trivy.py`](./Plugins/VAPT/VA/Trivy/trivy.py) | Good example of defensive JSON handling |
| JSON array of findings from a SAST tool | [`Plugins/VAPT/SAST/Semgrep/semgrep.py`](./Plugins/VAPT/SAST/Semgrep/semgrep.py) | Easy-to-read loop-based mapping |
| XML input | [`Plugins/VAPT/DAST/BurpSuite/burpsuite.py`](./Plugins/VAPT/DAST/BurpSuite/burpsuite.py) | Good reference for XML parsing and empty result handling |
| Compliance report with text extraction | [`Plugins/Compliance/Nessus/nessus.py`](./Plugins/Compliance/Nessus/nessus.py) | Shows regex extraction and compliance-specific schema |
| Cloud compliance findings | [`Plugins/Compliance/Cloud/AWS/SecurityHub/securityhub.py`](./Plugins/Compliance/Cloud/AWS/SecurityHub/securityhub.py) | Good for helper functions and evidence/remediation builders |

Rule of thumb:

- flat CSV: start from Nessus or ThreatCode
- nested JSON: start from Trivy or Semgrep
- XML: start from BurpSuite
- compliance text parsing: start from Compliance Nessus

## The Two Schemas You Must Respect

ThreatVault mainly uses two plugin output shapes in this repository.

### VAPT Schema

Use this for vulnerability findings.

```python
["cve", "risk", "host", "port", "name", "description", "remediation", "evidence", "vpr_score"]
```

Field expectations:

| Field | Type | Notes |
| --- | --- | --- |
| `cve` | string | Use `""` if the tool does not provide a CVE |
| `risk` | string | Must end up as `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW` |
| `host` | string | IP, hostname, image name, repo name, or another useful target identifier |
| `port` | integer | Real port if available, otherwise usually `0` |
| `name` | string | Finding title |
| `description` | string | Replace newlines with `<br/>` |
| `remediation` | string | Replace newlines with `<br/>` |
| `evidence` | string | Replace newlines with `<br/>`; empty string is fine |
| `vpr_score` | string | Use `""` if not provided |

Important notes from existing samples:

- Most infrastructure, cloud, and web plugins use `0` when there is no real network port.
- Some SAST plugins store a source code line number in `port` because ThreatVault still expects an integer column.
- Keep the value numeric. Do not return `"0"` as a string.

### Compliance Schema

Use this for pass/fail or rules-based checks.

```python
["risk", "host", "port", "name", "description", "remediation", "evidence", "status"]
```

Field expectations:

| Field | Type | Notes |
| --- | --- | --- |
| `risk` | string or null | Can be `None` if severity is not meaningful |
| `host` | string | Hostname, instance, account, resource, or target identifier |
| `port` | integer | Usually `0` |
| `name` | string | Control, rule, or check name |
| `description` | string | Replace newlines with `<br/>` |
| `remediation` | string | Replace newlines with `<br/>` |
| `evidence` | string | Supporting text or observed value |
| `status` | string | Must end up as `PASSED`, `FAILED`, or `WARNING` unless the backend explicitly expects another value |

Important difference:

- VAPT uses `cve` and `vpr_score`.
- Compliance does not.

## Five Rules That Break Plugins Most Often

If you remember only five things, remember these:

1. The final columns must be in the exact expected order.
2. `port` must be an integer column, not a string column.
3. Risk and status values must be normalized to the allowed values.
4. Newlines in long text should be changed to `<br/>`.
5. Empty results should still return a valid empty `DataFrame` with the correct schema when possible.

## How To Build A Plugin

### 1. Collect a real sample file

Do not build from screenshots or guessed field names. Save one real export from the tool first.

Questions to answer before coding:

- Is the file CSV, JSON, NDJSON, or XML?
- Are the findings in a top-level list, nested array, or repeated XML node?
- Which field best represents severity?
- Which field best identifies the affected target?
- Where is the remediation text?

### 2. Decide the plugin type

Use VAPT when the report describes vulnerabilities, exposures, or weaknesses.

Use Compliance when the report describes checks, controls, or pass/fail rules.

### 3. Create the folder

Examples:

```bash
mkdir -p Plugins/VAPT/VA/YourTool
mkdir -p Plugins/VAPT/SAST/YourTool
mkdir -p Plugins/Compliance/YourTool
```

### 4. Start from a sample, then rename fields

The usual workflow is:

1. validate file type
2. parse input
3. extract or rename source columns
4. normalize values
5. select the exact ThreatVault schema order
6. return the result

### 5. Use a simple starter template

For a beginner, this style is easier to maintain than trying to be too clever early.

```python
import json
import polars as pl

VAPT_COLUMNS = [
    "cve",
    "risk",
    "host",
    "port",
    "name",
    "description",
    "remediation",
    "evidence",
    "vpr_score",
]


def empty_vapt_df() -> pl.DataFrame:
    return pl.DataFrame(
        schema={
            "cve": pl.Utf8,
            "risk": pl.Utf8,
            "host": pl.Utf8,
            "port": pl.Int64,
            "name": pl.Utf8,
            "description": pl.Utf8,
            "remediation": pl.Utf8,
            "evidence": pl.Utf8,
            "vpr_score": pl.Utf8,
        }
    )


def html_text(value: str | None) -> str:
    return (value or "").replace("\n", "<br/>")


def to_port(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def process(file: bytes, file_type: str) -> pl.DataFrame:
    if file_type not in {"application/json", "json"}:
        raise ValueError(f"Unsupported file type: {file_type}")

    data = json.loads(file.decode("utf-8"))
    findings = data.get("findings", [])

    rows = []
    for finding in findings:
        rows.append(
            {
                "cve": finding.get("cve", "") or "",
                "risk": (finding.get("severity", "MEDIUM") or "MEDIUM").upper(),
                "host": finding.get("target", "") or "",
                "port": to_port(finding.get("port")),
                "name": finding.get("title", "") or "",
                "description": html_text(finding.get("description")),
                "remediation": html_text(finding.get("solution")),
                "evidence": html_text(finding.get("evidence")),
                "vpr_score": str(finding.get("vpr_score", "") or ""),
            }
        )

    if not rows:
        return empty_vapt_df()

    df = pl.DataFrame(rows)
    df = df.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
    return df.select(VAPT_COLUMNS)
```

What to customize:

- the supported `file_type` values
- where the findings live in the source file
- how severity maps into ThreatVault risk values
- how host, evidence, and remediation should be built

### 6. Normalize values on purpose

Common cleanups used across the repo:

```python
pl.col("risk").str.to_uppercase()
pl.col("status").str.to_uppercase()
pl.col("port").cast(pl.Int64, strict=False).fill_null(0)
pl.col("description").str.replace_all("\n", "<br/>")
pl.col("remediation").str.replace_all("\n", "<br/>")
pl.col("evidence").str.replace_all("\n", "<br/>")
```

Typical filters:

```python
df = df.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
df = df.filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
```

### 7. Return the final schema last

Make this the final step so you can inspect intermediate columns while developing.

```python
df = df.select([
    "cve",
    "risk",
    "host",
    "port",
    "name",
    "description",
    "remediation",
    "evidence",
    "vpr_score",
])
```

## How To Test Your Plugin

At minimum, test with one real file locally before you commit.

Simple test pattern:

```python
import polars as pl
from pathlib import Path

from yourtool import process


def test_plugin():
    sample = Path("sample.json").read_bytes()
    result = process(sample, "application/json")
    df = result.collect() if hasattr(result, "collect") else result

    print(df.head())
    print(df.schema)

    expected = [
        "cve",
        "risk",
        "host",
        "port",
        "name",
        "description",
        "remediation",
        "evidence",
        "vpr_score",
    ]

    assert df.columns == expected
    assert df.schema["port"] == pl.Int64


if __name__ == "__main__":
    test_plugin()
```

What you should verify:

- the plugin does not crash on the sample input
- the output columns are correct and ordered correctly
- `port` is numeric
- risk or status values are valid
- empty fields are handled predictably
- multiline text displays cleanly with `<br/>`

## Common Mistakes

### Mistake 1: Returning almost the right columns

ThreatVault needs the exact schema, not a close approximation.

Wrong:

```python
["risk", "host", "name", "description"]
```

Right:

```python
["cve", "risk", "host", "port", "name", "description", "remediation", "evidence", "vpr_score"]
```

### Mistake 2: Leaving `port` as a string

Wrong:

```python
"port": "443"
```

Right:

```python
"port": 443
```

### Mistake 3: Passing through raw severity labels

Your source tool may use `Error`, `Warning`, `Info`, `Informational`, `Medium`, or custom labels. Map them to the values ThreatVault expects.

### Mistake 4: Forgetting empty-result handling

Some valid reports contain no findings. That should not automatically be treated as a parser failure.

### Mistake 5: Over-engineering the first version

A clear plugin with a few helper functions is better than a clever plugin that nobody can debug later.

## Definition Of Done

Your plugin is ready when all of these are true:

- it has a `process(file: bytes, file_type: str)` function
- it validates supported file types
- it works against a real sample export
- it returns the exact ThreatVault schema
- it normalizes values the backend depends on
- it handles missing or empty values without crashing
- it is placed in the correct folder under `Plugins/`

## Helpful Repo Docs

Use these documents after this README:

- [`PLUGIN_CREATION_GUIDE.md`](./PLUGIN_CREATION_GUIDE.md): longer tutorial with more examples
- [`QUICK_REFERENCE.md`](./QUICK_REFERENCE.md): short cheat sheet for everyday development
- [`CONTRIBUTING.md`](./CONTRIBUTING.md): pull request and contribution process
- [`blueprint.txt`](./blueprint.txt): lower-level specification details

## AI-Assisted Plugin Generation

If you want AI to generate a first draft, use:

- [`PLUGIN_GENERATOR_PROMPT.md`](./PLUGIN_GENERATOR_PROMPT.md)
- [`AI_PLUGIN_QUICK_START.md`](./AI_PLUGIN_QUICK_START.md)

That can save time, but you still need to review the generated code against the schema and testing checklist above.

## Final Advice

The safest way to create a new plugin is:

1. find the closest sample
2. copy it
3. replace the field mapping carefully
4. test with a real file
5. check schema, types, and normalization one last time

If you follow those five steps, you will avoid most plugin bugs in this repository.
