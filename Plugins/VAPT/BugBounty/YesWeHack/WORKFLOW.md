# YesWeHack → ThreatVault Workflow Guide

## Overview

This document is a runbook for exporting YesWeHack bug bounty reports via `ywh2csv.py`, uploading them to ThreatVault, and verifying the rendering in the browser.

**Plugins directory:** `/opt/ThreatVault-Plugins/Plugins/VAPT/BugBounty/YesWeHack/`

**Key files:**
- `ywh2csv.py` — exports YesWeHack reports to ThreatVault CSV format
- `tv_helpers.py` — ThreatVault wipe/reload/upload utilities (CLI-only, no browser needed)
- `yeswehack.py` — the ThreatVault plugin that processes the CSV

---

## The Three Fixes (How They Work)

### Fix 1: HTML Tables → `<pre>` Blocks

**Problem:** ThreatVault's bleach filter (`SAFE_TAGS`) does NOT include `<table>`, `<tr>`, `<td>`, `<th>`. When bleach processes HTML, it strips all table tags entirely, but preserves the inner text of cells. Without row structure, all cell text runs together as one blob.

**Solution:** `_convert_tables_to_pre()` runs BEFORE bleach, converting every `<table>...</table>` block into a `<pre>` block with pipe-delimited columns:

```
<pre>
Bank | Accounts | Full Name
----------------------
Maybank | 2 | John Doe
CIMB | 1 | Jane Smith
</pre>
```

**How the conversion works (code walkthrough):**

```python
def _convert_tables_to_pre(text: str) -> str:
    import re

    def convert_table(m):
        table_html = m.group(0)

        # Step 1: Strip <br/> tags — YesWeHack HTML has <br/> between every tag
        # inside tables, which would otherwise corrupt header cell extraction
        table_html = re.sub(r'<br\s*/?>', '', table_html)

        # Step 2: Extract <th> cells using NEGATIVE LOOKAHEAD
        # r'<th(?![a-z/])' ensures we match <th> but NOT <thead>, </thead>, etc.
        # because those contain letters or '/' immediately after 'th'
        header_cells = re.findall(r'<th(?![a-z/])([^>]*)>(.*?)</th>', table_html, ...)
        clean_headers = []
        for attrs, content in header_cells:
            # Strip any HTML tags inside the cell (e.g., <code>, <strong>)
            clean = re.sub(r'<[^>]+>', '', content, flags=re.DOTALL).strip()
            if clean:
                clean_headers.append(clean)

        # Step 3: Extract all <tr> rows
        rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table_html, re.DOTALL | re.IGNORECASE)

        lines = []
        if clean_headers:
            # Header line + separator line
            lines.append(' | '.join(clean_headers))
            lines.append('-' * (sum(len(h) for h in clean_headers) + 3 * (len(clean_headers) - 1)))

        # Step 4: Extract <td> cells per row (same negative lookahead trick)
        for row_content in rows:
            cells = re.findall(r'<td(?![a-z/])([^>]*)>(.*?)</td>', row_content, ...)
            ...

        return '<pre>\n' + '\n'.join(lines) + '\n</pre>'

    # Match full <table>...</table> blocks
    # KEY: flags=re.DOTALL | re.IGNORECASE as KEYWORD ARG, not positional
    # Passing as 4th positional arg would be interpreted as count=48 (max replacements)
    return re.sub(r'<table[^>]*>.*?</table>', convert_table, text, flags=re.DOTALL | re.IGNORECASE)
```

**Critical detail — negative lookahead for `th` and `td`:**

YesWeHack HTML has patterns like this:
```html
<table>
  <br/>
  <thead>
    <br/>
    <tr>
      <br/>
      <th>Bank</th>
```

A naive `<th>(.*?)</th>` pattern would match nothing because `.*?` with `re.DOTALL` is lazy and the `<br/>` tags get in the way. Instead:
- `<th(?![a-z/])` — the negative lookahead `(?![a-z/])` says "only match `<th>` if the next character is NOT a lowercase letter or `/`". This skips `<thead>` and `</thead>` which have letters or `/` right after `th`.
- Same for `<td(?![a-z/])` to skip `<td>` matches inside `<thead>` or `<tbody>`.

**Bleach-safe?** Yes. `<pre>` IS in `SAFE_TAGS`.

---

### Fix 2: `<h3>` → `<p><strong>`

**Problem:** `SAFE_TAGS` does not include `h2` or `h3`. Both are stripped by bleach, losing heading semantics. The existing code converted `<h2>` but not `<h3>`.

**Solution:** In `format_description()`, both `<h2>` and `<h3>` are converted to `<p><strong>text</strong></p>`:

```python
text = re.sub(
    r'<h2>(.*?)</h2>',
    lambda m: f'<p><strong>{re.sub(r"<[^>]+>", "", m.group(1)).strip()}</strong></p>',
    text, flags=re.DOTALL
)
text = re.sub(
    r'<h3>(.*?)</h3>',
    lambda m: f'<p><strong>{re.sub(r"<[^>]+>", "", m.group(1)).strip()}</strong></p>',
    text, flags=re.DOTALL
)
```

**Why `(.*?)` + `re.DOTALL` + inner strip?**
Consider: `<h3>Step 2 — Overwrite all mutable fields with <code>YWH_onosh</code></h3>`

- Pattern `r'<h3>([^<]+)</h3>'` uses `[^<]+` which stops at the first `<` — would only match `Step 2 — Overwrite all mutable fields with `.
- Pattern `(.*?)` with `re.DOTALL` matches everything inside `<h3>` including nested tags.
- `re.sub(r"<[^>]+>", "", m.group(1))` then strips HTML tags from the matched content, leaving just the text.
- `.strip()` removes any leftover whitespace.

**Bleach-safe?** Yes. `<p>`, `<strong>` are in `SAFE_TAGS`.

---

### Fix 3: `extract_remediation()` — Only h2 Section + Hardcoded Fallback

**Problem:** The original function had a 4-step priority chain (h2 section → suggestions JSON → bug_type → empty string). In practice, `suggestions` contains endpoint/payload data (not remediation advice) and `bug_type.remediation_link` is never populated. The empty fallback was unfriendly.

**Solution:** Simplified to only look for the `<h2>Remediation</h2>` section, with a hardcoded fallback message:

```python
def extract_remediation(description_html: str, suggestions: Any, bug_type: Dict) -> str:
    import re

    # Try h2 Remediation section (handles multilingual: Remediation, Remédiation, Remèdiation)
    if description_html:
        pattern = r'<h2>[^<]*[Rr]em[eéè]d[iI]ation[^<]*</h2>(.*?)(?=<h2|$)'
        match = re.search(pattern, description_html, re.DOTALL | re.IGNORECASE)
        if match:
            remediation_html = match.group(1).strip()
            if remediation_html:
                return _normalize_block_html(remediation_html)

    return 'No Remediation Provided by Hunter. If you need assistance, kindly contact purplesec@paynet.my'
```

**Why `(.*?)(?=<h2|$)`?** — Match content until the next `<h2>` tag OR end of string (`$`). This captures all content inside the Remediation section even if there are nested paragraphs or lists.

**French support:** The regex `[Rr]em[eéè]d[iI]ation` matches:
- `Remediation` / `remediation` (English)
- `Remédiation` / `remédiation` (French with accent)
- `Remèdiation` / `remèdiation` (French with grave accent)

---

## Step-by-Step: Wipe, Reload & Verify

### Prerequisites

- `YWH_API_KEY` environment variable set
- `THREATVAULT_API_TOKEN` environment variable set (for `tv_helpers.py`)
- ThreatVault running at `http://127.0.0.1:8000` (or override with `THREATVAULT_BASE_URL`)
- Chrome DevTools connection active (for browser verification)

### Step 1: Export from YesWeHack

```bash
cd /opt/ThreatVault-Plugins/Plugins/VAPT/BugBounty/YesWeHack

# Export with filters (only accepted + pending-fix reports)
python3 ywh2csv.py <program-slug> -o /tmp/nfp.csv

# Export ALL reports (no filter) — use for testing or full reload
python3 ywh2csv.py <program-slug> -o /tmp/nfp.csv --no-filter
```

### Step 2: Verify CSV Before Upload

```bash
# Count reports
wc -l /tmp/nfp.csv

# Check for raw table tags (should be 0)
grep -c '<table' /tmp/nfp.csv

# Check for h3 tags (should be 0)
grep -c '<h3' /tmp/nfp.csv

# Check for raw newlines in description (should be 0)
grep -c '^"' /tmp/nfp.csv

# Find a specific report for spot-check
grep "JWT Tokens" /tmp/nfp.csv
```

### Step 3: Wipe + Upload via Browser (Recommended)

Using the browser gives you visual confirmation and works without needing `THREATVAULT_API_TOKEN`.

1. Navigate to ThreatVault → Products → NFP
2. Click **"Upload Started"** button
3. Set Last Scan Date to today (click spinbutton, use `evaluate_script` to set `input[type="date"]` value to `'YYYY-MM-DD'`)
4. Select the YesWeHack plugin (ID: `654ee9b9-b73a-4490-9c1f-c22b7ccd4678`)
5. Upload the CSV file
6. Wait for processing to complete

### Step 4: Alternative — Wipe + Upload via CLI

If `THREATVAULT_API_TOKEN` is set:

```bash
cd /opt/ThreatVault-Plugins/Plugins/VAPT/BugBounty/YesWeHack

# Wipe product data AND reload
python3 tv_helpers.py refresh \
  --file /tmp/nfp.csv \
  --product-name "NFP" \
  --plugin-id 654ee9b9-b73a-4490-9c1f-c22b7ccd4678
```

What `refresh` does:
1. Deletes all findings for the product
2. Deletes all finding_names for the product's findings
3. Deletes all file_upload_log entries
4. Clears the DuckDB snapshot
5. Restarts the ThreatVault app container
6. Uploads the new CSV

### Step 5: Verify in Browser

1. Open the NFP product in ThreatVault
2. Find the specific report (e.g., "Information Disclosure... JWT Tokens")
3. Click to open the finding detail
4. Check:
   - **Description**: Tables render as `<pre>` blocks with ` | ` delimited columns
   - **Solution**: Shows `"No Remediation Provided by Hunter. If you need assistance, kindly contact purplesec@paynet.my"` if no Remediation/Recommendation h2 section
   - **h3 headers**: Any `<h3>` sections appear bold inside description

---

## Troubleshooting

### Tables still appearing stripped after upload

1. Re-export the CSV and check: `grep -c '<table' /tmp/nfp.csv` — should be 0
2. If tables still appear, check the specific finding in the CSV:
   ```bash
   grep "JWT Tokens" /tmp/nfp.csv | grep '<table'
   ```
3. Verify `_convert_tables_to_pre()` was called — the function name should appear in `grep` results from the source

### `re.sub` callback not firing (historical issue)

**Symptom:** `_convert_tables_to_pre()` function exists but tables aren't converted.

**Root cause (from prior debugging):** Two compounding issues:
1. `convert_table` was defined inside an `if` block at 4-space indentation, making it scoped to that block only
2. `flags=re.DOTALL | re.IGNORECASE` was passed as the 4th positional argument, which Python interpreted as `count=48` instead of `flags`

**Fix:** Always use `flags=` keyword argument:
```python
# WRONG (passes 48 as count, not flags):
re.sub(pattern, callback, text, re.DOTALL | re.IGNORECASE)

# CORRECT:
re.sub(pattern, callback, text, flags=re.DOTALL | re.IGNORECASE)
```

### h3 headers not bolded after upload

1. Check CSV: `grep -c '<h3' /tmp/nfp.csv` — should be 0 (all converted to `<p><strong>`)
2. Check `format_description()` in source — h3 substitution line must be present
3. Verify the regex uses `(.*?)` not `([^<]+)` — the latter stops at first nested `<`

### Upload button stays disabled

**Symptom:** Date spinbutton UI is tricky to interact with via DevTools `fill`.

**Fix:** Use `evaluate_script` to set the hidden `input[type="date"]` value directly:
```javascript
// Set scan date to today
document.querySelector('input[type="date"]').value = '2026-04-10'
```

Then trigger change event and wait for the button to enable.

### `tv_helpers.py refresh` fails with "Please provide valid api key!"

**Cause:** Using the wrong token. The JWT from `document.cookie` (browser session) is NOT the same as the ThreatVault API key.

**Fix:** Use the **API key from ThreatVault Manage API**, not the browser cookie:
1. Go to ThreatVault UI → **Manage API**
2. Create or copy your API key (a long random string, NOT the `Bearer eyJ...` JWT)
3. Pass it via `--token` flag

The API key format: `Authorization: <api_key>` (no `Bearer ` prefix).

### CLI refresh vs browser upload

**CLI refresh (`tv_helpers.py refresh`) is now the primary method** — it correctly:
1. Deletes `finding_name` records BEFORE `finding` records (order matters for the SQL join)
2. Uploads via `/api/upload` REST endpoint with API key auth
3. Clears DuckDB snapshot and waits for app readiness before upload

**Browser upload is fallback only** — needed if API key is unavailable or API endpoint fails.

| Resource | ID |
|---|---|
| NFP Product | `bd29dd54-bdff-4ea1-8b50-2683bc8223fc` |
| YesWeHack Plugin | `654ee9b9-b73a-4490-9c1f-c22b7ccd4678` |

---

## Quick Reference Commands

```bash
# Export
python3 ywh2csv.py paynet-nfp-bug-bounty-program -o /tmp/nfp.csv --no-filter

# Verify CSV
grep -c '<table' /tmp/nfp.csv       # should be 0
grep -c '<h3' /tmp/nfp.csv           # should be 0

# List products
python3 tv_helpers.py list-products

# Wipe only
python3 tv_helpers.py clean --product-name "NFP"

# CLI refresh (needs API key from ThreatVault Manage API, not JWT from browser)
python3 tv_helpers.py refresh --file /tmp/nfp.csv --product-name "NFP" \
  --plugin-id 654ee9b9-b73a-4490-9c1f-c22b7ccd4678 \
  --token "your-api-key-from-manage-api"
```
