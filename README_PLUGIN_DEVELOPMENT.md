# ThreatVault Plugin Development Resources

Welcome to the ThreatVault Plugin Development Kit! This collection provides everything you need to create custom plugins for importing security scan data into ThreatVault.

---

## 📚 Available Resources

### 1. **PLUGIN_DEVELOPMENT_GUIDE.md** - Complete Tutorial
   - **Who it's for:** Beginners and intermediate developers
   - **What it covers:**
     - Introduction to plugins
     - Prerequisites and setup
     - Field specifications and data types
     - Step-by-step tutorials for VA and Compliance
     - Testing and validation
     - Troubleshooting common errors
     - Best practices
     - Complete working examples
   - **Length:** Comprehensive (100+ sections)
   - **Start here if:** You're new to plugin development

### 2. **PLUGIN_QUICK_REFERENCE.md** - Cheat Sheet
   - **Who it's for:** Quick lookups and experienced developers
   - **What it covers:**
     - Field requirements table
     - Common Polars operations
     - Quick code snippets
     - Common mistakes vs correct approaches
     - Ready-to-use templates
   - **Length:** 1-page reference
   - **Use this when:** You need a quick reminder or code snippet

### 3. **template_va_plugin.py** - VA Plugin Template
   - **Who it's for:** Developers creating vulnerability assessment plugins
   - **What it is:**
     - Ready-to-use Python template
     - Pre-structured with all required sections
     - Inline TODO comments for customization
     - Built-in test code
   - **How to use:**
     1. Copy the file
     2. Replace placeholder column names with your actual CSV columns
     3. Test with your scan file
     4. Deploy to ThreatVault

### 4. **template_compliance_plugin.py** - Compliance Plugin Template
   - **Who it's for:** Developers creating compliance check plugins
   - **What it is:**
     - Ready-to-use Python template for compliance scans
     - Pre-configured with compliance-specific fields
     - Includes status mapping examples
     - Built-in test code
   - **How to use:**
     1. Copy the file
     2. Replace placeholder column names
     3. Test with your compliance scan file
     4. Deploy to ThreatVault

### 5. **semgrep_plugin.py** - Real-World Example
   - **Who it's for:** Learning by example
   - **What it is:**
     - Production-ready Semgrep plugin
     - Handles JSON input
     - Shows advanced data transformation
   - **Use case:** Static code analysis tool integration

### 6. **sample_va_plugins.py** - Official Example
   - **Who it's for:** Understanding ThreatVault's plugin patterns
   - **What it is:**
     - Official vulnerability assessment plugin example
     - Shows nested JSON handling
     - Demonstrates best practices

### 7. **threatvault-plugins-requirement.txt** - Official Requirements
   - **Who it's for:** Understanding ThreatVault's expectations
   - **What it is:**
     - Official plugin requirements documentation
     - Field mappings
     - VAPT vs Compliance differences

---

## 🚀 Quick Start Guide

### For Complete Beginners

1. **Read:** Open `PLUGIN_DEVELOPMENT_GUIDE.md`
2. **Learn:** Go through the "Step-by-Step Tutorial" section
3. **Practice:** Use `template_va_plugin.py` or `template_compliance_plugin.py`
4. **Test:** Follow the testing instructions in the guide
5. **Deploy:** Upload to ThreatVault

### For Experienced Developers

1. **Copy:** `template_va_plugin.py` or `template_compliance_plugin.py`
2. **Reference:** Keep `PLUGIN_QUICK_REFERENCE.md` open
3. **Customize:** Update column mappings for your tool
4. **Test:** Run built-in test code
5. **Deploy:** Upload to ThreatVault

### For Learning by Example

1. **Open:** `semgrep_plugin.py` (JSON-based)
2. **Or Open:** `sample_va_plugins.py` (CSV-based)
3. **Study:** How data is transformed
4. **Adapt:** For your own tool's format
5. **Deploy:** Your customized version

---

## 📋 Plugin Type Decision Tree

```
Is your scan finding vulnerabilities or checking compliance?

├─ Finding Vulnerabilities (bugs, misconfigurations, CVEs)
│  └─ Use: VA (Vulnerability Assessment) Plugin
│     ├─ Template: template_va_plugin.py
│     ├─ Fields: 9 required (includes cve, vpr_score)
│     ├─ Uses: risk levels (CRITICAL, HIGH, MEDIUM, LOW)
│     └─ Examples: Nessus, OpenVAS, Semgrep, Burp Suite
│
└─ Checking Compliance (policy adherence, standards)
   └─ Use: Compliance Plugin
      ├─ Template: template_compliance_plugin.py
      ├─ Fields: 8 required (NO cve or vpr_score)
      ├─ Uses: status (PASSED, FAILED, WARNING)
      └─ Examples: CIS Benchmarks, ISO 27001, PCI-DSS
```

---

## 🛠️ Development Workflow

### Step 1: Understand Your Scan File

```bash
# Look at your scan file structure
head -20 scan_results.csv
# or
cat scan_results.json | jq '.' | head -50
```

**Identify:**
- What format? (CSV or JSON)
- What are the column names?
- How is severity/status represented?
- Are there any nested fields?

### Step 2: Choose Plugin Type

- **VA Plugin** if your tool finds security issues
- **Compliance Plugin** if your tool checks policy compliance

### Step 3: Use the Template

```bash
# Copy the appropriate template
cp template_va_plugin.py my_scanner_plugin.py
# or
cp template_compliance_plugin.py my_compliance_plugin.py
```

### Step 4: Customize Column Mappings

Open your plugin file and update the column names:

```python
# FROM (template):
pl.col("Source_Severity_Column").alias("risk"),

# TO (your actual column):
pl.col("Risk Level").alias("risk"),
```

### Step 5: Test Locally

```bash
# Run the built-in test (at bottom of template file)
python3 my_scanner_plugin.py

# Or create a separate test file
python3 test_my_plugin.py
```

### Step 6: Validate Output

Ensure your plugin returns:
- ✅ Correct number of columns (9 for VA, 8 for Compliance)
- ✅ Correct column names (case-sensitive)
- ✅ Correct data types (strings vs integers)
- ✅ No None/null values for required fields
- ✅ Risk/status values in uppercase
- ✅ Newlines replaced with `<br/>`

### Step 7: Deploy to ThreatVault

1. Upload your plugin file to ThreatVault
2. Test with a small scan file first
3. Verify results in ThreatVault dashboard
4. Deploy for production use

---

## 📖 Field Requirements Summary

### VA (Vulnerability Assessment)

| # | Field | Type | Required | Empty OK? |
|---|-------|------|----------|-----------|
| 1 | cve | String | ✅ | ✅ |
| 2 | risk | String | ✅ | ❌ |
| 3 | host | String | ✅ | ❌ |
| 4 | port | Integer | ✅ | ✅ (use 0) |
| 5 | name | String | ✅ | ❌ |
| 6 | description | String | ✅ | ❌ |
| 7 | remediation | String | ✅ | ❌ |
| 8 | evidence | String | ✅ | ✅ |
| 9 | vpr_score | String | ✅ | ✅ |

**Risk Values:** CRITICAL, HIGH, MEDIUM, LOW

### Compliance

| # | Field | Type | Required | Empty OK? |
|---|-------|------|----------|-----------|
| 1 | risk | String | ✅ | ✅ (auto "Medium") |
| 2 | host | String | ✅ | ❌ |
| 3 | port | Integer | ✅ | ✅ (use 0) |
| 4 | name | String | ✅ | ❌ |
| 5 | description | String | ✅ | ❌ |
| 6 | remediation | String | ✅ | ❌ |
| 7 | evidence | String | ✅ | ✅ |
| 8 | status | String | ✅ | ❌ |

**Status Values:** PASSED, FAILED, WARNING

❌ **Do NOT include in Compliance:** cve, vpr_score

---

## 🔧 Common Use Cases

### Use Case 1: CSV-Based Vulnerability Scanner

**Tool:** Custom vulnerability scanner with CSV output
**Plugin Type:** VA
**Template:** template_va_plugin.py
**Key Tasks:**
- Map CSV columns to ThreatVault fields
- Convert severity names to risk levels
- Handle port numbers

### Use Case 2: JSON-Based Code Scanner

**Tool:** Static code analysis tool (like Semgrep)
**Plugin Type:** VA
**Reference:** semgrep_plugin.py
**Key Tasks:**
- Parse JSON structure
- Extract nested fields
- Build evidence from file paths and line numbers

### Use Case 3: CIS Benchmark Compliance Checker

**Tool:** CIS benchmark audit tool
**Plugin Type:** Compliance
**Template:** template_compliance_plugin.py
**Key Tasks:**
- Map check results to status (PASSED/FAILED)
- Extract actual vs expected values
- Set port to 0

### Use Case 4: Nessus CSV Export

**Tool:** Nessus vulnerability scanner
**Plugin Type:** VA or Compliance (depends on scan type)
**Reference:** See examples in PLUGIN_DEVELOPMENT_GUIDE.md
**Key Tasks:**
- Handle both scan types with same CSV structure
- Parse nested description fields
- Map "None" severity appropriately

---

## ❓ FAQ

### Q: What's the difference between VA and Compliance plugins?

**A:** VA plugins find security issues and use risk levels (Critical/High/Medium/Low). Compliance plugins check policy adherence and use status (Passed/Failed/Warning).

### Q: Can I use both CSV and JSON in one plugin?

**A:** Yes! Check the file_type parameter and handle both:

```python
if file_type == "text/csv":
    df = pl.read_csv(file)
elif file_type in ["application/json", "json"]:
    data = json.loads(file.decode('utf-8'))
    # process JSON
else:
    raise ValueError(f"Unsupported: {file_type}")
```

### Q: What if my tool uses different severity names?

**A:** Map them using string replacement:

```python
pl.col("Severity")
  .str.replace("Critical", "CRITICAL")
  .str.replace("Severe", "HIGH")
  .str.to_uppercase()
  .alias("risk")
```

### Q: How do I handle multi-line descriptions?

**A:** Replace newlines with HTML breaks:

```python
pl.col("description").str.replace_all("\n", "<br/>")
```

### Q: Can CVE be empty?

**A:** Yes, for VA plugins. Use empty string:

```python
pl.col("CVE").fill_null("").alias("cve")
```

### Q: What if I don't have a port number?

**A:** Use 0:

```python
pl.lit(0).alias("port")
```

### Q: Do compliance plugins need CVE fields?

**A:** No! Compliance plugins should NOT include cve or vpr_score.

---

## 📞 Getting Help

### Self-Help Resources

1. **Error Messages:** Check "Common Errors and Troubleshooting" in PLUGIN_DEVELOPMENT_GUIDE.md
2. **Code Examples:** Study semgrep_plugin.py and sample_va_plugins.py
3. **Quick Lookup:** Use PLUGIN_QUICK_REFERENCE.md for syntax

### Documentation Files to Check

| Problem | Check This File |
|---------|----------------|
| Don't know where to start | PLUGIN_DEVELOPMENT_GUIDE.md (Introduction) |
| Need field definitions | PLUGIN_QUICK_REFERENCE.md or PLUGIN_DEVELOPMENT_GUIDE.md (Field Specifications) |
| Polars syntax questions | PLUGIN_QUICK_REFERENCE.md (Common Polars Operations) |
| Error debugging | PLUGIN_DEVELOPMENT_GUIDE.md (Common Errors) |
| Template starting point | template_va_plugin.py or template_compliance_plugin.py |
| Real-world example | semgrep_plugin.py |

---

## 📝 Example File Listing

```
plugin-development-kit/
├── README_PLUGIN_DEVELOPMENT.md          ← You are here
├── PLUGIN_DEVELOPMENT_GUIDE.md           ← Full tutorial
├── PLUGIN_QUICK_REFERENCE.md             ← Cheat sheet
├── template_va_plugin.py                 ← VA template
├── template_compliance_plugin.py         ← Compliance template
├── semgrep_plugin.py                     ← Working example
├── sample_va_plugins.py                  ← Official example
├── threatvault-plugins-requirement.txt   ← Requirements
└── test_semgrep_plugin.py               ← Test example
```

---

## 🎯 Success Checklist

Before deploying your plugin to production:

- [ ] Plugin follows required function signature: `process(file: bytes, file_type: str) -> pl.DataFrame`
- [ ] All required fields are present and correctly named
- [ ] Data types are correct (strings vs integers)
- [ ] Empty/null values are handled properly
- [ ] Text fields have newlines converted to `<br/>`
- [ ] Risk/status values are uppercase
- [ ] Invalid rows are filtered out
- [ ] Plugin tested with sample data
- [ ] Plugin tested with real scan file
- [ ] Error handling implemented
- [ ] Plugin validated with test script
- [ ] For VA: 9 columns, includes cve and vpr_score
- [ ] For Compliance: 8 columns, excludes cve and vpr_score
- [ ] Column order matches requirements

---

## 🚀 Next Steps

1. **Choose your starting point** based on your experience level
2. **Follow the workflow** outlined above
3. **Test thoroughly** before deploying
4. **Iterate** based on results

Good luck with your plugin development! 🎉

---

**Last Updated:** 2025
**Version:** 1.0
**Maintainer:** ThreatVault Development Team
