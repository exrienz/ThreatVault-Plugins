# 🤖 AI Plugin Generator - Quick Start Guide

Generate production-ready ThreatVault plugins in minutes using AI!

---

## 📝 Step 1: Prepare Your Prompt

Copy this template and fill in your tool details:

```
I need to create a ThreatVault plugin for [TOOL_NAME].

**Tool Information**:
- Tool Name: [e.g., Acunetix, Qualys, Checkmarx]
- Plugin Type: [VAPT or Compliance]
- Input Format: [CSV, JSON, or XML]

**Sample Output**:
[Paste first 50-100 lines of your tool's output OR upload the file]

Please generate a complete, production-ready ThreatVault plugin following all requirements from the ThreatVault Plugin Generator prompt.

**Critical Requirements**:
- Port field MUST be Integer type (pl.Int64)
- Handle all null values appropriately
- Use empty string "" for optional fields (CVE, VPR Score, Evidence)
- Replace newlines with <br/> in text fields
- Validate risk/status values
- Include complete test script

Generate:
1. Complete plugin code (plugin.py)
2. Test script (test_plugin.py)
3. Installation instructions
4. Validation checklist
```

---

## 🚀 Step 2: Use with Your Favorite LLM

### Option A: ChatGPT

1. Open [ChatGPT](https://chat.openai.com)
2. Start a new conversation
3. **First message**: Paste the entire [PLUGIN_GENERATOR_PROMPT.md](./PLUGIN_GENERATOR_PROMPT.md) system prompt
4. **Second message**: Use the template from Step 1 with your tool details

### Option B: Claude

1. Open [Claude](https://claude.ai)
2. Start a new conversation
3. **First message**: Paste the entire [PLUGIN_GENERATOR_PROMPT.md](./PLUGIN_GENERATOR_PROMPT.md) system prompt
4. **Second message**: Use the template from Step 1 with your tool details
5. Upload your sample file if available

### Option C: Other LLMs

- Gemini, Llama, or any other LLM
- Same process: System prompt first, then your specific request

---

## 📋 Step 3: Review Generated Code

The AI will provide:

### 1. Plugin Analysis
```markdown
## Analysis of [Tool Name] Output
- Field mappings
- Required transformations
- Edge cases identified
```

### 2. Complete Plugin Code
```python
"""
[Tool Name] Plugin for ThreatVault
"""
import polars as pl

def process(file: bytes, file_type: str) -> pl.DataFrame:
    # Fully implemented, production-ready code
    # with all required transformations
    ...
```

### 3. Test Script
```python
# test_toolname.py
# Complete validation script
```

### 4. Usage Instructions
```markdown
## Installation
## Testing
## Expected Output
```

---

## ✅ Step 4: Validate the Generated Code

Check these critical items:

```markdown
**Port Field** (Most Critical!)
- [ ] Port is `pl.Int64` type (NOT String)
- [ ] Empty values converted to 0
- [ ] Null values converted to 0

**Null Handling**
- [ ] CVE field: null → "" (empty string)
- [ ] VPR Score: null → "" (empty string)
- [ ] Evidence: null → "" (empty string)
- [ ] All required fields: no nulls present

**Data Validation**
- [ ] Risk values: CRITICAL, HIGH, MEDIUM, LOW only
- [ ] Status values: PASSED, FAILED, WARNING only (Compliance)
- [ ] Newlines replaced with <br/> in text fields

**Output Format**
- [ ] Returns pl.DataFrame (not LazyFrame or dict)
- [ ] Columns in exact required order
- [ ] All required fields present
```

---

## 🧪 Step 5: Test the Plugin

1. **Save the generated code**:
   ```bash
   mkdir -p Plugins/VAPT/VA/YourTool
   # Save plugin code to: Plugins/VAPT/VA/YourTool/yourtool.py
   # Save test script to: Plugins/VAPT/VA/YourTool/test_yourtool.py
   ```

2. **Run the test**:
   ```bash
   cd Plugins/VAPT/VA/YourTool
   python test_yourtool.py
   ```

3. **Expected output**:
   ```
   ✅ Plugin executed successfully!
   📊 Processed [X] findings

   🔍 Schema validation:
   ✅ Port type: Int64
   ✅ All required fields present
   ✅ No nulls in required fields

   🔍 Data validation:
   ✅ Risk values valid
   ✅ All rows processed
   ```

---

## 🐛 Troubleshooting

### Issue: Port is String type, not Integer

**Symptom**: Schema shows `port: String`

**Fix**: Ask the AI to regenerate with this specific instruction:
```
The port field must be Integer type (pl.Int64), not String.
Please update the code to convert port to integer using:

pl.col("port")
    .fill_null("0")
    .cast(pl.Utf8)
    .str.replace("^$", "0")
    .cast(pl.Int64, strict=False)
    .fill_null(0)
    .alias("port")
```

### Issue: Null values in required fields

**Symptom**: `null_count() > 0` for required fields

**Fix**: Ask the AI to add null handling:
```
Please add null handling for all required fields:

df = df.with_columns([
    pl.col("risk").fill_null("MEDIUM"),
    pl.col("host").fill_null("unknown"),
    pl.col("name").fill_null("Unknown Issue"),
    pl.col("description").fill_null("No description available"),
    pl.col("remediation").fill_null("No remediation available"),
    pl.col("evidence").fill_null(""),
])
```

### Issue: Invalid risk/status values

**Symptom**: Rows contain INFO, INFORMATIONAL, or other invalid values

**Fix**: Ask the AI to add filtering:
```
Please add validation to filter only valid risk values:

# For VAPT
df = df.filter(pl.col("risk").is_in(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))

# For Compliance
df = df.filter(pl.col("status").is_in(["PASSED", "FAILED", "WARNING"]))
```

### Issue: Newlines not replaced

**Symptom**: Text fields contain literal `\n` characters

**Fix**: Ask the AI to add:
```
Please add newline replacement for text fields:

df = df.with_columns(
    pl.col("description", "remediation", "evidence").str.replace_all("\n", "<br/>")
)
```

---

## 📚 Example Prompts for Common Tools

### Burp Suite CSV
```
I need a ThreatVault plugin for Burp Suite.

Tool: Burp Suite Professional
Type: VAPT (DAST)
Format: CSV

The CSV has these columns: serial_number, type, name, severity, confidence, host,
host_ip, path, location, issue_background, issue_detail, remediation_background,
remediation_detail, request, response

Port field is empty (web application). Please convert to integer 0.
Severity should map to risk (High → HIGH, Medium → MEDIUM, Low → LOW).
Combine issue_background and issue_detail for description field.
```

### Trivy Container Scan JSON
```
I need a ThreatVault plugin for Trivy container scans.

Tool: Trivy (Container Scanner)
Type: VAPT (SCA)
Format: JSON

The JSON structure has:
- Results array containing vulnerabilities
- Each vulnerability has: VulnerabilityID, PkgName, Severity, Description, FixedVersion

Map VulnerabilityID to CVE field.
Map Severity (CRITICAL/HIGH/MEDIUM/LOW) to risk field.
Use container name as host.
Port should be 0 (container scan).
```

### CIS Benchmark CSV
```
I need a ThreatVault plugin for CIS Benchmark results.

Tool: CIS-CAT Lite
Type: Compliance
Format: CSV

The CSV has: Benchmark, Rule Number, Rule Title, Result, Severity

Map Result to status (Pass → PASSED, Fail → FAILED, Manual → WARNING).
Map Severity to risk (High → HIGH, Medium → MEDIUM, Low → LOW).
Port should be 0 for all compliance checks.
Extract hostname from Benchmark field.
```

---

## 💡 Pro Tips

1. **Provide More Context**: The more details you give about your tool's output format, the better the generated code

2. **Include Edge Cases**: Mention any special characters, empty fields, or unusual data formats in your sample

3. **Iterate if Needed**: If the first generation isn't perfect, ask the AI to fix specific issues

4. **Test with Real Data**: Always test with actual output from your tool, not just sample data

5. **Save the Conversation**: Keep the AI conversation for future reference or updates

6. **Ask for Explanations**: If you don't understand a transformation, ask the AI to explain it

---

## 🔗 Resources

- **Full AI Prompt**: [PLUGIN_GENERATOR_PROMPT.md](./PLUGIN_GENERATOR_PROMPT.md)
- **Manual Development Guide**: [README.md](./README.md)
- **Technical Specification**: [blueprint.txt](./blueprint.txt)
- **Plugin Examples**: [Plugins/](./Plugins/) directory

---

## ❓ FAQ

**Q: Can I use this for any security tool?**
A: Yes! As long as the tool outputs CSV, JSON, or XML, the AI can generate a plugin.

**Q: How accurate is the AI-generated code?**
A: Very accurate when given good sample data. Always test before using in production.

**Q: What if my tool uses a custom format?**
A: Provide a detailed description of the format. The AI can handle complex structures.

**Q: Can I modify the generated code?**
A: Absolutely! The code is a starting point. Customize as needed.

**Q: What if the generated code doesn't work?**
A: Use the troubleshooting section above, or ask the AI to fix specific issues.

**Q: Is the generated code production-ready?**
A: Yes, but always test thoroughly with your specific data first.

---

## 🎯 Success Checklist

Before submitting or using your AI-generated plugin:

- [ ] Generated code runs without errors
- [ ] Port field is Integer type (pl.Int64)
- [ ] No null values in required fields
- [ ] Risk/Status values are valid
- [ ] Test script validates all requirements
- [ ] Tested with real tool output (not just sample)
- [ ] Code includes error handling
- [ ] Documentation is complete

---

**Ready to generate your plugin? Get started with [PLUGIN_GENERATOR_PROMPT.md](./PLUGIN_GENERATOR_PROMPT.md)!**
