# Contributing to ThreatVault Plugins

Thank you for your interest in contributing to ThreatVault! We welcome plugins for any security tool.

## 🚀 How to Contribute

### 1. Before You Start

- Check if a plugin for your tool already exists in `Plugins/`
- Read the [Plugin Creation Guide](PLUGIN_CREATION_GUIDE.md) for detailed instructions
- Gather sample output from your security tool

### 2. Development Process

1. **Fork the repository**
   ```bash
   # On GitHub, click "Fork" button
   ```

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ThreatVault-Plugins.git
   cd ThreatVault-Plugins
   ```

3. **Create a branch**
   ```bash
   git checkout -b add-toolname-plugin
   ```

4. **Create your plugin**
   ```bash
   # Choose the right category
   mkdir -p Plugins/VAPT/VA/YourTool  # or Compliance/YourTool
   cd Plugins/VAPT/VA/YourTool

   # Create plugin file
   touch yourtool.py

   # Create test file (recommended)
   touch test_yourtool.py

   # Add sample data (optional but helpful)
   touch sample_scan.csv
   ```

5. **Write your plugin**
   - Follow the templates in [PLUGIN_CREATION_GUIDE.md](PLUGIN_CREATION_GUIDE.md)
   - Use [QUICK_REFERENCE.md](QUICK_REFERENCE.md) as a cheat sheet
   - Check [blueprint.txt](blueprint.txt) for detailed specifications

6. **Test thoroughly**
   ```bash
   python test_yourtool.py
   ```

7. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add YourTool VAPT plugin for vulnerability scanning"
   ```

8. **Push to your fork**
   ```bash
   git push origin add-toolname-plugin
   ```

9. **Create a Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your branch
   - Fill out the PR template (see below)

### 3. Pull Request Template

When creating your PR, please include:

```markdown
## Plugin Information

- **Tool Name**: YourTool
- **Plugin Type**: VAPT (VA/SAST/DAST/SCA) or Compliance
- **Input Format**: CSV / JSON
- **Version Tested**: v1.2.3 (if applicable)

## Description

Brief description of what the tool does and what the plugin transforms.

## Testing

- [ ] Tested with real scan output
- [ ] All required fields populated
- [ ] Schema validation passes
- [ ] Edge cases handled (nulls, empty values, special characters)
- [ ] Test file included: `test_yourtool.py`

## Files Added

- `Plugins/<Type>/<Category>/<Tool>/yourtool.py` - Main plugin
- `Plugins/<Type>/<Category>/<Tool>/test_yourtool.py` - Test script
- `Plugins/<Type>/<Category>/<Tool>/sample_scan.csv` - Sample input (optional)

## Additional Notes

Any special considerations, dependencies, or tool-specific quirks.
```

## 📋 Plugin Requirements

Your plugin will be reviewed against these criteria:

### Code Quality

- [ ] Clean, readable code with comments
- [ ] Follows Python best practices (PEP 8)
- [ ] No hardcoded credentials or sensitive data
- [ ] Proper error handling

### Functionality

- [ ] Implements required `process(file: bytes, file_type: str)` function
- [ ] Returns `pl.LazyFrame` or `pl.DataFrame`
- [ ] Correct schema for VAPT or Compliance
- [ ] All required fields present in exact order
- [ ] Proper data types (especially `port` as Int64)

### Data Validation

- [ ] File type validation
- [ ] Risk values: CRITICAL/HIGH/MEDIUM/LOW (VAPT)
- [ ] Status values: PASSED/FAILED/WARNING (Compliance)
- [ ] Newlines replaced with `<br/>` in text fields
- [ ] Handles null/empty values appropriately
- [ ] Port numbers are integers

### Testing

- [ ] Works with sample scan output
- [ ] Test script provided (recommended)
- [ ] Edge cases handled

## 🎯 Plugin Categories

Choose the right category for your plugin:

### VAPT (Vulnerability Assessment & Penetration Testing)

**VA (Vulnerability Assessment)**
- Network scanners: Nessus, OpenVAS, Qualys
- Cloud security: AWS Inspector, Azure Security Center
- Infrastructure scanners

**SAST (Static Application Security Testing)**
- Code analyzers: Semgrep, Bandit, SonarQube
- Security linters
- Code quality tools with security findings

**DAST (Dynamic Application Security Testing)**
- Web app scanners: Burp Suite, ZAP, Acunetix
- API security tools
- Runtime analysis tools

**SCA (Software Composition Analysis)**
- Dependency scanners: Trivy, Snyk, WhiteSource
- License compliance tools
- Container security scanners

### Compliance

- CIS Benchmarks
- NIST frameworks
- ISO 27001 audits
- PCI DSS scanners
- HIPAA compliance tools
- Custom policy checkers

### SBOM (Software Bill of Materials)

- Dependency tracking
- License management
- Supply chain security

## ✅ Review Process

1. **Automated Checks** (if configured)
   - Code style validation
   - Basic syntax checks

2. **Manual Review**
   - Maintainers will review your code
   - Test with validation suite
   - Check schema compliance
   - Verify data transformations

3. **Feedback**
   - You may receive change requests
   - Address feedback by updating your PR
   - Push new commits to your branch

4. **Approval & Merge**
   - Once approved, your plugin will be merged
   - Your contribution will be available to all ThreatVault users!

## 🐛 Reporting Issues

Found a bug in an existing plugin?

1. Check if an issue already exists
2. Create a new issue with:
   - Plugin name and location
   - Description of the problem
   - Sample input data (sanitized)
   - Expected vs actual output
   - Error messages (if any)

## 💡 Requesting Features

Have an idea for a new plugin or feature?

1. Open an issue with:
   - Tool name
   - What it does
   - Why it's useful
   - Sample output format (if available)

## 📖 Documentation

When contributing, please:

- Add inline comments for complex logic
- Include docstrings for functions
- Update README if needed
- Provide sample input files (sanitized)

Example:

```python
def process(file: bytes, file_type: str) -> pl.LazyFrame:
    """
    Transform ToolName CSV output to ThreatVault VAPT format.

    Args:
        file: Raw CSV file content as bytes
        file_type: MIME type (expected: "text/csv")

    Returns:
        LazyFrame with standardized ThreatVault schema

    Raises:
        ValueError: If file_type is not supported

    Example:
        >>> with open("scan.csv", "rb") as f:
        ...     result = process(f.read(), "text/csv")
        >>> df = result.collect()
        >>> print(len(df))
        42
    """
```

## 🔒 Security

- **Never commit** API keys, tokens, or credentials
- **Sanitize** all sample data (remove real IPs, hostnames, sensitive info)
- **Report security vulnerabilities** privately to maintainers

## 🤝 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn
- Follow community guidelines

## 📞 Getting Help

Stuck? We're here to help!

- **Documentation**: Check [PLUGIN_CREATION_GUIDE.md](PLUGIN_CREATION_GUIDE.md)
- **Examples**: Browse existing plugins in `Plugins/`
- **Questions**: Open an issue with the "question" label
- **Discussions**: Use GitHub Discussions (if enabled)

## 🎉 Recognition

Contributors will be:
- Listed in repository contributors
- Mentioned in release notes (if applicable)
- Helping the security community!

## 📝 Checklist for Contributors

Before submitting your PR, ensure:

- [ ] Code follows plugin template structure
- [ ] All required fields are mapped correctly
- [ ] Schema is in exact order (VAPT or Compliance)
- [ ] Port field is Int64 type
- [ ] Newlines replaced with `<br/>` tags
- [ ] File type validation included
- [ ] Risk/Status values are validated
- [ ] Null values are handled
- [ ] Test script works with sample data
- [ ] No sensitive information in code or samples
- [ ] Commits have clear, descriptive messages
- [ ] PR description is complete

## 🔄 Updating Existing Plugins

If you're improving an existing plugin:

1. Explain why the change is needed
2. Show before/after behavior
3. Test with existing scan outputs
4. Ensure backward compatibility (if possible)
5. Update tests if schema changes

## 📚 Additional Resources

- [README.md](README.md) - Repository overview
- [PLUGIN_CREATION_GUIDE.md](PLUGIN_CREATION_GUIDE.md) - Complete tutorial
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - One-page cheat sheet
- [blueprint.txt](blueprint.txt) - Technical specification
- [CLAUDE.md](CLAUDE.md) - AI assistant guidance

---

**Thank you for contributing to ThreatVault! Your work helps security teams everywhere.** 🚀🔒
