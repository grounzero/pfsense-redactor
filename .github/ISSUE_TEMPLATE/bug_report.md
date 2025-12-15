---
name: Bug Report
about: Report a bug or unexpected behavior
title: "BUG: "
labels: bug
assignees: ""
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

1. Run command: `pfsense-redactor ...`
2. With config file: '...'
3. See error

## Expected Behaviour

What you expected to happen.

## Actual Behaviour

What actually happened.

## Error Output

```
Paste any error messages or unexpected output here
```

## Environment

- **OS**: (e.g., Windows 11, macOS 14, Ubuntu 22.04)
- **Python version**: (run `python --version`)
- **pfsense-redactor version**: (run `pfsense-redactor --version`)
- **Installation method**: (pip, pipx, source, venv)

## Sample Config (if applicable)

If the issue is related to a specific config structure, please provide a **redacted** sample XML snippet:

```xml
<example>
  <!-- Minimal XML that reproduces the issue -->
</example>
```

**⚠️ Important**: Never paste real pfSense configs – redact sensitive data first! [Learn more about redacting configs.](https://github.com/grounzero/pfsense-redactor#redacting-configs)

## Additional Context

Add any other context about the problem here (screenshots, logs, etc.).

## Checklist

- [ ] I have searched existing issues to avoid duplicates
- [ ] I have included all relevant information above
- [ ] I have redacted any sensitive information from samples
- [ ] I am using a supported Python version (3.9+)
