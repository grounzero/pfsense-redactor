## Description

Provide a clear and concise description of what this PR does.

**Fixes**: #(issue number)

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🧪 Test improvements
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] 🔒 Security fix

## Changes Made

- Change 1
- Change 2
- Change 3

## Testing

Describe the tests you ran to verify your changes:

- [ ] Existing tests pass (`pytest tests/`)
- [ ] Added new tests for new functionality
- [ ] Tested on multiple platforms (Windows/macOS/Linux)
- [ ] Tested with sample pfSense configs
- [ ] Tested with different Python versions (3.9, 3.10, 3.11, 3.12, 3.13)

### Test commands used

```bash
# Example test commands
pytest tests/ -v
pfsense-redactor test-configs/default-config.xml --dry-run
```

## Impact Assessment

**Backwards compatibility**:

- [ ] ✅ Fully backwards compatible
- [ ] ⚠️ Minor compatibility changes (document below)
- [ ] 💥 Breaking changes (document below)

**Security implications**:

- [ ] No security impact
- [ ] Improves security
- [ ] Requires security review

## Documentation

- [ ] Updated README.md (if needed)
- [ ] Updated CHANGELOG.md
- [ ] Added/updated docstrings
- [ ] Added/updated comments for complex logic
- [ ] Updated test documentation (if applicable)

## Code Quality

- [ ] Code follows the project's style guidelines
- [ ] Self-review completed
- [ ] No new linting warnings/errors
- [ ] No debug/console statements left in code
- [ ] Type hints added (where applicable)

## Additional Notes

Add any additional context, screenshots, or information that reviewers should know.

## Checklist

- [ ] I have read the [Contributing Guidelines](../README.md#contributing)
- [ ] My code follows the project's coding standards
- [ ] I have performed a self-review of my code
- [ ] I have commented complex or non-obvious code
- [ ] I have made corresponding changes to documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing tests pass locally
- [ ] Any dependent changes have been merged
