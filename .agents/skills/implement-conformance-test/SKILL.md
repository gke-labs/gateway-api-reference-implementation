# Skill: Implementing Gateway API Conformance Tests

This skill outlines the process, best practices, and requirements for implementing or enabling Gateway API conformance tests in the reference implementation.

## Overview

When enabling or fixing a conformance test (e.g., enabling a test that was previously commented out, or resolving a failure in an active test), it is crucial to record detailed research, strategy, and findings.

## Strict Recording Requirements

To ensure knowledge is preserved and shared without introducing merge conflicts or cluttering the codebase:

1. **Do Not Modify This File Directly for Specific Test Findings**: To prevent multiple PRs from creating merge conflicts on this main `SKILL.md` file, do not add individual test details here.
2. **Create a Test Journal File**: For every conformance test you work on, you MUST create a markdown journal file at:
   ` .agents/skills/implement-conformance-test/journal/<testname>.md`
   (where `<testname>` is the name of the conformance test in kebab-case or snake-case, e.g., `httproute-exact-path-matching.md`).
3. **Pattern Promotion**: Only when a clear pattern or recurring strategy is identified across multiple journal files should we "promote" those patterns and general guidelines into this main `SKILL.md` file.

## Journal File Template

Each journal file under `journal/<testname>.md` should follow this structure:

```markdown
# Conformance Test Journal: <TestName>

## 1. Test Overview
- **Name**: Name of the conformance test (e.g., `HTTPRouteExactPathMatching`).
- **Description**: Brief description of what the test verifies.
- **Manifests**: Location of the YAML manifests used by the test (if applicable).

## 2. Issue / Failure Analysis
- **Observed Behavior**: What was the failure or reason the test was disabled?
- **Root Cause**: Explanation of the discrepancy between the reference implementation's behavior and the expected behavior of the conformance test.

## 3. Implementation / Fix Strategy
- **Approach**: Step-by-step plan of how the issue was fixed or enabled.
- **Key Files Modified**: List of files changed.

## 4. Validation & Results
- **Unit Tests**: Any new or updated unit tests to verify the behavior locally.
- **Conformance Logs**: Successful pass logs showing the test passes under the target Gateway API version.
```
