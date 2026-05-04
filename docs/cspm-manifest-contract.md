# CSPM Manifest Finding Contract

This document defines the shared contract used by the Go and Python manifest
scanners.

## Canonical finding fields

Each finding should be represented with these fields:

- `rule_id`: Stable identifier for the rule that fired.
- `severity`: Presentation label for the finding severity. Consumers should
  treat it case-insensitively.
- `severity_level`: Normalized severity value used by the Python reporter.
- `description`: Human-readable explanation of the finding.
- `remediation`: Short fix guidance.
- `resource`: Optional Kubernetes resource reference such as `Deployment/app`.
- `path`: Optional manifest path.
- `line_number`: Optional line number when it can be determined.

## Compatibility fields

The Python CSPM path still accepts the legacy `rule`, `message`, and `file`
keys when consuming findings, but new code should emit the canonical fields
above.

Python findings also include a `severity_level` helper field so reporters can
sort and summarize results without depending on the legacy presentation label.

## Implementation notes

- Go scanner violations already map cleanly to this contract through
  `pkg/types.Violation`.
- Python scanner findings should be normalized through
  `cspm/manifest_contract.py` before reporting or storage.