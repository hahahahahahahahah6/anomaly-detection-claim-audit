# Documented capability auditor

Version 0.1.0. An offline audit of documented outlier-flagging capability against Python source. Requires Python 3.9 or newer; no runtime dependencies.

Install and run:

```sh
pip install .
anomaly-detection-claim-audit /path/to/project
python3 -m anomaly_detection_claim_audit /path/to/project --json
```

The scanner reads root README.md and Markdown files with a docs directory component. It skips fenced code, includes inline code, and compares normalized paragraph templates with static constructor evidence. Templates live in the package, outside this guide.

Python files are parsed without execution. Supported evidence comes from selected sklearn estimators and pyod.models constructors, with import aliases resolved in each module. Local definitions shadow imported names. This is a conservative static heuristic: it cannot establish runtime behavior or inspect dynamic imports. Syntax-invalid source contributes no evidence.

Symlinks are skipped. Files in fixtures, docs, and examples directories do not contribute source evidence. Test files contribute separate evidence. Paths supplied through repeatable --ignore options exclude relative path prefixes.

```sh
anomaly-detection-claim-audit . --verbose --ignore build --ignore dist
anomaly-detection-claim-audit . --fail-on MEDIUM
anomaly-detection-claim-audit --version
```

Default failure threshold is HIGH. Test-only evidence produces MEDIUM. Exit codes are 0 when findings are below the threshold or absent, 2 for findings meeting the threshold, and 1 for usage or I/O errors. JSON includes status, findings, production_evidence, and test_evidence. Status is FAIL whenever any finding exists, even below the exit threshold.

Example claim and finding identifiers:

```text
detect anomalies
documented-anomaly-claim-false HIGH
no anomaly detection
documented-no-anomaly-claim-false HIGH
```

A positive claim without production evidence yields HIGH, reduced to MEDIUM when evidence appears only in tests. A negative claim with production evidence yields HIGH. With no source files, positive claims still produce HIGH and negative claims pass.

The tool uses no network, writes no files, and collects no telemetry.

Run tests and build:

```sh
python3 -m unittest discover
python3 -m build
```

Licensed under MIT.
