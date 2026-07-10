# security_doctor

[![CI](https://github.com/PopovVA/security_doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/PopovVA/security_doctor/actions/workflows/ci.yml)

Security audit for Flutter and Dart apps. Every rule maps to an
[OWASP MASVS](https://mas.owasp.org/MASVS/) requirement and a
[CWE](https://cwe.mitre.org/) id, so findings speak the language auditors
already use. Built for CI: exit codes work like a test suite, reports come
in console, JSON, Markdown and SARIF (GitHub Code Scanning) formats.

> Status: pre-release. All phase-1 rules are implemented; first publish
> is coming as 0.1.0. The sibling package for dependency auditing is
> [pubspec_doctor](https://pub.dev/packages/pubspec_doctor).

## Quick start

```sh
dart pub global activate security_doctor
security_doctor
```

## Configuration

Drop a `security_audit.yaml` next to your `pubspec.yaml` (all keys
optional):

```yaml
rules:
  SD002: false        # disable a rule
fail_on: high         # exit 1 only for findings at/above this severity
baseline: security_baseline.json  # optional; this is the default name
exclude:
  - lib/generated/**  # globs, relative to the project root
```

Severities are `low`, `medium`, `high`, `critical`; the default
`fail_on` is `low`. The `--fail-on` CLI flag overrides the config, and
`--format` picks the report: `console` (default), `json`, `markdown`
or `sarif`.

### Adopting on an existing project

Snapshot the current findings once, commit the file, and only new
findings will fail CI — historical debt stays visible (a "hidden"
counter in every report) without blocking:

```sh
security_doctor --write-baseline   # writes security_baseline.json
```

Baseline entries match findings by a content hash (rule + file +
normalized line), so they survive unrelated edits and line shifts.
Delete the file or re-run `--write-baseline` to reset.

### Compliance mapping (PCI DSS, ISO 27001)

`--compliance` regroups the report by requirements of a standard, in
the language auditors ask in:

```sh
security_doctor --compliance pci-dss
security_doctor --compliance iso-27001 --format markdown
```

Requirements with no findings are listed as clean. The mapping is
informative evidence for audit preparation — not a compliance verdict.

| Id | PCI DSS v4.0 | ISO 27001:2022 Annex A |
| --- | --- | --- |
| SD001 | 8.6.2 | A.5.17, A.8.28 |
| SD002 | 4.2.1 | A.5.14, A.8.24 |
| SD003 | 3.5.1 | A.8.24 |
| SD004 | 3.5.1, 4.2.1 | A.8.24 |
| SD005 | 4.2.1 | A.5.14, A.8.24 |
| SD006 | 6.5.6 | A.8.9 |
| SD007 | 7.2.1 | A.8.9 |
| SD008 | 3.3.1 | A.8.15 |

### GitHub Code Scanning

```yaml
- run: security_doctor --format sarif > security.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security.sarif
```

### Demo

An intentionally vulnerable mini app lives in
[`example/vulnerable_app`](example/vulnerable_app) — every rule fires on
it:

```sh
security_doctor --path example/vulnerable_app
```

## Rules (phase 1)

| Id | Rule | MASVS | CWE | Status |
| --- | --- | --- | --- | --- |
| SD001 | Hardcoded secrets and API keys in Dart code | MASVS-STORAGE-1 | CWE-798 | ✅ |
| SD002 | Cleartext `http://` URLs in code | MASVS-NETWORK-1 | CWE-319 | ✅ |
| SD003 | Sensitive data in SharedPreferences | MASVS-STORAGE-1 | CWE-922 | ✅ |
| SD004 | Weak cryptography (MD5, SHA1, ECB) | MASVS-CRYPTO-1 | CWE-327 | ✅ |
| SD005 | `usesCleartextTraffic` / `NSAllowsArbitraryLoads` | MASVS-NETWORK-1 | CWE-319 | ✅ |
| SD006 | `android:debuggable` / `android:allowBackup` | MASVS-RESILIENCE-2 | CWE-489 | ✅ |
| SD007 | Dangerous Android permissions | MASVS-PLATFORM-1 | CWE-250 | ✅ |
| SD008 | Sensitive data in `print`/log output | MASVS-STORAGE-2 | CWE-532 | ✅ |

Optional compliance mapping (PCI DSS, ISO 27001 Annex A) is planned as an
opt-in report layer on top of the same findings.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the severity threshold. |
| `1` | Findings at or above the threshold. |
| `2` | Usage or runtime error (e.g. no `pubspec.yaml`). |

## License

[MIT](LICENSE)
