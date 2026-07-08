# security_doctor

[![CI](https://github.com/PopovVA/security_doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/PopovVA/security_doctor/actions/workflows/ci.yml)

Security audit for Flutter and Dart apps. Every rule maps to an
[OWASP MASVS](https://mas.owasp.org/MASVS/) requirement and a
[CWE](https://cwe.mitre.org/) id, so findings speak the language auditors
already use. Built for CI: exit codes work like a test suite, reports come
in console, JSON, Markdown and SARIF (GitHub Code Scanning) formats.

> Status: pre-release. The rule engine and the first rules are under
> active development. The sibling package for dependency auditing is
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
exclude:
  - lib/generated/**  # globs, relative to the project root
```

Severities are `low`, `medium`, `high`, `critical`; the default
`fail_on` is `low`. The `--fail-on` CLI flag overrides the config, and
`--json` switches the report to JSON.

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
| SD008 | Sensitive data in `print`/log output | MASVS-STORAGE-2 | CWE-532 | planned |

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
