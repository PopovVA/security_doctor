# CLAUDE.md — security_doctor guardrails

Security audit CLI for Flutter/Dart (OWASP MASVS + CWE mapped rules).
Sibling of pubspec_doctor — conventions are transferred from it 1:1.

## Invariants
- Every rule is a class with metadata: id (SD###), severity, description,
  MASVS requirement, CWE id. Every rule ships with positive AND negative
  fixture tests. False positives are the worst failure mode — err quiet.
- CLI contract is frozen: exit 0 = clean, 1 = findings at/above threshold,
  2 = usage/runtime error. Reports: console, JSON, Markdown, SARIF.
- Rules declare what input they need (raw text / string literals / AST) —
  do not run the analyzer AST pass for rules that do not need it.

## Workflow
- Branches from `main`; merge only via squash PR. PR title = Conventional
  Commit (drives release-please versioning).
- CI gates: format, analyze --fatal-infos, tests, coverage >= 80%,
  pubspec_doctor audit, pana (threshold 60), pub downgrade + analyze.
  Keep dependency lower bounds honest (`dart pub downgrade` must analyze
  clean) — pub.dev scores this.
- Releases: release-please opens the release PR; merging it tags vX.Y.Z,
  publish.yml pushes to pub.dev via OIDC. Moving tag v0 follows releases.
  Release 0.1.0 is manual (first pub.dev publish), automation after.
- Do not commit secrets; no Claude attribution in commits/PRs
  (.claude/settings.json).

## Status
- Done: scaffolding, CI/CD, CLI skeleton (stage 2); rule engine core,
  security_audit.yaml config, console/JSON reports (stage 3); rules
  SD001-SD004 on the lazy AST pass, fixtures under test/fixtures/
  excluded from analysis (stage 4); SD005-SD007 on XML-parsed native
  configs, non-release manifests (src/debug etc.) are skipped (stage 5);
  SARIF + Markdown reporters, --format flag, SD008, vulnerable demo in
  example/vulnerable_app (stage 6).
- Next: stage 7 — release 0.1.0: needs RELEASE_PLEASE_TOKEN secret and
  the first manual `dart pub publish`, then flip pub.dev to automated
  publishing.
- Pending manual steps: RELEASE_PLEASE_TOKEN secret (fine-grained PAT,
  Contents+PR read/write on this repo); first manual `dart pub publish`,
  then enable trusted publishing and disable manual publishing on pub.dev.
