import 'dart:convert';
import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:crypto/crypto.dart';

import 'baseline.dart';
import 'config.dart';
import 'rule.dart';
import 'scan_file.dart';

/// The outcome of one audit run.
class AuditReport {
  AuditReport({
    required this.findings,
    required this.scannedFileCount,
    required this.failOn,
    this.baselineSuppressedCount = 0,
    this.ignoredCount = 0,
  });

  /// All findings, sorted by path, then line. Includes findings below the
  /// [failOn] threshold — those are reported but do not fail the run.
  final List<Finding> findings;

  final int scannedFileCount;

  final Severity failOn;

  /// Findings hidden because they match the committed baseline.
  final int baselineSuppressedCount;

  /// Findings silenced by an inline `security_doctor: ignore SD###`
  /// comment.
  final int ignoredCount;

  /// Findings that gate the exit code.
  List<Finding> get failing =>
      findings.where((f) => f.severity.atLeast(failOn)).toList();

  bool get fails => findings.any((f) => f.severity.atLeast(failOn));
}

/// Runs the enabled rules over a project directory.
class SecurityAuditor {
  SecurityAuditor({required this.rules, AuditConfig? config, this.baseline})
      : config = config ?? AuditConfig();

  final List<Rule> rules;
  final AuditConfig config;

  /// Known findings to suppress; see [Baseline].
  final Baseline? baseline;

  /// Directories never worth descending into.
  static const _skippedDirs = {
    '.git',
    '.dart_tool',
    '.idea',
    '.fvm',
    'build',
    'Pods',
    '.symlinks',
    'node_modules',
  };

  AuditReport audit(Directory root) {
    final active = rules.where((r) => config.ruleEnabled(r.id)).toList();
    final textRules = active.whereType<TextRule>().toList();
    final dartRules = active.whereType<DartRule>().toList();

    final findings = <Finding>[];
    var scanned = 0;
    var ignored = 0;
    for (final file in _discover(root)) {
      scanned++;
      final fileFindings = <Finding>[];
      for (final rule in textRules) {
        if (rule.appliesTo(file)) fileFindings.addAll(rule.check(file));
      }
      // The AST pass only runs when a rule actually needs it.
      if (dartRules.isNotEmpty && file.kind == FileKind.dart) {
        final result = parseString(
          content: file.content,
          path: file.path,
          throwIfDiagnostics: false,
        );
        // A file that does not parse yields unreliable ASTs; stay quiet
        // rather than risk false positives.
        if (result.errors.isEmpty) {
          for (final rule in dartRules) {
            fileFindings.addAll(rule.check(file, result.unit));
          }
        }
      }
      final before = fileFindings.length;
      fileFindings.removeWhere((f) => _isIgnored(f, file));
      ignored += before - fileFindings.length;
      for (final finding in fileFindings) {
        finding.fingerprint = _fingerprint(finding, file);
      }
      findings.addAll(fileFindings);
    }

    findings.sort((a, b) {
      final byPath = a.path.compareTo(b.path);
      if (byPath != 0) return byPath;
      final byLine = (a.line ?? 0).compareTo(b.line ?? 0);
      if (byLine != 0) return byLine;
      return a.rule.id.compareTo(b.rule.id);
    });

    var kept = findings;
    var suppressed = 0;
    if (baseline != null) {
      (kept, suppressed) = baseline!.apply(findings);
    }

    return AuditReport(
      findings: kept,
      scannedFileCount: scanned,
      failOn: config.failOn,
      baselineSuppressedCount: suppressed,
      ignoredCount: ignored,
    );
  }

  static final _ignorePattern =
      RegExp(r'security_doctor:\s*ignore\s+(SD\d+(?:\s*,\s*SD\d+)*)');

  /// Whitespace and comment punctuation — all that may precede a
  /// directive on a standalone comment line.
  static final _commentPrefix = RegExp(r'^[\s/#<!*-]*$');

  /// An inline `security_doctor: ignore SD###[, SD###]` on the finding's
  /// line or on a standalone comment line directly above silences it.
  /// Works in any file type — the marker is matched inside whatever
  /// comment syntax the file uses. A trailing comment only applies to
  /// its own line, so it cannot accidentally cover the line below.
  static bool _isIgnored(Finding finding, ScanFile file) {
    final line = finding.line;
    if (line == null) return false;
    bool matches(String text, {required bool standaloneOnly}) {
      final match = _ignorePattern.firstMatch(text);
      if (match == null) return false;
      if (standaloneOnly &&
          !_commentPrefix.hasMatch(text.substring(0, match.start))) {
        return false;
      }
      return match
          .group(1)!
          .split(',')
          .map((id) => id.trim())
          .contains(finding.rule.id);
    }

    return matches(file.lineText(line), standaloneOnly: false) ||
        (line > 1 && matches(file.lineText(line - 1), standaloneOnly: true));
  }

  /// Line numbers shift on every edit above a finding, so the baseline
  /// identity hashes the normalized line content instead.
  static String _fingerprint(Finding finding, ScanFile file) {
    final line = finding.line == null ? '' : file.lineText(finding.line!);
    final normalized = line.trim().replaceAll(RegExp(r'\s+'), ' ');
    final material = '${finding.rule.id}\n${finding.path}\n$normalized';
    return sha256.convert(utf8.encode(material)).toString();
  }

  Iterable<ScanFile> _discover(Directory root) sync* {
    yield* _discoverDirectory(root, root.path);
  }

  /// Walks one directory level at a time so ignored directories are
  /// skipped before descending — a flat `listSync(recursive: true)`
  /// would walk all of `.git`, `build` or `node_modules` only to have
  /// every entry filtered out afterwards. Per-level sorting keeps
  /// discovery deterministic; findings are re-sorted globally in
  /// [audit] regardless.
  Iterable<ScanFile> _discoverDirectory(
    Directory dir,
    String rootPath,
  ) sync* {
    final entries = dir.listSync(followLinks: false)
      ..sort((a, b) => a.path.compareTo(b.path));

    for (final entry in entries) {
      final relative = _relativePath(entry.path, rootPath);
      if (entry is Directory) {
        if (_skippedDirs.contains(relative.split('/').last)) continue;
        yield* _discoverDirectory(entry, rootPath);
      } else if (entry is File) {
        final kind = ScanFile.classify(relative);
        if (kind == null) continue;
        if (config.excludes(relative)) continue;
        final String content;
        try {
          content = entry.readAsStringSync();
        } on FileSystemException {
          continue; // Unreadable or non-UTF8 file: nothing a text rule can do.
        }
        yield ScanFile(path: relative, content: content, kind: kind);
      }
    }
  }

  static String _relativePath(String path, String rootPath) {
    var relative = path;
    if (relative.startsWith(rootPath)) {
      relative = relative.substring(rootPath.length);
    }
    relative = relative.replaceAll('\\', '/');
    while (relative.startsWith('/')) {
      relative = relative.substring(1);
    }
    return relative;
  }
}
