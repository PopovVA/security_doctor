import 'dart:io';

import 'config.dart';
import 'rule.dart';
import 'scan_file.dart';

/// The outcome of one audit run.
class AuditReport {
  AuditReport({
    required this.findings,
    required this.scannedFileCount,
    required this.failOn,
  });

  /// All findings, sorted by path, then line. Includes findings below the
  /// [failOn] threshold — those are reported but do not fail the run.
  final List<Finding> findings;

  final int scannedFileCount;

  final Severity failOn;

  /// Findings that gate the exit code.
  List<Finding> get failing =>
      findings.where((f) => f.severity.atLeast(failOn)).toList();

  bool get fails => findings.any((f) => f.severity.atLeast(failOn));
}

/// Runs the enabled rules over a project directory.
class SecurityAuditor {
  SecurityAuditor({required this.rules, AuditConfig? config})
      : config = config ?? AuditConfig();

  final List<Rule> rules;
  final AuditConfig config;

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
    final active = rules.where((r) => config.ruleEnabled(r.id));
    final textRules = active.whereType<TextRule>().toList();
    // Rules needing the Dart AST get their own subtype; the analyzer pass
    // is wired up only when such a rule is active, per the invariants.

    final findings = <Finding>[];
    var scanned = 0;
    for (final file in _discover(root)) {
      scanned++;
      for (final rule in textRules) {
        if (rule.appliesTo(file)) findings.addAll(rule.check(file));
      }
    }

    findings.sort((a, b) {
      final byPath = a.path.compareTo(b.path);
      if (byPath != 0) return byPath;
      final byLine = (a.line ?? 0).compareTo(b.line ?? 0);
      if (byLine != 0) return byLine;
      return a.rule.id.compareTo(b.rule.id);
    });

    return AuditReport(
      findings: findings,
      scannedFileCount: scanned,
      failOn: config.failOn,
    );
  }

  Iterable<ScanFile> _discover(Directory root) sync* {
    final rootPath = root.path;
    final entries = root
        .listSync(recursive: true, followLinks: false)
        .whereType<File>()
        .toList()
      ..sort((a, b) => a.path.compareTo(b.path));

    for (final file in entries) {
      final relative = _relativePath(file.path, rootPath);
      if (relative.split('/').any(_skippedDirs.contains)) continue;
      final kind = ScanFile.classify(relative);
      if (kind == null) continue;
      if (config.excludes(relative)) continue;
      final String content;
      try {
        content = file.readAsStringSync();
      } on FileSystemException {
        continue; // Unreadable or non-UTF8 file: nothing a text rule can do.
      }
      yield ScanFile(path: relative, content: content, kind: kind);
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
