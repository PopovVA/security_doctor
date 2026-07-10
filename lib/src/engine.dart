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
  });

  /// All findings, sorted by path, then line. Includes findings below the
  /// [failOn] threshold — those are reported but do not fail the run.
  final List<Finding> findings;

  final int scannedFileCount;

  final Severity failOn;

  /// Findings hidden because they match the committed baseline.
  final int baselineSuppressedCount;

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
    );
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
