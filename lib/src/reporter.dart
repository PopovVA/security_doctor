import 'dart:convert';

import 'engine.dart';
import 'rule.dart';

/// Turns an [AuditReport] into one of the output formats. Markdown and
/// SARIF land in later milestones on the same interface.
abstract class Reporter {
  String format(AuditReport report);
}

/// Human-readable output for terminals.
class ConsoleReporter implements Reporter {
  const ConsoleReporter();

  @override
  String format(AuditReport report) {
    final buffer = StringBuffer();
    for (final f in report.findings) {
      final location = [
        f.path,
        if (f.line != null) f.line,
        if (f.line != null && f.column != null) f.column,
      ].join(':');
      buffer
        ..writeln('$location [${f.rule.id} ${f.severity.name}] '
            '${f.rule.title}')
        ..writeln('  ${f.message}')
        ..writeln('  ${f.rule.masvs}, CWE-${f.rule.cwe}');
    }
    if (buffer.isNotEmpty) buffer.writeln();

    final files = '${report.scannedFileCount} '
        'file${report.scannedFileCount == 1 ? '' : 's'} scanned';
    if (report.findings.isEmpty) {
      buffer.write('No security findings ($files).');
    } else {
      final total = report.findings.length;
      final failing = report.failing.length;
      buffer.write(
        '$total finding${total == 1 ? '' : 's'}, $failing at or above '
        "'${report.failOn.name}' ($files).",
      );
    }
    return buffer.toString();
  }
}

/// Machine-readable output for CI and tooling.
class JsonReporter implements Reporter {
  const JsonReporter();

  @override
  String format(AuditReport report) {
    Map<String, Object?> encodeFinding(Finding f) => {
          'rule': f.rule.id,
          'severity': f.severity.name,
          'title': f.rule.title,
          'message': f.message,
          'path': f.path,
          'line': f.line,
          'column': f.column,
          'masvs': f.rule.masvs,
          'cwe': f.rule.cwe,
        };

    return const JsonEncoder.withIndent('  ').convert({
      'version': 1,
      'scannedFiles': report.scannedFileCount,
      'failOn': report.failOn.name,
      'findings': report.findings.map(encodeFinding).toList(),
    });
  }
}
