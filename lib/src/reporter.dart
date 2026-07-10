import 'dart:convert';

import 'engine.dart';
import 'rule.dart';

/// Turns an [AuditReport] into one of the output formats.
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
    final suppressed = report.baselineSuppressedCount;
    if (suppressed > 0) {
      buffer.write(
        ' $suppressed baselined finding${suppressed == 1 ? '' : 's'} '
        'hidden.',
      );
    }
    if (report.ignoredCount > 0) {
      buffer.write(
        ' ${report.ignoredCount} ignored by inline comment'
        '${report.ignoredCount == 1 ? '' : 's'}.',
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
          if (f.fingerprint != null) 'fingerprint': f.fingerprint,
        };

    return const JsonEncoder.withIndent('  ').convert({
      'version': 1,
      'scannedFiles': report.scannedFileCount,
      'failOn': report.failOn.name,
      'baselineSuppressed': report.baselineSuppressedCount,
      'ignored': report.ignoredCount,
      'findings': report.findings.map(encodeFinding).toList(),
    });
  }
}

/// SARIF 2.1.0 output for GitHub Code Scanning and similar tools.
class SarifReporter implements Reporter {
  const SarifReporter();

  /// GitHub renders `note`/`warning`/`error`; `security-severity` (a
  /// CVSS-like 0-10 score) drives its severity buckets.
  static String _level(Severity severity) => switch (severity) {
        Severity.low => 'note',
        Severity.medium => 'warning',
        Severity.high || Severity.critical => 'error',
      };

  static String _securitySeverity(Severity severity) => switch (severity) {
        Severity.low => '3.0',
        Severity.medium => '5.5',
        Severity.high => '8.0',
        Severity.critical => '9.5',
      };

  @override
  String format(AuditReport report) {
    final rules = <String, Rule>{
      for (final finding in report.findings) finding.rule.id: finding.rule,
    };
    final ruleIds = rules.keys.toList()..sort();

    Map<String, Object?> encodeRule(Rule rule) => {
          'id': rule.id,
          'name': rule.title,
          'shortDescription': {'text': rule.title},
          'fullDescription': {'text': rule.description},
          'defaultConfiguration': {'level': _level(rule.severity)},
          'properties': {
            'tags': [
              'security',
              'external/cwe/cwe-${rule.cwe}',
              rule.masvs,
            ],
            'security-severity': _securitySeverity(rule.severity),
          },
        };

    Map<String, Object?> encodeResult(Finding finding) => {
          'ruleId': finding.rule.id,
          'ruleIndex': ruleIds.indexOf(finding.rule.id),
          'level': _level(finding.severity),
          'message': {'text': finding.message},
          'locations': [
            {
              'physicalLocation': {
                'artifactLocation': {
                  'uri': finding.path,
                  'uriBaseId': '%SRCROOT%',
                },
                if (finding.line != null)
                  'region': {
                    'startLine': finding.line,
                    if (finding.column != null) 'startColumn': finding.column,
                  },
              },
            },
          ],
        };

    return const JsonEncoder.withIndent('  ').convert({
      '\$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
      'version': '2.1.0',
      'runs': [
        {
          'tool': {
            'driver': {
              'name': 'security_doctor',
              'informationUri': 'https://github.com/PopovVA/security_doctor',
              'rules': [for (final id in ruleIds) encodeRule(rules[id]!)],
            },
          },
          'results': report.findings.map(encodeResult).toList(),
        },
      ],
    });
  }
}

/// Markdown output for PR comments and job summaries.
class MarkdownReporter implements Reporter {
  const MarkdownReporter();

  @override
  String format(AuditReport report) {
    final buffer = StringBuffer('# security_doctor report\n\n');

    final suppressed = report.baselineSuppressedCount;
    final baselineNote = suppressed > 0
        ? ' $suppressed baselined finding${suppressed == 1 ? '' : 's'} '
            'hidden.'
        : '';
    final files = '${report.scannedFileCount} '
        'file${report.scannedFileCount == 1 ? '' : 's'} scanned';
    if (report.findings.isEmpty) {
      buffer.write('No security findings ($files).$baselineNote\n');
      return buffer.toString();
    }

    final total = report.findings.length;
    buffer
      ..writeln(
        '**$total finding${total == 1 ? '' : 's'}**, '
        '${report.failing.length} at or above `${report.failOn.name}` '
        '($files).$baselineNote',
      )
      ..writeln()
      ..writeln('| Severity | Rule | Location | Finding | MASVS | CWE |')
      ..writeln('| --- | --- | --- | --- | --- | --- |');
    for (final f in report.findings) {
      final location = f.line == null ? f.path : '${f.path}:${f.line}';
      buffer.writeln(
        '| ${f.severity.name} '
        '| ${f.rule.id} '
        '| `${_escape(location)}` '
        '| ${_escape(f.message)} '
        '| ${f.rule.masvs} '
        '| CWE-${f.rule.cwe} |',
      );
    }
    return buffer.toString();
  }

  static String _escape(String cell) =>
      cell.replaceAll('|', r'\|').replaceAll('\n', ' ');
}
