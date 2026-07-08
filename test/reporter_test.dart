import 'dart:convert';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'support.dart';

AuditReport _report({List<Finding>? findings, Severity failOn = Severity.low}) {
  return AuditReport(
    findings: findings ?? [],
    scannedFileCount: 2,
    failOn: failOn,
  );
}

Finding _finding({Severity severity = Severity.high}) {
  final rule = MarkerRule(id: 'SD999', severity: severity);
  return Finding(
    rule: rule,
    path: 'lib/a.dart',
    message: "Found 'MARKER'.",
    line: 3,
    column: 7,
  );
}

void main() {
  group('ConsoleReporter', () {
    test('reports a clean run', () {
      final output = const ConsoleReporter().format(_report());
      expect(output, 'No security findings (2 files scanned).');
    });

    test('lists findings with location, ids and MASVS/CWE mapping', () {
      final output =
          const ConsoleReporter().format(_report(findings: [_finding()]));
      expect(output, contains('lib/a.dart:3:7 [SD999 high] Marker found'));
      expect(output, contains("Found 'MARKER'."));
      expect(output, contains('MASVS-TEST-1, CWE-0'));
      expect(output, contains("1 finding, 1 at or above 'low'"));
    });

    test('counts findings below the threshold separately', () {
      final output = const ConsoleReporter().format(
        _report(
          findings: [_finding(severity: Severity.low)],
          failOn: Severity.high,
        ),
      );
      expect(output, contains("1 finding, 0 at or above 'high'"));
    });

    test('omits the location suffix when a finding has no line', () {
      final finding = Finding(
        rule: const MarkerRule(),
        path: 'pubspec.yaml',
        message: 'File-level finding.',
      );
      final output =
          const ConsoleReporter().format(_report(findings: [finding]));
      expect(output, contains('pubspec.yaml [SD999 high]'));
    });
  });

  group('JsonReporter', () {
    test('emits the documented shape', () {
      final output =
          const JsonReporter().format(_report(findings: [_finding()]));
      final decoded = jsonDecode(output) as Map<String, dynamic>;

      expect(decoded['version'], 1);
      expect(decoded['scannedFiles'], 2);
      expect(decoded['failOn'], 'low');

      final findings = decoded['findings'] as List<dynamic>;
      expect(findings, hasLength(1));
      expect(findings.first, {
        'rule': 'SD999',
        'severity': 'high',
        'title': 'Marker found',
        'message': "Found 'MARKER'.",
        'path': 'lib/a.dart',
        'line': 3,
        'column': 7,
        'masvs': 'MASVS-TEST-1',
        'cwe': 0,
      });
    });

    test('a clean run has an empty findings list', () {
      final decoded = jsonDecode(const JsonReporter().format(_report()))
          as Map<String, dynamic>;
      expect(decoded['findings'], isEmpty);
    });
  });
}
