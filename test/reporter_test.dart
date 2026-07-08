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

  group('SarifReporter', () {
    test('emits valid SARIF 2.1.0 with rules, levels and locations', () {
      final output =
          const SarifReporter().format(_report(findings: [_finding()]));
      final decoded = jsonDecode(output) as Map<String, dynamic>;

      expect(decoded['version'], '2.1.0');
      final run = (decoded['runs'] as List).single as Map<String, dynamic>;
      final driver = (run['tool'] as Map<String, dynamic>)['driver']
          as Map<String, dynamic>;
      expect(driver['name'], 'security_doctor');

      final sarifRule =
          (driver['rules'] as List).single as Map<String, dynamic>;
      expect(sarifRule['id'], 'SD999');
      final properties = sarifRule['properties'] as Map<String, dynamic>;
      expect(properties['tags'], contains('external/cwe/cwe-0'));
      expect(properties['tags'], contains('MASVS-TEST-1'));
      expect(properties['security-severity'], '8.0');

      final result = (run['results'] as List).single as Map<String, dynamic>;
      expect(result['ruleId'], 'SD999');
      expect(result['ruleIndex'], 0);
      expect(result['level'], 'error');
      final location = ((result['locations'] as List).single
          as Map<String, dynamic>)['physicalLocation'] as Map<String, dynamic>;
      expect(
        (location['artifactLocation'] as Map<String, dynamic>)['uri'],
        'lib/a.dart',
      );
      expect((location['region'] as Map<String, dynamic>)['startLine'], 3);
    });

    test('maps severities to SARIF levels', () {
      String levelFor(Severity severity) {
        final output = const SarifReporter()
            .format(_report(findings: [_finding(severity: severity)]));
        final decoded = jsonDecode(output) as Map<String, dynamic>;
        final result = (((decoded['runs'] as List).single
                as Map<String, dynamic>)['results'] as List)
            .single as Map<String, dynamic>;
        return result['level'] as String;
      }

      expect(levelFor(Severity.low), 'note');
      expect(levelFor(Severity.medium), 'warning');
      expect(levelFor(Severity.high), 'error');
      expect(levelFor(Severity.critical), 'error');
    });

    test('omits the region when a finding has no line', () {
      final finding = Finding(
        rule: const MarkerRule(),
        path: 'pubspec.yaml',
        message: 'File-level finding.',
      );
      final output = const SarifReporter().format(_report(findings: [finding]));
      expect(output, isNot(contains('startLine')));
    });
  });

  group('MarkdownReporter', () {
    test('reports a clean run', () {
      final output = const MarkdownReporter().format(_report());
      expect(output, contains('No security findings (2 files scanned).'));
    });

    test('renders a findings table with escaped cells', () {
      final finding = Finding(
        rule: const MarkerRule(),
        path: 'lib/a.dart',
        message: 'contains | a pipe',
        line: 3,
      );
      final output =
          const MarkdownReporter().format(_report(findings: [finding]));
      expect(output, contains('| Severity | Rule | Location |'));
      expect(output, contains('`lib/a.dart:3`'));
      expect(output, contains(r'contains \| a pipe'));
      expect(output, contains('MASVS-TEST-1'));
      expect(output, contains('CWE-0'));
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
