import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

void main() {
  group('mapping tables', () {
    test('every built-in rule maps to every standard', () {
      for (final standard in ComplianceStandard.values) {
        final mapping = ruleMappings[standard]!;
        for (final rule in builtInRules) {
          expect(
            mapping[rule.id],
            isNotNull,
            reason: '${rule.id} has no ${standard.displayName} mapping',
          );
          expect(mapping[rule.id], isNotEmpty);
        }
      }
    });

    test('every referenced requirement has a title', () {
      for (final standard in ComplianceStandard.values) {
        final titles = requirementTitles[standard]!;
        for (final requirements in ruleMappings[standard]!.values) {
          for (final id in requirements) {
            expect(
              titles[id],
              isNotNull,
              reason: '$id of ${standard.displayName} has no title',
            );
          }
        }
      }
    });

    test('parse resolves cli names and rejects unknown ones', () {
      expect(ComplianceStandard.parse('pci-dss'), ComplianceStandard.pciDss);
      expect(
        ComplianceStandard.parse('iso-27001'),
        ComplianceStandard.iso27001,
      );
      expect(() => ComplianceStandard.parse('soc2'), throwsFormatException);
    });
  });

  group('ComplianceReporter', () {
    AuditReport report(List<Finding> findings) => AuditReport(
          findings: findings,
          scannedFileCount: 3,
          failOn: Severity.low,
        );

    Finding finding(Rule rule) => Finding(
          rule: rule,
          path: 'lib/a.dart',
          message: 'Example finding.',
          line: 4,
        );

    test('groups findings under the mapped requirement', () {
      final output = const ComplianceReporter(ComplianceStandard.pciDss)
          .format(report([finding(const CleartextHttpRule())]));

      expect(output, contains('PCI DSS v4.0'));
      expect(output, contains('not a compliance verdict'));
      expect(
        output,
        contains('Requirement 4.2.1 — Strong cryptography protects data '
            'in transit (1 finding)'),
      );
      expect(output, contains('lib/a.dart:4 [SD002 medium]'));
      // Untouched requirements are listed as clean.
      expect(output, contains('8.6.2'));
      expect(output, contains('(no findings)'));
    });

    test('one finding can appear under several requirements', () {
      final output = const ComplianceReporter(ComplianceStandard.pciDss)
          .format(report([finding(const WeakCryptoRule())]));
      expect(output, contains('3.5.1'));
      expect(output, contains('4.2.1'));
      expect(
        'Requirement'.allMatches(output).length,
        greaterThanOrEqualTo(6),
      );
    });

    test('markdown flavor renders headings and bullets', () {
      final output = const ComplianceReporter(
        ComplianceStandard.iso27001,
        markdown: true,
      ).format(report([finding(const SensitiveLoggingRule())]));

      expect(output, contains('# security_doctor — ISO/IEC 27001:2022'));
      expect(output, contains('## Control A.8.15 — Logging (1 finding)'));
      expect(output, contains('- `lib/a.dart:4` [SD008 medium]'));
    });

    test('rules outside the table land in the unmapped section', () {
      final unmappedRule = _UnmappedRule();
      final output = const ComplianceReporter(ComplianceStandard.pciDss)
          .format(report([finding(unmappedRule)]));
      expect(output, contains('Not mapped to PCI DSS v4.0'));
      expect(output, contains('[SD999]'));
    });
  });

  group('CLI --compliance', () {
    late Directory root;

    setUp(() {
      root = Directory.systemTemp.createTempSync('security_doctor_comp');
      File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    });

    tearDown(() {
      root.deleteSync(recursive: true);
    });

    test('works with console and markdown, exit code unchanged', () async {
      Directory('${root.path}/lib').createSync();
      File('${root.path}/lib/main.dart')
          .writeAsStringSync("const url = 'http://api.example.com';\n");
      expect(
        await run(['--path', root.path, '--compliance', 'pci-dss']),
        1,
      );
      expect(
        await run([
          '--path',
          root.path,
          '--compliance',
          'iso-27001',
          '--format',
          'markdown',
        ]),
        1,
      );
    });

    test('rejects json/sarif formats and unknown standards', () async {
      expect(
        await run([
          '--path',
          root.path,
          '--compliance',
          'pci-dss',
          '--format',
          'sarif',
        ]),
        2,
      );
      expect(
        await run(['--path', root.path, '--compliance', 'soc2']),
        2,
      );
    });
  });
}

class _UnmappedRule extends TextRule {
  @override
  String get id => 'SD999';

  @override
  String get title => 'Unmapped';

  @override
  String get description => 'Not in any compliance table.';

  @override
  Severity get severity => Severity.low;

  @override
  String get masvs => 'MASVS-TEST-1';

  @override
  int get cwe => 0;

  @override
  bool appliesTo(ScanFile file) => false;

  @override
  List<Finding> check(ScanFile file) => const [];
}
