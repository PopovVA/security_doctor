import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

void main() {
  group('AuditConfig defaults', () {
    test('all rules enabled, fail_on low, nothing excluded', () {
      final config = AuditConfig();
      expect(config.ruleEnabled('SD001'), isTrue);
      expect(config.failOn, Severity.low);
      expect(config.excludes('lib/main.dart'), isFalse);
    });
  });

  group('AuditConfig.parse', () {
    test('empty document keeps defaults', () {
      final config = AuditConfig.parse('');
      expect(config.failOn, Severity.low);
      expect(config.disabledRules, isEmpty);
    });

    test('reads rule toggles, fail_on and exclude', () {
      final config = AuditConfig.parse('''
rules:
  SD002: false
  SD003: true
fail_on: high
exclude:
  - "lib/generated/**"
''');
      expect(config.ruleEnabled('SD002'), isFalse);
      expect(config.ruleEnabled('SD003'), isTrue);
      expect(config.failOn, Severity.high);
      expect(config.excludes('lib/generated/api.dart'), isTrue);
      expect(config.excludes('lib/main.dart'), isFalse);
    });

    test('rejects unknown top-level keys', () {
      expect(() => AuditConfig.parse('fail_On: high'), throwsFormatException);
    });

    test('rejects non-map top level', () {
      expect(() => AuditConfig.parse('- SD001'), throwsFormatException);
    });

    test('rejects non-boolean rule toggles', () {
      expect(
        () => AuditConfig.parse('rules:\n  SD001: off please'),
        throwsFormatException,
      );
    });

    test('rejects non-map rules section', () {
      expect(() => AuditConfig.parse('rules: SD001'), throwsFormatException);
    });

    test('rejects unknown fail_on severity', () {
      expect(
          () => AuditConfig.parse('fail_on: blocker'), throwsFormatException);
    });

    test('rejects non-string fail_on', () {
      expect(() => AuditConfig.parse('fail_on: 3'), throwsFormatException);
    });

    test('rejects non-list exclude', () {
      expect(
        () => AuditConfig.parse('exclude: lib/generated'),
        throwsFormatException,
      );
    });

    test('reads the baseline path', () {
      final config = AuditConfig.parse('baseline: known_findings.json\n');
      expect(config.baselinePath, 'known_findings.json');
      expect(AuditConfig.parse('').baselinePath, isNull);
    });

    test('rejects a non-string baseline', () {
      expect(() => AuditConfig.parse('baseline: 3'), throwsFormatException);
    });

    test('rejects non-string exclude entries', () {
      expect(() => AuditConfig.parse('exclude:\n  - 3'), throwsFormatException);
    });
  });

  group('AuditConfig.load', () {
    late Directory root;

    setUp(() {
      root = Directory.systemTemp.createTempSync('security_doctor_config');
    });

    tearDown(() {
      root.deleteSync(recursive: true);
    });

    test('missing file means defaults', () {
      expect(AuditConfig.load(root).failOn, Severity.low);
    });

    test('reads security_audit.yaml from the root', () {
      File('${root.path}/security_audit.yaml')
          .writeAsStringSync('fail_on: critical\n');
      expect(AuditConfig.load(root).failOn, Severity.critical);
    });
  });

  group('AuditConfig.copyWith', () {
    test('overrides fail_on and keeps the rest', () {
      final config = AuditConfig.parse('''
rules:
  SD001: false
exclude:
  - "test/**"
''');
      final overridden = config.copyWith(failOn: Severity.critical);
      expect(overridden.failOn, Severity.critical);
      expect(overridden.ruleEnabled('SD001'), isFalse);
      expect(overridden.excludes('test/a_test.dart'), isTrue);
    });
  });
}
