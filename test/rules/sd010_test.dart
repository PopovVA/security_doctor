import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = DebuggableEntitlementsRule();

  test('metadata', () {
    expect(rule.id, 'SD010');
    expect(rule.severity, Severity.high);
    expect(rule.masvs, 'MASVS-RESILIENCE-2');
    expect(rule.cwe, 489);
  });

  test('flags get-task-allow in release entitlements', () {
    final findings = checkTextFixture(
      rule,
      'sd010/vulnerable.entitlements',
      kind: FileKind.entitlements,
      path: 'ios/Runner/Runner.entitlements',
    );
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('get-task-allow'));
    expect(findings.single.line, isNotNull);
  });

  test('stays quiet when the flag is false', () {
    expect(
      checkTextFixture(
        rule,
        'sd010/clean.entitlements',
        kind: FileKind.entitlements,
        path: 'ios/Runner/Runner.entitlements',
      ),
      isEmpty,
    );
  });

  test('skips debug-profile entitlements files', () {
    expect(
      checkTextFixture(
        rule,
        'sd010/vulnerable.entitlements',
        kind: FileKind.entitlements,
        path: 'macos/Runner/DebugProfile.entitlements',
      ),
      isEmpty,
    );
  });

  test('stays quiet on unparseable XML', () {
    final file = ScanFile(
      path: 'ios/Runner/Runner.entitlements',
      content: '<plist><dict',
      kind: FileKind.entitlements,
    );
    expect(rule.check(file), isEmpty);
  });
}
