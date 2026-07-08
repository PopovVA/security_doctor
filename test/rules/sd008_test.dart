import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = SensitiveLoggingRule();

  test('metadata', () {
    expect(rule.id, 'SD008');
    expect(rule.severity, Severity.medium);
    expect(rule.masvs, 'MASVS-STORAGE-2');
    expect(rule.cwe, 532);
  });

  test('flags print/debugPrint/log calls referencing sensitive names', () {
    final findings = checkFixture(rule, 'sd008/vulnerable.dart');
    expect(findings, hasLength(4));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains("'password'"));
    expect(messages, contains("'authToken'"));
    expect(messages, contains("'apiKey'"));
  });

  test('stays quiet on harmless names and non-logging uses', () {
    expect(checkFixture(rule, 'sd008/clean.dart'), isEmpty);
  });
}
