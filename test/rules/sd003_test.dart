import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = SharedPreferencesRule();

  test('metadata', () {
    expect(rule.id, 'SD003');
    expect(rule.severity, Severity.high);
    expect(rule.masvs, 'MASVS-STORAGE-1');
    expect(rule.cwe, 922);
  });

  test('flags sensitive keys written to a preferences object', () {
    final findings = checkFixture(rule, 'sd003/vulnerable.dart');
    expect(findings, hasLength(5));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains("'authToken'"));
    expect(messages, contains("'user_password'"));
    expect(messages, contains("'session_tokens'"));
    expect(messages, contains("'apiKey'"));
    expect(messages, contains("'card_pin'"));
  });

  test('stays quiet on harmless keys, other receivers and dynamic keys', () {
    expect(checkFixture(rule, 'sd003/clean.dart'), isEmpty);
  });

  group('splitIdentifierWords', () {
    test('splits camelCase, snake_case and kebab-case', () {
      expect(splitIdentifierWords('authToken'), ['auth', 'token']);
      expect(splitIdentifierWords('user_password'), ['user', 'password']);
      expect(splitIdentifierWords('card-pin'), ['card', 'pin']);
      expect(splitIdentifierWords('authorName'), ['author', 'name']);
    });
  });
}
