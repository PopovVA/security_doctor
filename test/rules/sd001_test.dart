import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = HardcodedSecretsRule();

  test('metadata', () {
    expect(rule.id, 'SD001');
    expect(rule.severity, Severity.critical);
    expect(rule.masvs, 'MASVS-STORAGE-1');
    expect(rule.cwe, 798);
  });

  test('flags known credential formats and high-entropy secrets', () {
    final findings = checkFixture(rule, 'sd001/vulnerable.dart');

    // 3 known-format literals + 2 secret-named high-entropy variables.
    expect(findings, hasLength(5));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains('AWS access key id'));
    expect(messages, contains('Google API key'));
    expect(messages, contains('private key material'));
    expect(messages, contains("'dbPassword'"));
    expect(messages, contains("'apiKey'"));
    expect(findings.every((f) => f.line != null), isTrue);
  });

  // These token shapes cannot live in a committed fixture — GitHub push
  // protection rejects them as real secrets — so the sources are
  // assembled at runtime instead.
  test('flags Stripe, Slack and GitHub token formats', () {
    const cases = {
      'Stripe live key': ['sk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc'],
      'Slack token': ['xoxb', '-3336494366', '76-799261852869-clFJVVIao'],
      'GitHub token': ['ghp', '_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx'],
    };
    cases.forEach((expected, parts) {
      final findings = checkSource(
        rule,
        "const value = '${parts.join()}';\n",
      );
      expect(findings, hasLength(1), reason: expected);
      expect(findings.single.message, contains(expected));
    });
  });

  test('never echoes a full secret in the message', () {
    final findings = checkFixture(rule, 'sd001/vulnerable.dart');
    for (final finding in findings) {
      expect(finding.message, isNot(contains('AKIAIOSFODNN7RE4LKEY')));
      expect(finding.message, isNot(contains('q7RkX2mV9tLpZ4wY8bNcE3hJ')));
    }
  });

  test('stays quiet on placeholders, low entropy and unrelated names', () {
    expect(checkFixture(rule, 'sd001/clean.dart'), isEmpty);
  });
}
