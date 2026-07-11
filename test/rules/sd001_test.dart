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
    expect(messages, contains('private key'));
    expect(messages, contains("'dbPassword'"));
    expect(messages, contains("'apiKey'"));
    expect(findings.every((f) => f.line != null), isTrue);
  });

  test('phrases the message so the article is always grammatical', () {
    // 'a hardcoded ...' keeps the article on a consonant word, so
    // vowel-sound format names (AWS, OpenAI) do not read as "a AWS".
    final findings =
        checkSource(rule, "const value = 'AKIAIOSFODNN7RE4LKEY';\n");
    expect(findings.single.message, contains('a hardcoded AWS access key'));
    expect(findings.single.message, isNot(contains('a AWS')));
  });

  // These token shapes cannot live in a committed fixture — GitHub push
  // protection rejects them as real secrets — so the sources are
  // assembled at runtime instead.
  test('flags every known credential format', () {
    final hex32 = 'a1b2c3d4' * 4;
    final hex64 = hex32 + hex32;
    final cases = {
      'Stripe live key': ['sk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc'],
      'Slack token': ['xoxb', '-3336494366', '76-799261852869-clFJVVIao'],
      'GitHub token': ['ghp', '_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx'],
      'Google OAuth client secret': [
        'GOCSPX',
        '-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9s',
      ],
      'Firebase Cloud Messaging server key': [
        'AAAA',
        'a1B2c3D:APA91b',
        'F' * 64,
      ],
      'Square token': ['sq0atp', '-Ab1Cd2Ef3Gh4Ij5Kl6Mn7X'],
      'Braintree access token': [
        r'access_token$production$',
        'a1b2c3d4e5f6a7b8',
        r'$',
        hex32,
      ],
      'Slack webhook URL': [
        'https://hooks.slack.com/services/',
        'T0001/B0001/XXXXXXXXXXXXXXXXXXXXXXXX',
      ],
      'Telegram bot token': ['123456789', ':AA', 'F' * 33],
      'GitLab personal access token': ['glpat', '-Ab1Cd2Ef3Gh4Ij5Kl6Mn'],
      'npm access token': ['npm', '_', 'a1B2c3D4' * 4, 'e5F6'],
      'OpenAI API key': ['sk-', 'proj-', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8' * 2],
      'Anthropic API key': ['sk-', 'ant-', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8' * 2],
      'Twilio API key': ['SK', hex32],
      'SendGrid API key': [
        'SG',
        '.Ab1Cd2Ef3Gh4Ij5Kl6Mn7X',
        '.Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3Ab4X',
      ],
      'Mailgun API key': ['key', '-', hex32],
      'DigitalOcean token': ['dop', '_v1_', hex64],
      'Shopify token': ['shpat', '_', hex32],
      'signed JWT': [
        'eyJhbGciOiJIUzI1NiJ9',
        '.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
        '.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      ],
      'AWS access key id': ['AKIA', 'IOSFODNN7RE4LKEY'],
      'Google API key': ['AIza', 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'],
      'private key': ['-----BEGIN RSA ', 'PRIVATE KEY-----'],
    };
    cases.forEach((expected, parts) {
      // A raw string: several formats contain '$', which plain Dart
      // literals would treat as interpolation.
      final findings = checkSource(
        rule,
        "const value = r'${parts.join()}';\n",
      );
      expect(findings, hasLength(1), reason: expected);
      expect(findings.single.message, contains(expected), reason: expected);
    });
  });

  test('stays quiet on identifier-only and publishable look-alikes', () {
    // Assembled at runtime like the positive cases: GitHub push
    // protection flags even the look-alikes we deliberately ignore.
    final cases = [
      ['pk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc'], // Stripe publishable.
      ['AC', 'a1b2c3d4' * 4], // Twilio Account SID.
      ['sk-', 'short'], // Not an OpenAI key.
      ['eyJhbGciOiJIUzI1NiJ9', '.eyJzdWIiOiIxIn0'], // Unsigned JWT.
      ['key-', 'tooshort'],
    ];
    for (final parts in cases) {
      final value = parts.join();
      expect(
        checkSource(rule, "const value = r'$value';\n"),
        isEmpty,
        reason: value,
      );
    }
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
