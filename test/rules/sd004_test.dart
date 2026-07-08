import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = WeakCryptoRule();

  test('metadata', () {
    expect(rule.id, 'SD004');
    expect(rule.severity, Severity.high);
    expect(rule.masvs, 'MASVS-CRYPTO-1');
    expect(rule.cwe, 327);
  });

  test('flags md5/sha1 digests, weak Hmacs and ECB mode', () {
    final findings = checkFixture(rule, 'sd004/vulnerable.dart');

    // md5, sha1, crypto.md5, Hmac(md5), new Hmac(sha1),
    // 'AES/ECB/PKCS5Padding', ECBBlockCipher(...).
    expect(findings, hasLength(7));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains('MD5'));
    expect(messages, contains('SHA1'));
    expect(messages, contains('CRYPTO.MD5'));
    expect(messages, contains("'AES/ECB/PKCS5Padding'"));
    expect(messages, contains('ECBBlockCipher'));
  });

  test('stays quiet on sha256+, GCM and md5-ish identifiers', () {
    expect(checkFixture(rule, 'sd004/clean.dart'), isEmpty);
  });
}
