import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

void main() {
  const rule = CleartextHttpRule();

  test('metadata', () {
    expect(rule.id, 'SD002');
    expect(rule.severity, Severity.medium);
    expect(rule.masvs, 'MASVS-NETWORK-1');
    expect(rule.cwe, 319);
  });

  test('flags cleartext URLs, including ports and uppercase schemes', () {
    final findings = checkFixture(rule, 'sd002/vulnerable.dart');
    // 3 plain literals + adjacent strings + '+' concat + interpolation.
    expect(findings, hasLength(6));
    expect(
      findings.map((f) => f.message),
      everyElement(contains('https://')),
    );
    // Partial values are marked as such in the message.
    expect(
      findings.map((f) => f.message),
      contains(contains("'http://api.…'")),
    );
  });

  test(
      'stays quiet on https, local hosts, namespaces, prose and '
      'runtime-computed hosts', () {
    expect(checkFixture(rule, 'sd002/clean.dart'), isEmpty);
  });
}
