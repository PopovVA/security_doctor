import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _manifestPath = 'android/app/src/main/AndroidManifest.xml';

void main() {
  const rule = DangerousPermissionsRule();

  test('metadata', () {
    expect(rule.id, 'SD007');
    expect(rule.severity, Severity.low);
    expect(rule.masvs, 'MASVS-PLATFORM-1');
    expect(rule.cwe, 250);
  });

  test('flags dangerous permissions from both uses-permission tags', () {
    final findings = checkTextFixture(
      rule,
      'sd007/vulnerable_manifest.xml',
      kind: FileKind.androidManifest,
      path: _manifestPath,
    );
    expect(findings, hasLength(3));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains("'CAMERA'"));
    expect(messages, contains("'READ_SMS'"));
    expect(messages, contains("'ACCESS_FINE_LOCATION'"));
  });

  test('stays quiet on normal, notification and custom permissions', () {
    expect(
      checkTextFixture(
        rule,
        'sd007/clean_manifest.xml',
        kind: FileKind.androidManifest,
        path: _manifestPath,
      ),
      isEmpty,
    );
  });
}
