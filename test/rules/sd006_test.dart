import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _manifestPath = 'android/app/src/main/AndroidManifest.xml';

void main() {
  const rule = DebugFlagsRule();

  test('metadata', () {
    expect(rule.id, 'SD006');
    expect(rule.severity, Severity.high);
    expect(rule.masvs, 'MASVS-RESILIENCE-2');
    expect(rule.cwe, 489);
  });

  test('flags debuggable and allowBackup in the release manifest', () {
    final findings = checkTextFixture(
      rule,
      'sd006/vulnerable_manifest.xml',
      kind: FileKind.androidManifest,
      path: _manifestPath,
    );
    expect(findings, hasLength(2));
    final messages = findings.map((f) => f.message).join('\n');
    expect(messages, contains('android:debuggable'));
    expect(messages, contains('android:allowBackup'));
  });

  test('stays quiet on ="false"/absent flags and debug manifests', () {
    expect(
      checkTextFixture(
        rule,
        'sd006/clean_manifest.xml',
        kind: FileKind.androidManifest,
        path: _manifestPath,
      ),
      isEmpty,
    );
    expect(
      checkTextFixture(
        rule,
        'sd006/vulnerable_manifest.xml',
        kind: FileKind.androidManifest,
        path: 'android/app/src/debug/AndroidManifest.xml',
      ),
      isEmpty,
    );
  });
}
