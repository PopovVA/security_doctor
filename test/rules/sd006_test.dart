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

  test('reports the active flag, not a commented-out copy above it', () {
    final file = ScanFile(
      path: _manifestPath,
      content: '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- android:debuggable="true" was only ever meant for local builds -->
  <application android:debuggable="true"/>
</manifest>
''',
      kind: FileKind.androidManifest,
    );

    final findings = rule.check(file);

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
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
