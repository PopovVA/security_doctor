import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _manifestPath = 'android/app/src/main/AndroidManifest.xml';

void main() {
  const rule = CleartextConfigRule();

  test('metadata', () {
    expect(rule.id, 'SD005');
    expect(rule.severity, Severity.high);
    expect(rule.masvs, 'MASVS-NETWORK-1');
    expect(rule.cwe, 319);
  });

  test('flags usesCleartextTraffic="true" in the release manifest', () {
    final findings = checkTextFixture(
      rule,
      'sd005/vulnerable_manifest.xml',
      kind: FileKind.androidManifest,
      path: _manifestPath,
    );
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('usesCleartextTraffic'));
    expect(findings.single.line, isNotNull);
  });

  test('stays quiet on ="false" and on debug-source-set manifests', () {
    expect(
      checkTextFixture(
        rule,
        'sd005/clean_manifest.xml',
        kind: FileKind.androidManifest,
        path: _manifestPath,
      ),
      isEmpty,
    );
    expect(
      checkTextFixture(
        rule,
        'sd005/vulnerable_manifest.xml',
        kind: FileKind.androidManifest,
        path: 'android/app/src/debug/AndroidManifest.xml',
      ),
      isEmpty,
    );
  });

  test('flags NSAllowsArbitraryLoads in Info.plist', () {
    final findings = checkTextFixture(
      rule,
      'sd005/vulnerable_info.plist',
      kind: FileKind.infoPlist,
      path: 'ios/Runner/Info.plist',
    );
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('App Transport Security'));
  });

  test('reports the active key, not a commented-out copy above it', () {
    final file = ScanFile(
      path: 'ios/Runner/Info.plist',
      content: '''
<plist version="1.0"><dict>
  <!-- <key>NSAllowsArbitraryLoads</key><true/> -->
  <key>NSAllowsArbitraryLoads</key><true/>
</dict></plist>
''',
      kind: FileKind.infoPlist,
    );

    final findings = rule.check(file);

    expect(findings, hasLength(1));
    expect(findings.single.line, 3);
  });

  test('stays quiet when NSAllowsArbitraryLoads is false', () {
    expect(
      checkTextFixture(
        rule,
        'sd005/clean_info.plist',
        kind: FileKind.infoPlist,
        path: 'ios/Runner/Info.plist',
      ),
      isEmpty,
    );
  });

  test('stays quiet on unparseable XML', () {
    final file = ScanFile(
      path: _manifestPath,
      content: '<manifest><application',
      kind: FileKind.androidManifest,
    );
    expect(rule.check(file), isEmpty);
  });
}
