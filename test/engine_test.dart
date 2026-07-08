import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Directory root;

  setUp(() {
    root = Directory.systemTemp.createTempSync('security_doctor_engine');
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  void write(String relative, String content) {
    File('${root.path}/$relative')
      ..createSync(recursive: true)
      ..writeAsStringSync(content);
  }

  test('collects findings from matching files, sorted by path and line', () {
    write('lib/b.dart', 'MARKER\n');
    write('lib/a.dart', 'clean\nMARKER MARKER\n');
    write('pubspec.yaml', 'name: app\n');

    final report = SecurityAuditor(rules: [const MarkerRule()]).audit(root);

    expect(report.findings, hasLength(3));
    expect(report.findings[0].path, 'lib/a.dart');
    expect(report.findings[0].line, 2);
    expect(report.findings[0].column, 1);
    expect(report.findings[1].column, 8);
    expect(report.findings[2].path, 'lib/b.dart');
    expect(report.scannedFileCount, 3);
    expect(report.fails, isTrue);
  });

  test('does not run rules on kinds they do not apply to', () {
    write('pubspec.yaml', 'name: app # MARKER\n');

    final report = SecurityAuditor(rules: [const MarkerRule()]).audit(root);

    expect(report.findings, isEmpty);
    expect(report.fails, isFalse);
  });

  test('skips disabled rules', () {
    write('lib/a.dart', 'MARKER\n');

    final report = SecurityAuditor(
      rules: [const MarkerRule()],
      config: AuditConfig(disabledRules: {'SD999'}),
    ).audit(root);

    expect(report.findings, isEmpty);
  });

  test('skips excluded paths', () {
    write('lib/generated/a.dart', 'MARKER\n');
    write('lib/main.dart', 'MARKER\n');

    final report = SecurityAuditor(
      rules: [const MarkerRule()],
      config: AuditConfig(exclude: const ['lib/generated/**']),
    ).audit(root);

    expect(report.findings.map((f) => f.path), ['lib/main.dart']);
  });

  test('never descends into build and tool directories', () {
    write('.dart_tool/gen/a.dart', 'MARKER\n');
    write('build/app/b.dart', 'MARKER\n');
    write('.git/hooks/c.dart', 'MARKER\n');

    final report = SecurityAuditor(rules: [const MarkerRule()]).audit(root);

    expect(report.findings, isEmpty);
    expect(report.scannedFileCount, 0);
  });

  test('dart rules run on parsed units', () {
    write('lib/api.dart', "const url = 'http://api.example.com';\n");

    final report =
        SecurityAuditor(rules: [const CleartextHttpRule()]).audit(root);

    expect(report.findings, hasLength(1));
    expect(report.findings.single.rule.id, 'SD002');
    expect(report.findings.single.line, 1);
  });

  test('files that do not parse are skipped for dart rules', () {
    write('lib/broken.dart', "const url = 'http://api.example.com'\n}{");

    final report =
        SecurityAuditor(rules: [const CleartextHttpRule()]).audit(root);

    expect(report.findings, isEmpty);
    expect(report.scannedFileCount, 1);
  });

  test('disabled dart rules do not fire', () {
    write('lib/api.dart', "const url = 'http://api.example.com';\n");

    final report = SecurityAuditor(
      rules: [const CleartextHttpRule()],
      config: AuditConfig(disabledRules: {'SD002'}),
    ).audit(root);

    expect(report.findings, isEmpty);
  });

  test('native config rules see manifests and plists end to end', () {
    write('android/app/src/main/AndroidManifest.xml', '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true" android:debuggable="true"/>
</manifest>
''');
    write('android/app/src/debug/AndroidManifest.xml', '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true"/>
</manifest>
''');
    write('ios/Runner/Info.plist', '''
<plist version="1.0"><dict>
  <key>NSAllowsArbitraryLoads</key><true/>
</dict></plist>
''');

    final report = SecurityAuditor(
      rules: [const CleartextConfigRule(), const DebugFlagsRule()],
    ).audit(root);

    // Release manifest: SD005 + SD006. Plist: SD005. Debug manifest: none.
    expect(report.findings, hasLength(3));
    expect(
      report.findings.map((f) => f.rule.id),
      containsAll(['SD005', 'SD006']),
    );
    expect(
      report.findings.map((f) => f.path),
      isNot(contains('android/app/src/debug/AndroidManifest.xml')),
    );
  });

  test('findings below the threshold are reported but do not fail', () {
    write('lib/a.dart', 'MARKER\n');

    final report = SecurityAuditor(
      rules: [const MarkerRule(severity: Severity.low)],
      config: AuditConfig(failOn: Severity.high),
    ).audit(root);

    expect(report.findings, hasLength(1));
    expect(report.failing, isEmpty);
    expect(report.fails, isFalse);
  });
}
