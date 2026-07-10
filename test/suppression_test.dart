import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Directory root;

  setUp(() {
    root = Directory.systemTemp.createTempSync('security_doctor_ignore');
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  void write(String relative, String content) {
    File('${root.path}/$relative')
      ..createSync(recursive: true)
      ..writeAsStringSync(content);
  }

  AuditReport audit({List<Rule>? rules}) =>
      SecurityAuditor(rules: rules ?? [const MarkerRule()]).audit(root);

  test('a same-line ignore comment silences the finding', () {
    write('lib/a.dart', 'MARKER // security_doctor: ignore SD999\n');
    final report = audit();
    expect(report.findings, isEmpty);
    expect(report.ignoredCount, 1);
    expect(report.fails, isFalse);
  });

  test('a previous-line ignore comment silences the finding', () {
    write(
      'lib/a.dart',
      '// security_doctor: ignore SD999\nMARKER\nMARKER\n',
    );
    final report = audit();
    // Only the finding directly below the comment is silenced.
    expect(report.findings, hasLength(1));
    expect(report.ignoredCount, 1);
  });

  test('comma-separated ids and unrelated ids', () {
    write(
      'lib/a.dart',
      'MARKER // security_doctor: ignore SD001, SD999\n'
          'MARKER // security_doctor: ignore SD001\n',
    );
    final report = audit();
    expect(report.findings, hasLength(1));
    expect(report.findings.single.line, 2);
    expect(report.ignoredCount, 1);
  });

  test('works with XML comment syntax in manifests', () {
    write('android/app/src/main/AndroidManifest.xml', '''
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- security_doctor: ignore SD006 -->
  <application android:allowBackup="true"/>
</manifest>
''');
    final report = audit(rules: [const DebugFlagsRule()]);
    expect(report.findings, isEmpty);
    expect(report.ignoredCount, 1);
  });

  test('ignored findings do not enter the baseline flow', () {
    write('lib/a.dart', 'MARKER // security_doctor: ignore SD999\n');
    final baseline = Baseline.fromFindings(audit().findings);
    expect(baseline.counts, isEmpty);
  });

  test('the ignored count reaches the console report', () {
    write('lib/a.dart', 'MARKER // security_doctor: ignore SD999\n');
    final output = const ConsoleReporter().format(audit());
    expect(output, contains('1 ignored by inline comment'));
  });
}
