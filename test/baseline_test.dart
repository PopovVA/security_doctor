import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  group('Baseline.parse', () {
    test('round-trips through toJsonString', () {
      final baseline = Baseline({'aaa': 2, 'bbb': 1});
      final parsed = Baseline.parse(baseline.toJsonString());
      expect(parsed.counts, {'aaa': 2, 'bbb': 1});
    });

    test('rejects invalid JSON, wrong version and malformed entries', () {
      expect(() => Baseline.parse('not json'), throwsFormatException);
      expect(() => Baseline.parse('{"version": 2}'), throwsFormatException);
      expect(
        () => Baseline.parse('{"version": 1, "findings": [{"count": 1}]}'),
        throwsFormatException,
      );
      expect(
        () => Baseline.parse(
          '{"version": 1, "findings": [{"fingerprint": "a", "count": 0}]}',
        ),
        throwsFormatException,
      );
    });
  });

  group('engine with a baseline', () {
    late Directory root;

    setUp(() {
      root = Directory.systemTemp.createTempSync('security_doctor_baseline');
    });

    tearDown(() {
      root.deleteSync(recursive: true);
    });

    void write(String relative, String content) {
      File('${root.path}/$relative')
        ..createSync(recursive: true)
        ..writeAsStringSync(content);
    }

    AuditReport audit({Baseline? baseline}) => SecurityAuditor(
          rules: [const MarkerRule()],
          baseline: baseline,
        ).audit(root);

    test('baselined findings are suppressed, new ones still fail', () {
      write('lib/a.dart', 'MARKER old\n');
      final baseline = Baseline.fromFindings(audit().findings);

      write('lib/a.dart', 'MARKER old\nMARKER new\n');
      final report = audit(baseline: baseline);

      expect(report.baselineSuppressedCount, 1);
      expect(report.findings, hasLength(1));
      expect(report.findings.single.line, 2);
      expect(report.fails, isTrue);
    });

    test('suppression survives line shifts', () {
      write('lib/a.dart', 'MARKER old\n');
      final baseline = Baseline.fromFindings(audit().findings);

      write('lib/a.dart', '// comment\n// comment\nMARKER old\n');
      final report = audit(baseline: baseline);

      expect(report.baselineSuppressedCount, 1);
      expect(report.findings, isEmpty);
      expect(report.fails, isFalse);
    });

    test('a fingerprint absorbs only its recorded count', () {
      write('lib/a.dart', 'MARKER x\n');
      final baseline = Baseline.fromFindings(audit().findings);

      // The same line twice: one occurrence is baselined, one is new.
      write('lib/a.dart', 'MARKER x\nMARKER x\n');
      final report = audit(baseline: baseline);

      expect(report.baselineSuppressedCount, 1);
      expect(report.findings, hasLength(1));
    });
  });

  group('CLI baseline flow', () {
    late Directory root;

    setUp(() {
      root = Directory.systemTemp.createTempSync('security_doctor_cli_bl');
      File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
      Directory('${root.path}/lib').createSync();
      File('${root.path}/lib/main.dart')
          .writeAsStringSync("const url = 'http://api.example.com';\n");
    });

    tearDown(() {
      root.deleteSync(recursive: true);
    });

    test('--write-baseline then a clean run exits 0 on old findings', () async {
      expect(await run(['--path', root.path]), 1);
      expect(await run(['--path', root.path, '--write-baseline']), 0);
      expect(
        File('${root.path}/security_baseline.json').existsSync(),
        isTrue,
      );
      expect(await run(['--path', root.path]), 0);

      // A new finding still fails.
      File('${root.path}/lib/extra.dart')
          .writeAsStringSync("const other = 'http://evil.example.com';\n");
      expect(await run(['--path', root.path]), 1);
    });

    test('a configured but missing baseline exits 2', () async {
      File('${root.path}/security_audit.yaml')
          .writeAsStringSync('baseline: missing.json\n');
      expect(await run(['--path', root.path]), 2);
    });

    test('a malformed baseline exits 2', () async {
      File('${root.path}/security_baseline.json')
          .writeAsStringSync('{"version": 42}');
      expect(await run(['--path', root.path]), 2);
    });
  });
}
