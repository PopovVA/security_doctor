import 'dart:io';

import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;

  setUp(() {
    root = Directory.systemTemp.createTempSync('security_doctor_test');
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  test('--help exits 0', () async {
    expect(await run(['--help']), 0);
  });

  test('unknown flags exit 2', () async {
    expect(await run(['--no-such-flag']), 2);
  });

  test('an invalid --fail-on value exits 2', () async {
    expect(await run(['--fail-on', 'blocker']), 2);
  });

  test('a directory without pubspec.yaml exits 2', () async {
    expect(await run(['--path', root.path]), 2);
  });

  test('a clean project exits 0', () async {
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    expect(await run(['--path', root.path]), 0);
  });

  test('a clean project exits 0 with --json too', () async {
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    expect(await run(['--path', root.path, '--json']), 0);
  });

  test('a malformed security_audit.yaml exits 2', () async {
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    File('${root.path}/security_audit.yaml')
        .writeAsStringSync('no_such_key: true\n');
    expect(await run(['--path', root.path]), 2);
  });

  test('--fail-on overrides the config threshold', () async {
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    File('${root.path}/security_audit.yaml')
        .writeAsStringSync('fail_on: critical\n');
    expect(await run(['--path', root.path, '--fail-on', 'low']), 0);
  });
}
