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

  test('a directory without pubspec.yaml exits 2', () async {
    expect(await run(['--path', root.path]), 2);
  });

  test('a project with pubspec.yaml exits 0 while no rules exist', () async {
    File('${root.path}/pubspec.yaml').writeAsStringSync('name: app\n');
    expect(await run(['--path', root.path]), 0);
  });
}
