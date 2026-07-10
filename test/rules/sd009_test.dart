import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

const _gradlePath = 'android/app/build.gradle';

void main() {
  const rule = GradleReleaseConfigRule();

  test('metadata', () {
    expect(rule.id, 'SD009');
    expect(rule.severity, Severity.low);
    expect(rule.masvs, 'MASVS-RESILIENCE-3');
    expect(rule.cwe, 1269);
  });

  test('flags minifyEnabled false in the release block only', () {
    final findings = checkTextFixture(
      rule,
      'sd009/vulnerable_build.gradle',
      kind: FileKind.gradle,
      path: _gradlePath,
    );
    // The debug block also says minifyEnabled false — one finding, not two.
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('minifyEnabled'));
    expect(findings.single.line, 7);
  });

  test('flags minification without shrinkResources (kts syntax)', () {
    final findings = checkTextFixture(
      rule,
      'sd009/no_shrink_build.gradle.kts',
      kind: FileKind.gradle,
      path: 'android/app/build.gradle.kts',
    );
    expect(findings, hasLength(1));
    expect(findings.single.message, contains('shrinkResources'));
  });

  test('stays quiet on minify + shrink and on signingConfigs.release', () {
    expect(
      checkTextFixture(
        rule,
        'sd009/clean_build.gradle',
        kind: FileKind.gradle,
        path: _gradlePath,
      ),
      isEmpty,
    );
  });

  test('stays quiet on gradle files without a release block', () {
    final file = ScanFile(
      path: 'android/build.gradle',
      content: 'ext.kotlin_version = "2.0.0"\n',
      kind: FileKind.gradle,
    );
    expect(rule.check(file), isEmpty);
  });
}
