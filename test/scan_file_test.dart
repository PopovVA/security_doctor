import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

void main() {
  group('ScanFile.classify', () {
    test('recognises every scanned kind', () {
      expect(ScanFile.classify('lib/main.dart'), FileKind.dart);
      expect(ScanFile.classify('pubspec.yaml'), FileKind.pubspec);
      expect(ScanFile.classify('pubspec.lock'), FileKind.pubspec);
      expect(
        ScanFile.classify('android/app/src/main/AndroidManifest.xml'),
        FileKind.androidManifest,
      );
      expect(ScanFile.classify('ios/Runner/Info.plist'), FileKind.infoPlist);
      expect(ScanFile.classify('android/app/build.gradle'), FileKind.gradle);
      expect(ScanFile.classify('android/build.gradle.kts'), FileKind.gradle);
      expect(
        ScanFile.classify('ios/Runner/Runner.entitlements'),
        FileKind.entitlements,
      );
    });

    test('returns null for files no rule reads', () {
      expect(ScanFile.classify('README.md'), isNull);
      expect(ScanFile.classify('assets/logo.png'), isNull);
      expect(ScanFile.classify('analysis_options.yaml'), isNull);
    });
  });

  group('ScanFile.positionOf', () {
    final file = ScanFile(
      path: 'lib/a.dart',
      content: 'one\ntwo\nthree',
      kind: FileKind.dart,
    );

    test('maps offsets to 1-based line and column', () {
      expect(file.positionOf(0), (line: 1, column: 1));
      expect(file.positionOf(2), (line: 1, column: 3));
      expect(file.positionOf(4), (line: 2, column: 1));
      expect(file.positionOf(9), (line: 3, column: 2));
    });
  });
}
