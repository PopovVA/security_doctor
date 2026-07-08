import 'package:security_doctor/security_doctor.dart';
import 'package:test/test.dart';

void main() {
  group('Severity', () {
    test('atLeast follows declaration order', () {
      expect(Severity.critical.atLeast(Severity.low), isTrue);
      expect(Severity.medium.atLeast(Severity.medium), isTrue);
      expect(Severity.low.atLeast(Severity.high), isFalse);
    });

    test('parse accepts every severity name', () {
      for (final severity in Severity.values) {
        expect(Severity.parse(severity.name), severity);
      }
    });

    test('parse rejects unknown names', () {
      expect(() => Severity.parse('blocker'), throwsFormatException);
    });
  });
}
