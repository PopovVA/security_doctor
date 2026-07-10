import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:security_doctor/src/rules/literals.dart';
import 'package:test/test.dart';

List<LiteralOccurrence> collect(String source) {
  final result = parseString(content: source, throwIfDiagnostics: false);
  expect(result.errors, isEmpty);
  return collectStringLiterals(result.unit);
}

void main() {
  test('simple literals are complete values', () {
    final literals = collect("const a = 'hello';");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'hello');
    expect(literals.single.isComplete, isTrue);
  });

  test('all-simple adjacent strings join without duplicating parts', () {
    final literals = collect("const a = 'http://' 'api.example.com';");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'http://api.example.com');
    expect(literals.single.isComplete, isTrue);
  });

  test('interpolations yield their constant prefix as partial', () {
    final literals = collect(r"void f(Object e) => print('http://api.$e');");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'http://api.');
    expect(literals.single.isComplete, isFalse);
  });

  test('interpolations with no prefix yield nothing for themselves', () {
    final literals = collect(r"void f(Object e) => print('$e suffix');");
    expect(literals, isEmpty);
  });

  test('literals nested inside interpolation expressions still count', () {
    final literals =
        collect(r"void f(Object e) => print('x${e.toString() + 'y'}');");
    expect(literals.map((l) => l.value), contains('y'));
  });

  test('+-concatenation of two literals folds to one complete value', () {
    final literals = collect("const a = 'http://' + 'api.example.com';");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'http://api.example.com');
    expect(literals.single.isComplete, isTrue);
  });

  test('+-concatenation with a runtime tail is a partial prefix', () {
    final literals = collect("String f(String host) => 'http://' + host;");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'http://');
    expect(literals.single.isComplete, isFalse);
  });

  test('chains fold left to right until the first runtime part', () {
    final literals =
        collect("String f(String p) => 'http://' + 'api.example.com/' + p;");
    expect(literals, hasLength(1));
    expect(literals.single.value, 'http://api.example.com/');
    expect(literals.single.isComplete, isFalse);
  });

  test('a chain starting with a runtime value reports only leaf literals', () {
    final literals = collect("String f(String p) => p + '/suffix';");
    expect(literals, hasLength(1));
    expect(literals.single.value, '/suffix');
    expect(literals.single.isComplete, isTrue);
  });
}
