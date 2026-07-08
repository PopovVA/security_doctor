import 'dart:io';

import 'package:analyzer/dart/analysis/utilities.dart';
import 'package:security_doctor/security_doctor.dart';

/// Parses a fixture under test/fixtures/ and runs one Dart rule on it,
/// the same way the engine does.
List<Finding> checkFixture(DartRule rule, String fixture) =>
    checkSource(rule, File('test/fixtures/$fixture').readAsStringSync());

/// Runs one text rule on a fixture under test/fixtures/, with the kind
/// and project-relative path the engine would assign to it.
List<Finding> checkTextFixture(
  TextRule rule,
  String fixture, {
  required FileKind kind,
  required String path,
}) {
  final file = ScanFile(
    path: path,
    content: File('test/fixtures/$fixture').readAsStringSync(),
    kind: kind,
  );
  if (!rule.appliesTo(file)) return const [];
  return rule.check(file);
}

/// Runs one Dart rule on in-memory source — for inputs that cannot be
/// committed as fixture files (e.g. secret-shaped literals).
List<Finding> checkSource(DartRule rule, String content) {
  final result = parseString(content: content, throwIfDiagnostics: false);
  if (result.errors.isNotEmpty) {
    throw StateError('Source does not parse: ${result.errors}');
  }
  final file = ScanFile(
    path: 'lib/source.dart',
    content: content,
    kind: FileKind.dart,
  );
  return rule.check(file, result.unit);
}
