import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'sensitive_words.dart';

/// SD008 — sensitive data passed to `print`/`log`/`debugPrint`.
///
/// Fires only when a logging call references an identifier whose name
/// is unambiguously sensitive (whole-word match: `authToken` yes,
/// `authorName` no) — the content of arbitrary logged strings is
/// unknowable statically, so everything else stays quiet.
class SensitiveLoggingRule extends DartRule {
  const SensitiveLoggingRule();

  @override
  String get id => 'SD008';

  @override
  String get title => 'Sensitive data in log output';

  @override
  Severity get severity => Severity.medium;

  @override
  String get description =>
      'Log output ends up in logcat, crash reports and CI logs, all '
      'readable by other apps or third parties. Never log credentials.';

  @override
  String get masvs => 'MASVS-STORAGE-2';

  @override
  int get cwe => 532;

  static const _logFunctions = {'print', 'debugPrint', 'log'};

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final visitor = _LogCallVisitor();
    unit.accept(visitor);
    final findings = <Finding>[];
    for (final call in visitor.calls) {
      final leaked = _sensitiveIdentifiersIn(call.argumentList);
      if (leaked.isEmpty) continue;
      final position = file.positionOf(call.offset);
      findings.add(
        Finding(
          rule: this,
          path: file.path,
          line: position.line,
          column: position.column,
          message: "'${call.methodName.name}' logs "
              "'${leaked.join("', '")}' — credentials in logs leak via "
              'logcat, crash reports and CI output.',
        ),
      );
    }
    return findings;
  }

  static List<String> _sensitiveIdentifiersIn(ArgumentList arguments) {
    final collector = _IdentifierCollector();
    arguments.accept(collector);
    return collector.sensitive;
  }
}

class _LogCallVisitor extends RecursiveAstVisitor<void> {
  final calls = <MethodInvocation>[];

  @override
  void visitMethodInvocation(MethodInvocation node) {
    // Bare calls only: `print(...)`, `debugPrint(...)`, `log(...)`.
    // A method on some object (`logger.log`) is included via the same
    // name check; the receiver does not change what gets written out.
    if (SensitiveLoggingRule._logFunctions.contains(node.methodName.name)) {
      calls.add(node);
    }
    super.visitMethodInvocation(node);
  }
}

class _IdentifierCollector extends RecursiveAstVisitor<void> {
  final sensitive = <String>[];

  @override
  void visitSimpleIdentifier(SimpleIdentifier node) {
    if (isSensitiveName(node.name) && !sensitive.contains(node.name)) {
      sensitive.add(node.name);
    }
    super.visitSimpleIdentifier(node);
  }
}
