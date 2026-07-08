import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'sensitive_words.dart';

/// SD003 — sensitive data written to SharedPreferences.
///
/// SharedPreferences (and NSUserDefaults behind it on iOS) is plaintext
/// on-disk storage. The rule only fires when both the receiver looks
/// like a preferences object AND the key name is unambiguously
/// sensitive — anything less certain stays quiet.
class SharedPreferencesRule extends DartRule {
  const SharedPreferencesRule();

  @override
  String get id => 'SD003';

  @override
  String get title => 'Sensitive data in SharedPreferences';

  @override
  Severity get severity => Severity.high;

  @override
  String get description =>
      'SharedPreferences stores values in plaintext. Keep tokens, '
      'passwords and other secrets in flutter_secure_storage or the '
      'platform keychain/keystore.';

  @override
  String get masvs => 'MASVS-STORAGE-1';

  @override
  int get cwe => 922;

  static const _writeMethods = {'setString', 'setStringList'};

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final visitor = _PrefsWriteVisitor();
    unit.accept(visitor);
    final findings = <Finding>[];
    for (final write in visitor.writes) {
      if (!isSensitiveName(write.key)) continue;
      final position = file.positionOf(write.offset);
      findings.add(
        Finding(
          rule: this,
          path: file.path,
          line: position.line,
          column: position.column,
          message: "Key '${write.key}' looks sensitive but is written to "
              'SharedPreferences, which is stored in plaintext.',
        ),
      );
    }
    return findings;
  }
}

class _PrefsWrite {
  _PrefsWrite({required this.key, required this.offset});

  final String key;
  final int offset;
}

class _PrefsWriteVisitor extends RecursiveAstVisitor<void> {
  final writes = <_PrefsWrite>[];

  @override
  void visitMethodInvocation(MethodInvocation node) {
    if (SharedPreferencesRule._writeMethods.contains(
      node.methodName.name,
    )) {
      final target = node.target?.toSource().toLowerCase() ?? '';
      final arguments = node.argumentList.arguments;
      if (target.contains('pref') &&
          arguments.isNotEmpty &&
          arguments.first is SimpleStringLiteral) {
        final key = arguments.first as SimpleStringLiteral;
        writes.add(_PrefsWrite(key: key.value, offset: key.offset));
      }
    }
    super.visitMethodInvocation(node);
  }
}
