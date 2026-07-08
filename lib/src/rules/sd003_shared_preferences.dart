import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';

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

  /// Words that make a preference key sensitive. Matched against whole
  /// words split from the key (camelCase and snake_case aware), so
  /// 'authorName' does not match 'auth'.
  static const _sensitiveWords = {
    'password',
    'passwd',
    'pwd',
    'secret',
    'token',
    'jwt',
    'credential',
    'credentials',
    'apikey',
    'auth',
    'session',
    'pin',
    'cvv',
    'ssn',
  };

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final visitor = _PrefsWriteVisitor();
    unit.accept(visitor);
    final findings = <Finding>[];
    for (final write in visitor.writes) {
      final words = splitIdentifierWords(write.key);
      // 'apiKey' arrives as [api, key]; rejoin neighbours so the pair
      // can match 'apikey' without 'key' alone being sensitive.
      final pairs = [
        for (var i = 0; i + 1 < words.length; i++) words[i] + words[i + 1],
      ];
      final sensitive = words.followedBy(pairs).any(_sensitiveWords.contains);
      if (!sensitive) continue;
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

/// Splits camelCase, snake_case and kebab-case identifiers into
/// lowercase words.
List<String> splitIdentifierWords(String identifier) {
  final withBreaks = identifier.replaceAllMapped(
    RegExp('([a-z0-9])([A-Z])'),
    (m) => '${m[1]} ${m[2]}',
  );
  return withBreaks
      .split(RegExp('[^A-Za-z0-9]+'))
      .where((w) => w.isNotEmpty)
      .map((w) => w.toLowerCase())
      .toList();
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
