import 'dart:math' as math;

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'literals.dart';

/// SD001 — hardcoded secrets and API keys in Dart code.
///
/// Two detectors, both tuned to stay quiet when unsure:
/// - well-known credential formats (AWS, Google, Stripe, Slack, GitHub,
///   PEM private keys) anywhere in a string literal;
/// - a variable whose name says "secret" initialized with a long,
///   high-entropy literal that does not look like a placeholder.
class HardcodedSecretsRule extends DartRule {
  const HardcodedSecretsRule();

  @override
  String get id => 'SD001';

  @override
  String get title => 'Hardcoded secret or API key';

  @override
  String get description =>
      'Credentials compiled into the app can be extracted from the '
      'binary. Load them from secure storage or the environment instead.';

  @override
  Severity get severity => Severity.critical;

  @override
  String get masvs => 'MASVS-STORAGE-1';

  @override
  int get cwe => 798;

  /// Known credential shapes. Kept specific on purpose: a narrow pattern
  /// that always means "credential" beats a broad one that sometimes does.
  static final _knownFormats = <String, RegExp>{
    'AWS access key id': RegExp('AKIA[0-9A-Z]{16}'),
    'Google API key': RegExp('AIza[0-9A-Za-z_-]{35}'),
    'Stripe live key': RegExp('[sr]k_live_[0-9a-zA-Z]{20,}'),
    'Slack token': RegExp('xox[baprs]-[0-9A-Za-z-]{10,}'),
    'GitHub token': RegExp('gh[pousr]_[A-Za-z0-9]{36,}'),
    'private key material': RegExp('-----BEGIN [A-Z ]*PRIVATE KEY-----'),
  };

  static final _secretName = RegExp(
    r'(?:password|passwd|secret|api_?key|access_?key|private_?key|'
    r'credential|auth_?token)',
    caseSensitive: false,
  );

  static const _placeholderMarkers = [
    'example',
    'sample',
    'placeholder',
    'your_',
    'your-',
    'changeme',
    'change_me',
    'dummy',
    'xxxx',
    '****',
    '<',
    ' ',
  ];

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final findings = <Finding>[];

    for (final literal in collectStringLiterals(unit)) {
      for (final entry in _knownFormats.entries) {
        final match = entry.value.firstMatch(literal.value);
        if (match == null) continue;
        final position = file.positionOf(literal.offset);
        findings.add(
          Finding(
            rule: this,
            path: file.path,
            line: position.line,
            column: position.column,
            message: 'String literal contains what looks like a '
                '${entry.key} (${_mask(match.group(0)!)}).',
          ),
        );
        break; // One finding per literal is enough.
      }
    }

    final declarations = _SecretDeclarationVisitor();
    unit.accept(declarations);
    for (final declaration in declarations.suspects) {
      final value = declaration.value;
      if (value.length < 16) continue;
      if (value.contains(RegExp(r'\s'))) continue;
      if (_looksLikePlaceholder(value)) continue;
      if (_shannonEntropy(value) < 3.5) continue;
      final position = file.positionOf(declaration.offset);
      findings.add(
        Finding(
          rule: this,
          path: file.path,
          line: position.line,
          column: position.column,
          message: "Variable '${declaration.name}' is initialized with a "
              'high-entropy literal (${_mask(value)}) — this looks like '
              'a hardcoded credential.',
        ),
      );
    }

    return findings;
  }

  static bool _looksLikePlaceholder(String value) {
    final lower = value.toLowerCase();
    if (_placeholderMarkers.any(lower.contains)) return true;
    return lower.split('').toSet().length <= 2; // 'aaaa', '....', etc.
  }

  static String _mask(String value) {
    final visible = value.length <= 8 ? 2 : 4;
    return '${value.substring(0, visible)}…';
  }

  static double _shannonEntropy(String value) {
    final counts = <int, int>{};
    for (final unit in value.codeUnits) {
      counts[unit] = (counts[unit] ?? 0) + 1;
    }
    var entropy = 0.0;
    for (final count in counts.values) {
      final p = count / value.length;
      entropy -= p * math.log(p) / math.ln2;
    }
    return entropy;
  }
}

class _SecretDeclaration {
  _SecretDeclaration({
    required this.name,
    required this.value,
    required this.offset,
  });

  final String name;
  final String value;
  final int offset;
}

class _SecretDeclarationVisitor extends RecursiveAstVisitor<void> {
  final suspects = <_SecretDeclaration>[];

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    final initializer = node.initializer;
    if (initializer is SimpleStringLiteral &&
        HardcodedSecretsRule._secretName.hasMatch(node.name.lexeme)) {
      suspects.add(
        _SecretDeclaration(
          name: node.name.lexeme,
          value: initializer.value,
          offset: initializer.offset,
        ),
      );
    }
    super.visitVariableDeclaration(node);
  }
}
