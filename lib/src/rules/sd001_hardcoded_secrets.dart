import 'dart:math' as math;

import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/token.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'literals.dart';

/// SD001 — hardcoded secrets and API keys in Dart code.
///
/// Two detectors, both tuned to stay quiet when unsure:
/// - well-known credential formats (AWS, Google, Stripe, Slack, GitHub,
///   PEM private keys) anywhere in a string literal;
/// - a secret-named binding — variable, map entry, parameter default or
///   named argument — whose value is a long, high-entropy literal that
///   does not look like a placeholder.
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
  /// that always means "credential" beats a broad one that sometimes
  /// does. Publishable/identifier-only values (Stripe pk_live, Twilio
  /// Account SIDs) are deliberately absent.
  static final _knownFormats = <String, RegExp>{
    'AWS access key id': RegExp('AKIA[0-9A-Z]{16}'),
    'Google API key': RegExp('AIza[0-9A-Za-z_-]{35}'),
    'Google OAuth client secret': RegExp('GOCSPX-[A-Za-z0-9_-]{28}'),
    'Firebase Cloud Messaging server key':
        RegExp('AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{60,}'),
    'Stripe live key': RegExp('[sr]k_live_[0-9a-zA-Z]{20,}'),
    'Square token': RegExp('sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}'),
    'Braintree access token':
        RegExp(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    'Slack token': RegExp('xox[baprs]-[0-9A-Za-z-]{10,}'),
    'Slack webhook URL': RegExp(
        r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+'),
    'Telegram bot token': RegExp('[0-9]{8,10}:AA[A-Za-z0-9_-]{33}'),
    'GitHub token': RegExp('gh[pousr]_[A-Za-z0-9]{36,}'),
    'GitLab personal access token': RegExp('glpat-[A-Za-z0-9_-]{20}'),
    'npm access token': RegExp('npm_[A-Za-z0-9]{36}'),
    'OpenAI API key': RegExp(
        'sk-proj-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),
    'Anthropic API key': RegExp('sk-ant-[A-Za-z0-9-]{40,}'),
    'Twilio API key': RegExp('SK[0-9a-fA-F]{32}'),
    'SendGrid API key': RegExp(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    'Mailgun API key': RegExp('key-[0-9a-z]{32}'),
    'DigitalOcean token': RegExp('do[pos]_v1_[0-9a-f]{64}'),
    'Shopify token': RegExp('shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}'),
    'signed JWT': RegExp(
        r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    'private key': RegExp('-----BEGIN [A-Z ]*PRIVATE KEY-----'),
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
            // "a hardcoded" keeps the article on a consonant word, so
            // every key name reads correctly (a Slack token, an AWS
            // access key id) without per-name a/an handling.
            message: 'String literal contains a hardcoded '
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
          message: "${declaration.kind} '${declaration.name}' is set to a "
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
    required this.kind,
    required this.name,
    required this.value,
    required this.offset,
  });

  /// What the binding is — 'Variable', 'Map entry', 'Parameter',
  /// 'Argument' — so the message names the actual context.
  final String kind;
  final String name;
  final String value;
  final int offset;
}

/// Collects every place a secret-sounding name is bound to a string
/// literal: variable initializers, map entries, parameter defaults and
/// named arguments. Entropy and placeholder filtering happen later in
/// [HardcodedSecretsRule.check]; this only gathers candidates.
///
/// Parameter defaults and named arguments are recognized by the shape
/// of the literal's parent node, not by AST class: analyzer 14 renamed
/// both nodes (`NamedExpression` → `NamedArgument`,
/// `DefaultFormalParameter` → a default clause nested in the
/// parameter), and shape matching keeps a single code path compiling
/// across analyzer 8 through 14 — the same approach as SD004's
/// `Object?` signature.
class _SecretDeclarationVisitor extends RecursiveAstVisitor<void> {
  final suspects = <_SecretDeclaration>[];

  void _suspect(String kind, String? name, Expression? value) {
    if (name == null) return;
    if (value is! SimpleStringLiteral) return;
    if (!HardcodedSecretsRule._secretName.hasMatch(name)) return;
    suspects.add(
      _SecretDeclaration(
        kind: kind,
        name: name,
        value: value.value,
        offset: value.offset,
      ),
    );
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    _suspect('Variable', node.name.lexeme, node.initializer);
    super.visitVariableDeclaration(node);
  }

  @override
  void visitMapLiteralEntry(MapLiteralEntry node) {
    // A string key names the entry outright; an identifier key (a
    // constant reference) names it just as clearly.
    final key = node.key;
    final name = key is SimpleStringLiteral
        ? key.value
        : key is SimpleIdentifier
            ? key.name
            : null;
    _suspect('Map entry', name, node.value);
    super.visitMapLiteralEntry(node);
  }

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    final parent = node.parent;
    if (parent != null) {
      final shape = parent.childEntities.toList();
      _suspect('Argument', _argumentName(shape, node), node);
      _suspect('Parameter', _parameterName(parent, shape, node), node);
    }
    super.visitSimpleStringLiteral(node);
  }

  /// The name binding [node] as a named argument, or null.
  ///
  /// analyzer ≤13 parses `f(key: 'v')` as `NamedExpression(Label('key:')
  /// value)` where the label wraps an identifier; analyzer 14 parses it
  /// as `NamedArgument('key' ':' value)` with plain tokens.
  static String? _argumentName(List<Object?> shape, SimpleStringLiteral node) {
    if (shape case [Label label, SimpleStringLiteral value]
        when identical(value, node)) {
      final name = label.childEntities.first;
      if (name is SimpleIdentifier) return name.name;
    }
    if (shape case [Token name, Token colon, SimpleStringLiteral value]
        when colon.lexeme == ':' && identical(value, node)) {
      return name.lexeme;
    }
    return null;
  }

  /// The name of the parameter that [node] is the default value of, or
  /// null.
  ///
  /// analyzer ≤13 wraps the parameter: `DefaultFormalParameter(parameter
  /// '=' value)`; analyzer 14 nests the clause inside the parameter
  /// instead: `FormalParameter(... DefaultClause('=' value))`.
  static String? _parameterName(
    AstNode parent,
    List<Object?> shape,
    SimpleStringLiteral node,
  ) {
    bool isSeparator(Token token) => token.lexeme == '=' || token.lexeme == ':';

    if (shape
        case [
          FormalParameter parameter,
          Token separator,
          SimpleStringLiteral value,
        ] when isSeparator(separator) && identical(value, node)) {
      return parameter.name?.lexeme;
    }
    if (shape case [Token separator, SimpleStringLiteral value]
        when isSeparator(separator) && identical(value, node)) {
      final grandparent = parent.parent;
      if (grandparent is FormalParameter) return grandparent.name?.lexeme;
    }
    return null;
  }
}
