import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'literals.dart';

/// SD004 — weak cryptography: MD5, SHA-1, ECB mode.
///
/// Detects the two ways weak primitives show up in Flutter code:
/// package:crypto's `md5`/`sha1` digests (used directly or inside an
/// Hmac), and ECB block mode via cipher transformation strings
/// ('AES/ECB/...') or pointycastle's ECBBlockCipher.
class WeakCryptoRule extends DartRule {
  const WeakCryptoRule();

  @override
  String get id => 'SD004';

  @override
  String get title => 'Weak cryptographic algorithm';

  @override
  Severity get severity => Severity.high;

  @override
  String get description =>
      'MD5 and SHA-1 are broken for security purposes, and ECB mode '
      'leaks plaintext structure. Use SHA-256+ and an authenticated '
      'mode such as AES-GCM.';

  @override
  String get masvs => 'MASVS-CRYPTO-1';

  @override
  int get cwe => 327;

  static const _weakDigests = {'md5', 'sha1'};

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final findings = <Finding>[];

    Finding at(int offset, String message) {
      final position = file.positionOf(offset);
      return Finding(
        rule: this,
        path: file.path,
        line: position.line,
        column: position.column,
        message: message,
      );
    }

    final visitor = _WeakCryptoVisitor();
    unit.accept(visitor);
    for (final use in visitor.digestUses) {
      findings.add(
        at(
          use.offset,
          '${use.name.toUpperCase()} is cryptographically broken; '
          'use sha256 or stronger.',
        ),
      );
    }
    for (final use in visitor.ecbCiphers) {
      findings.add(
        at(
          use,
          'ECBBlockCipher leaks plaintext structure; use an '
          'authenticated mode such as GCM.',
        ),
      );
    }

    for (final literal in collectStringLiterals(unit)) {
      if (literal.value.toUpperCase().contains('/ECB')) {
        findings.add(
          at(
            literal.offset,
            "Cipher transformation '${literal.value}' uses ECB mode, "
            'which leaks plaintext structure; use GCM.',
          ),
        );
      }
    }

    return findings;
  }
}

class _DigestUse {
  _DigestUse({required this.name, required this.offset});

  final String name;
  final int offset;
}

class _WeakCryptoVisitor extends RecursiveAstVisitor<void> {
  final digestUses = <_DigestUse>[];
  final ecbCiphers = <int>[];

  /// Accepts [Object] rather than [Expression]: analyzer 13 changed
  /// `ArgumentList.arguments` to `NodeList<Argument>` (which Expression
  /// implements), and this keeps one code path compiling on 12 through 14.
  static bool _isWeakDigest(Object? expression) {
    final name = switch (expression) {
      SimpleIdentifier(:final name) => name,
      PrefixedIdentifier(:final identifier) => identifier.name,
      _ => null,
    };
    return name != null && WeakCryptoRule._weakDigests.contains(name);
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    // md5.convert(...), crypto.sha1.convert(...)
    if (node.methodName.name == 'convert' && _isWeakDigest(node.target)) {
      final target = node.target!;
      digestUses.add(
        _DigestUse(name: target.toSource(), offset: target.offset),
      );
    }
    // Hmac(md5, key) — constructors without `new` parse as invocations.
    if (node.methodName.name == 'Hmac') {
      final arguments = node.argumentList.arguments;
      if (arguments.isNotEmpty && _isWeakDigest(arguments.first)) {
        digestUses.add(
          _DigestUse(
            name: arguments.first.toSource(),
            offset: arguments.first.offset,
          ),
        );
      }
    }
    // ECBBlockCipher(AESEngine()) from pointycastle.
    if (node.methodName.name == 'ECBBlockCipher') {
      ecbCiphers.add(node.offset);
    }
    super.visitMethodInvocation(node);
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    // Explicit `new`/`const` forms of the same constructors.
    final type = node.constructorName.type.toSource();
    if (type == 'Hmac') {
      final arguments = node.argumentList.arguments;
      if (arguments.isNotEmpty && _isWeakDigest(arguments.first)) {
        digestUses.add(
          _DigestUse(
            name: arguments.first.toSource(),
            offset: arguments.first.offset,
          ),
        );
      }
    }
    if (type == 'ECBBlockCipher') {
      ecbCiphers.add(node.offset);
    }
    super.visitInstanceCreationExpression(node);
  }
}
