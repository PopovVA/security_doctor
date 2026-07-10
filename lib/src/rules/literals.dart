import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

/// A string value (or its known constant prefix) found in one file.
class LiteralOccurrence {
  LiteralOccurrence({
    required this.value,
    required this.offset,
    this.isComplete = true,
  });

  final String value;
  final int offset;

  /// False when [value] is only the constant prefix of a string whose
  /// tail is computed at runtime (interpolation or concatenation).
  /// Prefix checks (`http://…`) are safe on partial values; whole-value
  /// reasoning is not.
  final bool isComplete;
}

/// Collects string literals from a unit: simple literals, adjacent
/// strings, and the constant prefixes of interpolations and `+`
/// concatenations. Runtime-computed tails are unknowable statically —
/// rules get the known prefix and an [LiteralOccurrence.isComplete]
/// flag instead of a guess.
List<LiteralOccurrence> collectStringLiterals(CompilationUnit unit) {
  final collector = _LiteralCollector();
  unit.accept(collector);
  return collector.literals;
}

class _LiteralCollector extends RecursiveAstVisitor<void> {
  final literals = <LiteralOccurrence>[];

  /// Leaves already folded into a joined occurrence, so they are not
  /// reported a second time individually.
  final _consumed = <AstNode>{};

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    if (!_consumed.contains(node)) {
      literals.add(LiteralOccurrence(value: node.value, offset: node.offset));
    }
    super.visitSimpleStringLiteral(node);
  }

  @override
  void visitAdjacentStrings(AdjacentStrings node) {
    final parts = node.strings;
    if (parts.every((s) => s is SimpleStringLiteral)) {
      literals.add(
        LiteralOccurrence(
          value: parts.cast<SimpleStringLiteral>().map((s) => s.value).join(),
          offset: node.offset,
        ),
      );
      parts.forEach(_consumed.add);
    }
    // Mixed adjacent strings fall through: each part is handled by its
    // own visit (simple parts as literals, interpolations as prefixes).
    super.visitAdjacentStrings(node);
  }

  @override
  void visitStringInterpolation(StringInterpolation node) {
    final first = node.elements.first;
    if (first is InterpolationString && first.value.isNotEmpty) {
      literals.add(
        LiteralOccurrence(
          value: first.value,
          offset: node.offset,
          isComplete: false,
        ),
      );
    }
    // Still descend: interpolated expressions can contain literals.
    super.visitStringInterpolation(node);
  }

  @override
  void visitBinaryExpression(BinaryExpression node) {
    // Only handle the outermost `+` of a chain; nested ones are part
    // of this fold.
    if (node.operator.lexeme == '+' &&
        node.parent is! BinaryExpression &&
        !_consumed.contains(node)) {
      final folded = _fold(node);
      if (folded != null && folded.value.isNotEmpty) {
        literals.add(
          LiteralOccurrence(
            value: folded.value,
            offset: node.offset,
            isComplete: folded.complete,
          ),
        );
      }
    }
    super.visitBinaryExpression(node);
  }

  /// Folds the constant prefix of a `+` chain. Returns null when the
  /// chain does not start with a string literal.
  ({String value, bool complete})? _fold(Expression node) {
    if (node is SimpleStringLiteral) {
      _consumed.add(node);
      return (value: node.value, complete: true);
    }
    if (node is BinaryExpression && node.operator.lexeme == '+') {
      final left = _fold(node.leftOperand);
      if (left == null) return null;
      _consumed.add(node);
      if (!left.complete) return left;
      final right = _fold(node.rightOperand);
      if (right == null) return (value: left.value, complete: false);
      return (
        value: left.value + right.value,
        complete: right.complete,
      );
    }
    return null;
  }
}
