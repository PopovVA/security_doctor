import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

/// A string literal with its position, as collected from one file.
class LiteralOccurrence {
  LiteralOccurrence({required this.value, required this.offset});

  final String value;
  final int offset;
}

/// Collects simple (non-interpolated) string literals from a unit.
/// Interpolated strings are skipped: their runtime value is unknowable
/// statically, and guessing invites false positives.
List<LiteralOccurrence> collectStringLiterals(CompilationUnit unit) {
  final collector = _LiteralCollector();
  unit.accept(collector);
  return collector.literals;
}

class _LiteralCollector extends RecursiveAstVisitor<void> {
  final literals = <LiteralOccurrence>[];

  @override
  void visitSimpleStringLiteral(SimpleStringLiteral node) {
    literals.add(LiteralOccurrence(value: node.value, offset: node.offset));
    super.visitSimpleStringLiteral(node);
  }
}
