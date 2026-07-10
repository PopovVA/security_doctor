import 'package:analyzer/dart/ast/ast.dart';

import 'scan_file.dart';

/// How serious a finding is.
///
/// Declaration order is severity order, so `index` comparisons express
/// "at or above a threshold".
enum Severity {
  low,
  medium,
  high,
  critical;

  bool atLeast(Severity threshold) => index >= threshold.index;

  /// Parses a severity name as it appears in config and CLI flags.
  static Severity parse(String name) {
    final severity = values.asNameMap()[name];
    if (severity == null) {
      throw FormatException(
        "Unknown severity '$name'. "
        'Expected one of: ${values.map((v) => v.name).join(', ')}.',
      );
    }
    return severity;
  }
}

/// A single security check.
///
/// Rules declare what input they need through their subtype: [TextRule]
/// works on raw file text; rules that need the Dart AST get their own
/// subtype so the analyzer pass only runs when such a rule is active.
abstract class Rule {
  const Rule();

  /// Stable identifier, `SD###`.
  String get id;

  /// Short human-readable name of the check.
  String get title;

  /// What the rule detects and why it matters.
  String get description;

  Severity get severity;

  /// OWASP MASVS requirement id, e.g. `MASVS-NETWORK-1`.
  String get masvs;

  /// CWE id without the prefix, e.g. `319` for CWE-319.
  int get cwe;
}

/// A rule that inspects the raw text of one file at a time.
abstract class TextRule extends Rule {
  const TextRule();

  /// Whether [file] is worth checking at all (usually a [ScanFile.kind]
  /// test). Files that do not apply are never passed to [check].
  bool appliesTo(ScanFile file);

  List<Finding> check(ScanFile file);
}

/// A rule that inspects the parsed AST of a Dart file.
///
/// The engine parses each Dart file once, and only when at least one
/// [DartRule] is active — text-only runs never pay for the analyzer.
/// Rules that just need string literals share the literal-collecting
/// visitor instead of getting a third subtype.
abstract class DartRule extends Rule {
  const DartRule();

  List<Finding> check(ScanFile file, CompilationUnit unit);
}

/// One occurrence of a rule violation.
class Finding {
  Finding({
    required this.rule,
    required this.path,
    required this.message,
    this.line,
    this.column,
  });

  final Rule rule;

  /// Path relative to the audited project root, with forward slashes.
  final String path;

  final String message;

  /// 1-based, when the rule can point at a location.
  final int? line;
  final int? column;

  /// Content-based identity for baseline matching: a hash of rule id,
  /// path and the normalized source line, so it survives line shifts.
  /// Set by the engine after the rule produced the finding.
  String? fingerprint;

  Severity get severity => rule.severity;
}
