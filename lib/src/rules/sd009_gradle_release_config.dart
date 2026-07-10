import '../rule.dart';
import '../scan_file.dart';

/// SD009 — release build type without code shrinking.
///
/// Text-based on purpose: Gradle scripts are Turing-complete, so the
/// rule only asserts what it can see literally inside a `release { }`
/// block — an explicit `minifyEnabled false`, or minification enabled
/// without resource shrinking. Values set through variables or plugins
/// stay unflagged (quiet over clever).
class GradleReleaseConfigRule extends TextRule {
  const GradleReleaseConfigRule();

  @override
  String get id => 'SD009';

  @override
  String get title => 'Release build without code shrinking';

  @override
  Severity get severity => Severity.low;

  @override
  String get description =>
      'R8/ProGuard shrinking removes unused code and obfuscates the '
      'rest, raising the bar for reverse engineering of release builds.';

  @override
  String get masvs => 'MASVS-RESILIENCE-3';

  @override
  int get cwe => 1269;

  static final _minifyDisabled =
      RegExp(r'(?:isMinifyEnabled|minifyEnabled)\s*=?\s*false');
  static final _minifyEnabled =
      RegExp(r'(?:isMinifyEnabled|minifyEnabled)\s*=?\s*true');
  static final _shrinkMentioned =
      RegExp(r'(?:isShrinkResources|shrinkResources)');
  static final _releaseBlock = RegExp(r'release\s*\{');

  @override
  bool appliesTo(ScanFile file) => file.kind == FileKind.gradle;

  @override
  List<Finding> check(ScanFile file) {
    final findings = <Finding>[];
    for (final block in _releaseBlocks(file.content)) {
      final text = block.text;

      final disabled = _minifyDisabled.firstMatch(text);
      if (disabled != null) {
        final position = file.positionOf(block.offset + disabled.start);
        findings.add(
          Finding(
            rule: this,
            path: file.path,
            line: position.line,
            column: position.column,
            message: 'minifyEnabled is explicitly false in the release '
                'build type: the release binary ships unshrunken and '
                'unobfuscated.',
          ),
        );
        continue; // Suggesting shrinkResources on top would be noise.
      }

      final enabled = _minifyEnabled.firstMatch(text);
      if (enabled != null && !_shrinkMentioned.hasMatch(text)) {
        final position = file.positionOf(block.offset + enabled.start);
        findings.add(
          Finding(
            rule: this,
            path: file.path,
            line: position.line,
            column: position.column,
            message: 'Minification is on but shrinkResources is not set '
                'in the release build type — unused resources still ship.',
          ),
        );
      }
    }
    return findings;
  }

  /// Extracts every `release { ... }` block by brace matching. A
  /// `signingConfigs { release { } }` block matches too, but none of
  /// the patterns above can occur there, so it is harmless.
  static Iterable<({int offset, String text})> _releaseBlocks(
    String content,
  ) sync* {
    for (final match in _releaseBlock.allMatches(content)) {
      final start = match.end; // Position after '{'.
      var depth = 1;
      var i = start;
      while (i < content.length && depth > 0) {
        final char = content[i];
        if (char == '{') depth++;
        if (char == '}') depth--;
        i++;
      }
      if (depth == 0) {
        yield (offset: start, text: content.substring(start, i - 1));
      }
    }
  }
}
