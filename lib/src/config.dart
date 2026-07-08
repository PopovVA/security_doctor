import 'dart:io';

import 'package:glob/glob.dart';
import 'package:yaml/yaml.dart';

import 'rule.dart';

/// Settings from `security_audit.yaml` at the project root.
///
/// ```yaml
/// rules:
///   SD002: false        # disable a rule
/// fail_on: high         # exit 1 only for findings at/above this severity
/// exclude:
///   - lib/generated/**  # glob, relative to the project root
/// ```
///
/// Unknown keys are an error: a typo that silently disables a setting is
/// worse than a failed run.
class AuditConfig {
  AuditConfig({
    this.disabledRules = const {},
    this.failOn = Severity.low,
    List<String> exclude = const [],
  })  : excludePatterns = List.unmodifiable(exclude),
        _excludeGlobs = exclude.map(Glob.new).toList();

  /// Rule ids switched off via `rules: {SD###: false}`.
  final Set<String> disabledRules;

  /// Findings at or above this severity make the run exit 1. Everything
  /// is still reported; this only gates the exit code.
  final Severity failOn;

  /// The raw `exclude` globs, as written in the config.
  final List<String> excludePatterns;

  final List<Glob> _excludeGlobs;

  bool ruleEnabled(String id) => !disabledRules.contains(id);

  /// Whether a root-relative path (forward slashes) is excluded from the
  /// scan.
  bool excludes(String path) => _excludeGlobs.any((g) => g.matches(path));

  AuditConfig copyWith({Severity? failOn}) => AuditConfig(
        disabledRules: disabledRules,
        failOn: failOn ?? this.failOn,
        exclude: excludePatterns,
      );

  /// Reads `security_audit.yaml` from [root] if present; defaults
  /// otherwise. Throws [FormatException] on malformed config.
  factory AuditConfig.load(Directory root) {
    final file = File('${root.path}/security_audit.yaml');
    if (!file.existsSync()) return AuditConfig();
    return AuditConfig.parse(file.readAsStringSync());
  }

  factory AuditConfig.parse(String source) {
    final doc = loadYaml(source);
    if (doc == null) return AuditConfig();
    if (doc is! YamlMap) {
      throw const FormatException(
        'security_audit.yaml must be a YAML map at the top level.',
      );
    }

    const knownKeys = {'rules', 'fail_on', 'exclude'};
    for (final key in doc.keys) {
      if (!knownKeys.contains(key)) {
        throw FormatException(
          "Unknown key '$key' in security_audit.yaml. "
          'Expected one of: ${knownKeys.join(', ')}.',
        );
      }
    }

    final disabled = <String>{};
    final rules = doc['rules'];
    if (rules != null) {
      if (rules is! YamlMap) {
        throw const FormatException(
          "'rules' must be a map of rule id to boolean.",
        );
      }
      for (final entry in rules.entries) {
        final value = entry.value;
        if (value is! bool) {
          throw FormatException(
            "'rules: ${entry.key}' must be true or false, "
            "got '$value'.",
          );
        }
        if (!value) disabled.add(entry.key.toString());
      }
    }

    var failOn = Severity.low;
    final rawFailOn = doc['fail_on'];
    if (rawFailOn != null) {
      if (rawFailOn is! String) {
        throw FormatException("'fail_on' must be a string, got '$rawFailOn'.");
      }
      failOn = Severity.parse(rawFailOn);
    }

    final exclude = <String>[];
    final rawExclude = doc['exclude'];
    if (rawExclude != null) {
      if (rawExclude is! YamlList) {
        throw const FormatException("'exclude' must be a list of globs.");
      }
      for (final pattern in rawExclude) {
        if (pattern is! String) {
          throw FormatException(
              "'exclude' entries must be strings, got '$pattern'.");
        }
        exclude.add(pattern);
      }
    }

    return AuditConfig(
      disabledRules: disabled,
      failOn: failOn,
      exclude: exclude,
    );
  }
}
