import 'dart:convert';
import 'dart:io';

import 'rule.dart';

/// A committed snapshot of known findings. Findings matching the
/// baseline are reported as suppressed and never fail the run, so the
/// tool can be adopted on an existing codebase without fixing all
/// historical debt first.
///
/// Matching is by [Finding.fingerprint] — a content hash that survives
/// line shifts — with a count per fingerprint, so two identical
/// occurrences baseline two findings, not unlimited ones.
class Baseline {
  Baseline(Map<String, int> counts) : counts = Map.unmodifiable(counts);

  /// Fingerprint → number of baselined occurrences.
  final Map<String, int> counts;

  static const defaultFileName = 'security_baseline.json';

  factory Baseline.fromFindings(Iterable<Finding> findings) {
    final counts = <String, int>{};
    for (final finding in findings) {
      final fingerprint = finding.fingerprint;
      if (fingerprint == null) continue;
      counts[fingerprint] = (counts[fingerprint] ?? 0) + 1;
    }
    return Baseline(counts);
  }

  /// Parses the baseline file format. Throws [FormatException] on
  /// anything malformed — a silently ignored baseline would resurface
  /// hundreds of findings with no explanation.
  factory Baseline.parse(String source) {
    final Object? doc;
    try {
      doc = jsonDecode(source);
    } on FormatException {
      throw const FormatException('Baseline file is not valid JSON.');
    }
    if (doc is! Map<String, dynamic> || doc['version'] != 1) {
      throw const FormatException(
        "Baseline file must be an object with 'version': 1.",
      );
    }
    final entries = doc['findings'];
    if (entries is! List) {
      throw const FormatException("Baseline 'findings' must be a list.");
    }
    final counts = <String, int>{};
    for (final entry in entries) {
      if (entry is! Map<String, dynamic>) {
        throw const FormatException('Baseline entries must be objects.');
      }
      final fingerprint = entry['fingerprint'];
      final count = entry['count'] ?? 1;
      if (fingerprint is! String || count is! int || count < 1) {
        throw const FormatException(
          "Baseline entries need a string 'fingerprint' and a positive "
          "'count'.",
        );
      }
      counts[fingerprint] = (counts[fingerprint] ?? 0) + count;
    }
    return Baseline(counts);
  }

  factory Baseline.load(File file) => Baseline.parse(file.readAsStringSync());

  /// Splits [findings] into kept findings and a suppressed count. Each
  /// baselined fingerprint absorbs at most its recorded count.
  (List<Finding>, int) apply(List<Finding> findings) {
    final remaining = Map<String, int>.from(counts);
    final kept = <Finding>[];
    var suppressed = 0;
    for (final finding in findings) {
      final budget = remaining[finding.fingerprint] ?? 0;
      if (budget > 0) {
        remaining[finding.fingerprint!] = budget - 1;
        suppressed++;
      } else {
        kept.add(finding);
      }
    }
    return (kept, suppressed);
  }

  /// Serializes with sorted keys so the file diffs cleanly in git.
  String toJsonString() {
    final sorted = counts.keys.toList()..sort();
    return const JsonEncoder.withIndent('  ').convert({
      'version': 1,
      'findings': [
        for (final fingerprint in sorted)
          {'fingerprint': fingerprint, 'count': counts[fingerprint]},
      ],
    });
  }
}
