import 'engine.dart';
import 'reporter.dart';
import 'rule.dart';

/// Compliance standards findings can be grouped by.
///
/// The mapping is informative: it tells an auditor which requirement a
/// finding is evidence against. It is NOT a compliance verdict — a
/// clean run does not make an app PCI DSS or ISO 27001 compliant.
enum ComplianceStandard {
  pciDss('pci-dss', 'PCI DSS v4.0', 'Requirement'),
  iso27001('iso-27001', 'ISO/IEC 27001:2022 Annex A', 'Control');

  const ComplianceStandard(this.cliName, this.displayName, this.unitLabel);

  /// The value used on the command line (`--compliance pci-dss`).
  final String cliName;

  final String displayName;

  /// What this standard calls one entry: requirement vs control.
  final String unitLabel;

  static ComplianceStandard parse(String name) {
    for (final standard in values) {
      if (standard.cliName == name) return standard;
    }
    throw FormatException(
      "Unknown compliance standard '$name'. "
      'Expected one of: ${values.map((s) => s.cliName).join(', ')}.',
    );
  }
}

/// Short titles for every requirement/control referenced by the rule
/// mappings, keyed by standard.
const Map<ComplianceStandard, Map<String, String>> requirementTitles = {
  ComplianceStandard.pciDss: {
    '3.3.1': 'Sensitive authentication data is not retained or logged',
    '3.5.1': 'Stored account data is rendered unreadable',
    '4.2.1': 'Strong cryptography protects data in transit',
    '6.5.6': 'Test and development features are removed before production',
    '7.2.1': 'Access is granted on need-to-know and least privilege',
    '8.6.2': 'Passwords and passphrases are not hard-coded',
  },
  ComplianceStandard.iso27001: {
    'A.5.14': 'Information transfer',
    'A.5.17': 'Authentication information',
    'A.8.9': 'Configuration management',
    'A.8.15': 'Logging',
    'A.8.24': 'Use of cryptography',
    'A.8.28': 'Secure coding',
  },
};

/// Rule id → requirements/controls the finding is evidence against.
const Map<ComplianceStandard, Map<String, List<String>>> ruleMappings = {
  ComplianceStandard.pciDss: {
    'SD001': ['8.6.2'],
    'SD002': ['4.2.1'],
    'SD003': ['3.5.1'],
    'SD004': ['3.5.1', '4.2.1'],
    'SD005': ['4.2.1'],
    'SD006': ['6.5.6'],
    'SD007': ['7.2.1'],
    'SD008': ['3.3.1'],
  },
  ComplianceStandard.iso27001: {
    'SD001': ['A.5.17', 'A.8.28'],
    'SD002': ['A.5.14', 'A.8.24'],
    'SD003': ['A.8.24'],
    'SD004': ['A.8.24'],
    'SD005': ['A.5.14', 'A.8.24'],
    'SD006': ['A.8.9'],
    'SD007': ['A.8.9'],
    'SD008': ['A.8.15'],
  },
};

/// Groups findings by requirement of one standard. Requirements the
/// tool knows but has no findings for are listed as clean, which is the
/// half auditors actually ask for.
class ComplianceReporter implements Reporter {
  const ComplianceReporter(this.standard, {this.markdown = false});

  final ComplianceStandard standard;
  final bool markdown;

  static const _disclaimer =
      'Informative mapping of findings to requirements; not a '
      'compliance verdict or a substitute for a QSA/auditor assessment.';

  @override
  String format(AuditReport report) {
    final titles = requirementTitles[standard]!;
    final mapping = ruleMappings[standard]!;

    final byRequirement = <String, List<Finding>>{
      for (final id in titles.keys) id: [],
    };
    final unmapped = <Finding>[];
    for (final finding in report.findings) {
      final requirements = mapping[finding.rule.id];
      if (requirements == null || requirements.isEmpty) {
        unmapped.add(finding);
        continue;
      }
      for (final id in requirements) {
        byRequirement[id]!.add(finding);
      }
    }

    final buffer = StringBuffer();
    void heading(String text) => buffer.writeln(markdown ? '## $text' : text);

    if (markdown) {
      buffer.writeln('# security_doctor — ${standard.displayName}\n');
    } else {
      buffer.writeln('security_doctor — ${standard.displayName}\n');
    }
    buffer
      ..writeln(markdown ? '> $_disclaimer' : _disclaimer)
      ..writeln();

    final sortedIds = titles.keys.toList()..sort(_compareRequirementIds);
    for (final id in sortedIds) {
      final findings = byRequirement[id]!;
      final status = findings.isEmpty
          ? 'no findings'
          : '${findings.length} finding${findings.length == 1 ? '' : 's'}';
      heading('${standard.unitLabel} $id — ${titles[id]} ($status)');
      for (final f in findings) {
        final location = f.line == null ? f.path : '${f.path}:${f.line}';
        buffer.writeln(
          markdown
              ? '- `$location` [${f.rule.id} ${f.severity.name}] '
                  '${f.message}'
              : '  $location [${f.rule.id} ${f.severity.name}] '
                  '${f.message}',
        );
      }
      buffer.writeln();
    }

    if (unmapped.isNotEmpty) {
      heading('Not mapped to ${standard.displayName}');
      for (final f in unmapped) {
        buffer.writeln(
          markdown
              ? '- [${f.rule.id}] ${f.message}'
              : '  [${f.rule.id}] ${f.message}',
        );
      }
      buffer.writeln();
    }

    final suppressed = report.baselineSuppressedCount;
    buffer.write(
      '${report.findings.length} finding'
      '${report.findings.length == 1 ? '' : 's'} across '
      '${report.scannedFileCount} scanned file'
      '${report.scannedFileCount == 1 ? '' : 's'}.'
      '${suppressed > 0 ? ' $suppressed baselined hidden.' : ''}',
    );
    return buffer.toString();
  }

  /// Sorts '3.5.1' / 'A.8.24' style ids numerically per segment.
  static int _compareRequirementIds(String a, String b) {
    final aParts = a.split('.');
    final bParts = b.split('.');
    for (var i = 0; i < aParts.length && i < bParts.length; i++) {
      final aNum = int.tryParse(aParts[i]);
      final bNum = int.tryParse(bParts[i]);
      final cmp = aNum != null && bNum != null
          ? aNum.compareTo(bNum)
          : aParts[i].compareTo(bParts[i]);
      if (cmp != 0) return cmp;
    }
    return aParts.length.compareTo(bParts.length);
  }
}
