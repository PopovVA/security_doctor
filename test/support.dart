import 'package:security_doctor/security_doctor.dart';

/// A text rule that fires on a marker substring — enough to exercise the
/// engine and reporters without any real rule logic.
class MarkerRule extends TextRule {
  const MarkerRule({
    this.id = 'SD999',
    this.severity = Severity.high,
    this.marker = 'MARKER',
    this.kind = FileKind.dart,
  });

  @override
  final String id;

  @override
  final Severity severity;

  final String marker;
  final FileKind kind;

  @override
  String get title => 'Marker found';

  @override
  String get description => 'Fires wherever the marker substring appears.';

  @override
  String get masvs => 'MASVS-TEST-1';

  @override
  int get cwe => 0;

  @override
  bool appliesTo(ScanFile file) => file.kind == kind;

  @override
  List<Finding> check(ScanFile file) {
    final findings = <Finding>[];
    var offset = file.content.indexOf(marker);
    while (offset != -1) {
      final position = file.positionOf(offset);
      findings.add(
        Finding(
          rule: this,
          path: file.path,
          message: "Found '$marker'.",
          line: position.line,
          column: position.column,
        ),
      );
      offset = file.content.indexOf(marker, offset + 1);
    }
    return findings;
  }
}
