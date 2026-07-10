import '../rule.dart';
import '../scan_file.dart';
import 'native_config.dart';

/// SD010 — `get-task-allow` enabled in iOS/macOS entitlements.
///
/// With this entitlement a debugger can attach to the production app.
/// Debug-profile entitlements files (e.g. Flutter's
/// DebugProfile.entitlements on macOS) legitimately carry it, so
/// anything with "debug" in the file name is skipped.
class DebuggableEntitlementsRule extends TextRule {
  const DebuggableEntitlementsRule();

  @override
  String get id => 'SD010';

  @override
  String get title => 'get-task-allow enabled in entitlements';

  @override
  Severity get severity => Severity.high;

  @override
  String get description =>
      'get-task-allow lets a debugger attach to the shipped app, '
      'exposing memory and control flow. Release entitlements must not '
      'carry it.';

  @override
  String get masvs => 'MASVS-RESILIENCE-2';

  @override
  int get cwe => 489;

  @override
  bool appliesTo(ScanFile file) =>
      file.kind == FileKind.entitlements &&
      !file.path.split('/').last.toLowerCase().contains('debug');

  @override
  List<Finding> check(ScanFile file) {
    final doc = tryParseXml(file.content);
    if (doc == null) return const [];
    if (!plistBoolIsTrue(doc, 'get-task-allow')) return const [];
    final position = locate(file, 'get-task-allow');
    return [
      Finding(
        rule: this,
        path: file.path,
        line: position?.line,
        column: position?.column,
        message: 'get-task-allow is true: a debugger can attach to this '
            'build. Remove it from release entitlements.',
      ),
    ];
  }
}
