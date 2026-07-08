import 'package:xml/xml.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'native_config.dart';

/// SD006 — debug/backup flags left on in the release Android manifest:
/// `android:debuggable="true"` and `android:allowBackup="true"`.
class DebugFlagsRule extends TextRule {
  const DebugFlagsRule();

  @override
  String get id => 'SD006';

  @override
  String get title => 'Debug or backup flag enabled in the manifest';

  @override
  Severity get severity => Severity.high;

  @override
  String get description =>
      'A debuggable release build exposes the app to runtime '
      'inspection; allowBackup lets adb pull app data off the device.';

  @override
  String get masvs => 'MASVS-RESILIENCE-2';

  @override
  int get cwe => 489;

  static const _flags = {
    'android:debuggable':
        'android:debuggable="true" ships a debuggable build: anyone '
            'with the device can attach a debugger and read app memory.',
    'android:allowBackup':
        'android:allowBackup="true" lets `adb backup` extract app data '
            'from unrooted devices. Disable it or use a backup ruleset.',
  };

  @override
  bool appliesTo(ScanFile file) => file.kind == FileKind.androidManifest;

  @override
  List<Finding> check(ScanFile file) {
    if (isNonReleaseManifest(file.path)) return const [];
    final doc = tryParseXml(file.content);
    if (doc == null) return const [];

    final findings = <Finding>[];
    for (final application in doc.findAllElements('application')) {
      for (final entry in _flags.entries) {
        if (application.getAttribute(entry.key) != 'true') continue;
        final position = locate(file, entry.key);
        findings.add(
          Finding(
            rule: this,
            path: file.path,
            line: position?.line,
            column: position?.column,
            message: entry.value,
          ),
        );
      }
    }
    return findings;
  }
}
