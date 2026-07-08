import 'package:xml/xml.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'native_config.dart';

/// SD005 — cleartext traffic enabled in native config:
/// `android:usesCleartextTraffic="true"` in the Android manifest or
/// `NSAllowsArbitraryLoads` in Info.plist.
class CleartextConfigRule extends TextRule {
  const CleartextConfigRule();

  @override
  String get id => 'SD005';

  @override
  String get title => 'Cleartext traffic enabled in native config';

  @override
  Severity get severity => Severity.high;

  @override
  String get description =>
      'usesCleartextTraffic and NSAllowsArbitraryLoads disable the '
      'platform-level ban on unencrypted HTTP for the whole app.';

  @override
  String get masvs => 'MASVS-NETWORK-1';

  @override
  int get cwe => 319;

  @override
  bool appliesTo(ScanFile file) =>
      file.kind == FileKind.androidManifest || file.kind == FileKind.infoPlist;

  @override
  List<Finding> check(ScanFile file) {
    final doc = tryParseXml(file.content);
    if (doc == null) return const [];

    switch (file.kind) {
      case FileKind.androidManifest:
        if (isNonReleaseManifest(file.path)) return const [];
        return _checkManifest(file, doc);
      case FileKind.infoPlist:
        return _checkPlist(file, doc);
      default:
        return const [];
    }
  }

  List<Finding> _checkManifest(ScanFile file, XmlDocument doc) {
    const attribute = 'android:usesCleartextTraffic';
    for (final application in doc.findAllElements('application')) {
      if (application.getAttribute(attribute) != 'true') continue;
      final position = locate(file, attribute);
      return [
        Finding(
          rule: this,
          path: file.path,
          line: position?.line,
          column: position?.column,
          message: '$attribute="true" allows unencrypted HTTP app-wide. '
              'Remove it or scope exceptions in a '
              'networkSecurityConfig.',
        ),
      ];
    }
    return const [];
  }

  List<Finding> _checkPlist(ScanFile file, XmlDocument doc) {
    const key = 'NSAllowsArbitraryLoads';
    if (!plistBoolIsTrue(doc, key)) return const [];
    final position = locate(file, key);
    return [
      Finding(
        rule: this,
        path: file.path,
        line: position?.line,
        column: position?.column,
        message: '$key disables App Transport Security app-wide. Remove it '
            'or use per-domain NSExceptionDomains.',
      ),
    ];
  }
}
