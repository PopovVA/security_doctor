import 'package:xml/xml.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'native_config.dart';

/// SD007 — dangerous Android permissions declared in the manifest.
///
/// A static tool cannot know whether CAMERA is excessive for this
/// particular app, so the rule is informational by design: severity is
/// low and every message asks for a review rather than asserting a bug.
class DangerousPermissionsRule extends TextRule {
  const DangerousPermissionsRule();

  @override
  String get id => 'SD007';

  @override
  String get title => 'Dangerous permission declared';

  @override
  Severity get severity => Severity.low;

  @override
  String get description =>
      'Runtime ("dangerous") permissions widen the attack surface and '
      'trigger store review questions. Each one declared should be '
      'demonstrably needed.';

  @override
  String get masvs => 'MASVS-PLATFORM-1';

  @override
  int get cwe => 250;

  /// Android permissions with a `dangerous` protection level (plus the
  /// special-access MANAGE_EXTERNAL_STORAGE, SYSTEM_ALERT_WINDOW and
  /// REQUEST_INSTALL_PACKAGES, which reviewers treat the same way).
  /// POST_NOTIFICATIONS is deliberately absent: nearly every app
  /// declares it, so flagging it is noise.
  static const dangerous = {
    'ACCEPT_HANDOVER',
    'ACCESS_BACKGROUND_LOCATION',
    'ACCESS_COARSE_LOCATION',
    'ACCESS_FINE_LOCATION',
    'ACCESS_MEDIA_LOCATION',
    'ACTIVITY_RECOGNITION',
    'ADD_VOICEMAIL',
    'ANSWER_PHONE_CALLS',
    'BLUETOOTH_ADVERTISE',
    'BLUETOOTH_CONNECT',
    'BLUETOOTH_SCAN',
    'BODY_SENSORS',
    'BODY_SENSORS_BACKGROUND',
    'CALL_PHONE',
    'CAMERA',
    'GET_ACCOUNTS',
    'MANAGE_EXTERNAL_STORAGE',
    'NEARBY_WIFI_DEVICES',
    'PROCESS_OUTGOING_CALLS',
    'READ_CALENDAR',
    'READ_CALL_LOG',
    'READ_CONTACTS',
    'READ_EXTERNAL_STORAGE',
    'READ_MEDIA_AUDIO',
    'READ_MEDIA_IMAGES',
    'READ_MEDIA_VIDEO',
    'READ_PHONE_NUMBERS',
    'READ_PHONE_STATE',
    'READ_SMS',
    'RECEIVE_MMS',
    'RECEIVE_SMS',
    'RECEIVE_WAP_PUSH',
    'RECORD_AUDIO',
    'REQUEST_INSTALL_PACKAGES',
    'SEND_SMS',
    'SYSTEM_ALERT_WINDOW',
    'USE_SIP',
    'UWB_RANGING',
    'WRITE_CALENDAR',
    'WRITE_CALL_LOG',
    'WRITE_CONTACTS',
    'WRITE_EXTERNAL_STORAGE',
  };

  static const _prefix = 'android.permission.';

  @override
  bool appliesTo(ScanFile file) => file.kind == FileKind.androidManifest;

  @override
  List<Finding> check(ScanFile file) {
    if (isNonReleaseManifest(file.path)) return const [];
    final doc = tryParseXml(file.content);
    if (doc == null) return const [];

    final findings = <Finding>[];
    for (final tag in ['uses-permission', 'uses-permission-sdk-23']) {
      for (final element in doc.findAllElements(tag)) {
        final name = element.getAttribute('android:name');
        if (name == null || !name.startsWith(_prefix)) continue;
        final permission = name.substring(_prefix.length);
        if (!dangerous.contains(permission)) continue;
        final position = locate(file, name);
        findings.add(
          Finding(
            rule: this,
            path: file.path,
            line: position?.line,
            column: position?.column,
            message: "Dangerous permission '$permission' is declared — "
                'verify the app actually needs it.',
          ),
        );
      }
    }
    return findings;
  }
}
