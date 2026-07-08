import 'dart:io';

import 'package:security_doctor/security_doctor.dart';

/// Programmatic usage. Most people want the CLI instead:
///
/// ```sh
/// dart pub global activate security_doctor
/// security_doctor
/// ```
///
/// This directory will grow an intentionally vulnerable mini app used to
/// demonstrate every rule.
Future<void> main() async {
  exitCode = await run(['--path', '.']);
}
