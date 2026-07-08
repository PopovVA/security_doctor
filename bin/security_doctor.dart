import 'dart:io';

import 'package:security_doctor/src/cli.dart';

Future<void> main(List<String> arguments) async {
  exitCode = await run(arguments);
}
