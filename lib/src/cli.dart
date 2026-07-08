import 'dart:io';

import 'package:args/args.dart';

/// Exit codes, matching the pubspec_doctor convention:
/// 0 — no findings at or above the threshold, 1 — findings found,
/// 2 — usage or runtime error.
Future<int> run(List<String> arguments) async {
  final parser = ArgParser()
    ..addOption(
      'path',
      abbr: 'p',
      defaultsTo: '.',
      help: 'Path to the project root (where pubspec.yaml lives).',
    )
    ..addFlag('json', negatable: false, help: 'Output the report as JSON.')
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Show this usage information.',
    );

  final ArgResults args;
  try {
    args = parser.parse(arguments);
  } on FormatException catch (e) {
    stderr
      ..writeln(e.message)
      ..writeln()
      ..writeln(_usage(parser));
    return 2;
  }

  if (args.flag('help')) {
    stdout.writeln(_usage(parser));
    return 0;
  }

  final root = Directory(args.option('path')!);
  if (!File('${root.path}${Platform.pathSeparator}pubspec.yaml').existsSync()) {
    stderr.writeln('No pubspec.yaml found at ${root.path}');
    return 2;
  }

  // The rule engine lands in the next milestone; the CLI contract
  // (flags, exit codes) is stable from day one.
  stdout.writeln('security_doctor: no rules registered yet.');
  return 0;
}

String _usage(ArgParser parser) =>
    'Security audit for Flutter and Dart apps (OWASP MASVS, CWE).\n\n'
    'Usage: security_doctor [options]\n\n'
    '${parser.usage}';
