import 'dart:io';

import 'package:args/args.dart';

import 'config.dart';
import 'engine.dart';
import 'registry.dart';
import 'reporter.dart';
import 'rule.dart';

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
    ..addOption(
      'fail-on',
      allowed: Severity.values.map((s) => s.name),
      help: 'Lowest severity that makes the run exit 1. '
          'Overrides fail_on from security_audit.yaml.',
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

  AuditConfig config;
  try {
    config = AuditConfig.load(root);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    return 2;
  }
  final failOn = args.option('fail-on');
  if (failOn != null) {
    config = config.copyWith(failOn: Severity.parse(failOn));
  }

  final report =
      SecurityAuditor(rules: builtInRules, config: config).audit(root);
  final reporter = args.flag('json')
      ? const JsonReporter() as Reporter
      : const ConsoleReporter();
  stdout.writeln(reporter.format(report));
  return report.fails ? 1 : 0;
}

String _usage(ArgParser parser) =>
    'Security audit for Flutter and Dart apps (OWASP MASVS, CWE).\n\n'
    'Usage: security_doctor [options]\n\n'
    '${parser.usage}';
