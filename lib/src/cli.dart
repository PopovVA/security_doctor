import 'dart:io';

import 'package:args/args.dart';

import 'baseline.dart';
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
    ..addOption(
      'format',
      abbr: 'f',
      allowed: ['console', 'json', 'markdown', 'sarif'],
      defaultsTo: 'console',
      help: 'Report format. sarif suits GitHub Code Scanning uploads.',
    )
    ..addFlag(
      'json',
      negatable: false,
      help: 'Shorthand for --format json.',
    )
    ..addFlag(
      'write-baseline',
      negatable: false,
      help: 'Snapshot all current findings into the baseline file so '
          'only new findings fail future runs.',
    )
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

  final baselineFile = File(
    '${root.path}/${config.baselinePath ?? Baseline.defaultFileName}',
  );

  if (args.flag('write-baseline')) {
    final report =
        SecurityAuditor(rules: builtInRules, config: config).audit(root);
    baselineFile.writeAsStringSync(
      '${Baseline.fromFindings(report.findings).toJsonString()}\n',
    );
    stdout.writeln(
      'Baseline written: ${report.findings.length} finding'
      '${report.findings.length == 1 ? '' : 's'} → ${baselineFile.path}',
    );
    return 0;
  }

  Baseline? baseline;
  if (baselineFile.existsSync()) {
    try {
      baseline = Baseline.load(baselineFile);
    } on FormatException catch (e) {
      stderr.writeln('${baselineFile.path}: ${e.message}');
      return 2;
    }
  } else if (config.baselinePath != null) {
    // An explicitly configured baseline that is missing is an error; a
    // missing default file just means "no baseline yet".
    stderr.writeln('Baseline file not found: ${baselineFile.path}');
    return 2;
  }

  final report = SecurityAuditor(
    rules: builtInRules,
    config: config,
    baseline: baseline,
  ).audit(root);
  final format = args.flag('json') ? 'json' : args.option('format')!;
  final Reporter reporter = switch (format) {
    'json' => const JsonReporter(),
    'markdown' => const MarkdownReporter(),
    'sarif' => const SarifReporter(),
    _ => const ConsoleReporter(),
  };
  stdout.writeln(reporter.format(report));
  return report.fails ? 1 : 0;
}

String _usage(ArgParser parser) =>
    'Security audit for Flutter and Dart apps (OWASP MASVS, CWE).\n\n'
    'Usage: security_doctor [options]\n\n'
    '${parser.usage}';
