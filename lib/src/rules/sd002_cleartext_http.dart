import 'package:analyzer/dart/ast/ast.dart';

import '../rule.dart';
import '../scan_file.dart';
import 'literals.dart';

/// SD002 — cleartext `http://` URLs in Dart code.
class CleartextHttpRule extends DartRule {
  const CleartextHttpRule();

  @override
  String get id => 'SD002';

  @override
  String get title => 'Cleartext http:// URL';

  @override
  String get description =>
      'Traffic over http:// can be read and modified in transit. '
      'Use https:// for anything that leaves the device.';

  @override
  Severity get severity => Severity.medium;

  @override
  String get masvs => 'MASVS-NETWORK-1';

  @override
  int get cwe => 319;

  static final _httpUrl = RegExp('^http://', caseSensitive: false);

  static final _validHost = RegExp(r'^[a-z0-9.\-]+$|^\[[0-9a-f:]+\]$');

  /// Local-only hosts: cleartext never leaves the machine or emulator.
  static const _localHosts = {
    'localhost',
    '127.0.0.1',
    '10.0.2.2',
    '0.0.0.0',
    '[::1]'
  };

  /// XML namespaces and schema identifiers are opaque ids, not requests.
  static const _identifierPrefixes = [
    'http://www.w3.org/',
    'http://schemas.',
    'http://xmlns.',
    'http://ns.adobe.com/',
    'http://purl.org/',
  ];

  @override
  List<Finding> check(ScanFile file, CompilationUnit unit) {
    final findings = <Finding>[];
    for (final literal in collectStringLiterals(unit)) {
      final value = literal.value;
      if (!_httpUrl.hasMatch(value)) continue;
      if (_identifierPrefixes.any(value.toLowerCase().startsWith)) continue;
      final host = _hostOf(value);
      // Prose that merely starts with 'http://' is not a request. For a
      // partial value (constant prefix of an interpolation or concat)
      // an invalid/empty host means the host is computed at runtime —
      // unknowable, so stay quiet.
      if (!_validHost.hasMatch(host)) continue;
      if (_localHosts.contains(host)) continue;
      final position = file.positionOf(literal.offset);
      final shown = literal.isComplete ? value : '$value…';
      findings.add(
        Finding(
          rule: this,
          path: file.path,
          line: position.line,
          column: position.column,
          message: "Cleartext URL '$shown'. Use https:// instead.",
        ),
      );
    }
    return findings;
  }

  static String _hostOf(String url) {
    var rest = url.substring('http://'.length);
    for (final stop in ['/', '?', '#']) {
      final index = rest.indexOf(stop);
      if (index != -1) rest = rest.substring(0, index);
    }
    // Strip credentials and port; keep bracketed IPv6 intact.
    final at = rest.lastIndexOf('@');
    if (at != -1) rest = rest.substring(at + 1);
    if (!rest.startsWith('[')) {
      final colon = rest.indexOf(':');
      if (colon != -1) rest = rest.substring(0, colon);
    } else {
      final bracket = rest.indexOf(']');
      if (bracket != -1) rest = rest.substring(0, bracket + 1);
    }
    return rest.toLowerCase();
  }
}
