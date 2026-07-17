import 'package:xml/xml.dart';

import '../scan_file.dart';

/// Shared helpers for rules that read native config files
/// (AndroidManifest.xml, Info.plist and friends).

/// Parses XML, or returns null: a config that does not parse gives a
/// rule nothing reliable to assert, so rules stay quiet on it.
XmlDocument? tryParseXml(String content) {
  try {
    return XmlDocument.parse(content);
  } on XmlException {
    return null;
  }
}

/// Whether an Android manifest belongs to a non-release source set
/// (`src/debug/`, `src/profile/`, test sets). Debug manifests routinely
/// and legitimately enable cleartext or debugging — flagging them is
/// pure noise.
bool isNonReleaseManifest(String path) => const [
      '/src/debug/',
      '/src/profile/',
      '/src/androidTest/',
      '/src/test/',
    ].any(path.contains);

/// Finds a `<key>name</key><true/>` pair anywhere in a plist document.
bool plistBoolIsTrue(XmlDocument doc, String name) {
  for (final key in doc.findAllElements('key')) {
    if (key.innerText.trim() != name) continue;
    final element = _nextElementSibling(key);
    if (element != null && element.name.local == 'true') return true;
  }
  return false;
}

XmlElement? _nextElementSibling(XmlElement element) {
  final siblings = element.parent?.children;
  if (siblings == null) return null;
  var seen = false;
  for (final node in siblings) {
    if (identical(node, element)) {
      seen = true;
      continue;
    }
    if (seen && node is XmlElement) return node;
  }
  return null;
}

/// Locates [needle] in the file for a line/column to report. The XML
/// parse established the semantics; this only recovers a position.
/// Matches inside `<!-- ... -->` are skipped, so a commented-out copy
/// of a setting earlier in the file cannot steal the reported line
/// from the active one.
({int line, int column})? locate(ScanFile file, String needle) {
  var offset = file.content.indexOf(needle);
  while (offset != -1) {
    if (!_insideComment(file.content, offset)) return file.positionOf(offset);
    offset = file.content.indexOf(needle, offset + needle.length);
  }
  return null;
}

/// Whether [offset] falls inside an XML comment — the nearest `<!--`
/// before it is still unclosed. Valid XML forbids `--` within a
/// comment, so comparing the last two markers is enough.
bool _insideComment(String content, int offset) {
  final open = content.lastIndexOf('<!--', offset);
  if (open == -1) return false;
  return content.lastIndexOf('-->', offset) < open;
}
