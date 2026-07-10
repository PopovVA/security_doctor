/// The kinds of files the engine reads. Anything else is skipped without
/// being read from disk.
enum FileKind {
  dart,
  pubspec,
  androidManifest,
  infoPlist,
  gradle,
  entitlements
}

/// One file handed to rules: relative path, contents and classified kind.
class ScanFile {
  ScanFile({required this.path, required this.content, required this.kind});

  /// Path relative to the audited project root, with forward slashes.
  final String path;

  final String content;

  final FileKind kind;

  List<int>? _lineStarts;

  /// Classifies a relative path, or returns null for files no rule reads.
  static FileKind? classify(String path) {
    final name = path.split('/').last;
    if (name == 'pubspec.yaml' || name == 'pubspec.lock') {
      return FileKind.pubspec;
    }
    if (name == 'AndroidManifest.xml') return FileKind.androidManifest;
    if (name.endsWith('.dart')) return FileKind.dart;
    if (name.endsWith('.plist')) return FileKind.infoPlist;
    if (name.endsWith('.gradle') || name.endsWith('.gradle.kts')) {
      return FileKind.gradle;
    }
    if (name.endsWith('.entitlements')) return FileKind.entitlements;
    return null;
  }

  /// Translates a character [offset] in [content] into a 1-based
  /// line/column pair, so text rules can report precise locations.
  ({int line, int column}) positionOf(int offset) {
    final starts = _lineStarts ??= _computeLineStarts();
    var low = 0;
    var high = starts.length - 1;
    while (low < high) {
      final mid = (low + high + 1) >> 1;
      if (starts[mid] <= offset) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    return (line: low + 1, column: offset - starts[low] + 1);
  }

  /// The text of a 1-based [line], without the trailing newline.
  String lineText(int line) {
    final starts = _lineStarts ??= _computeLineStarts();
    if (line < 1 || line > starts.length) return '';
    final start = starts[line - 1];
    var end = line < starts.length ? starts[line] : content.length;
    while (end > start &&
        (content.codeUnitAt(end - 1) == 0x0A ||
            content.codeUnitAt(end - 1) == 0x0D)) {
      end--;
    }
    return content.substring(start, end);
  }

  List<int> _computeLineStarts() {
    final starts = [0];
    for (var i = 0; i < content.length; i++) {
      if (content.codeUnitAt(i) == 0x0A) starts.add(i + 1);
    }
    return starts;
  }
}
