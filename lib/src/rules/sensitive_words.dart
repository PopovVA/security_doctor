/// Words that mark an identifier or preference key as sensitive.
/// Matched against whole words split from the name, never substrings —
/// 'authorName' does not contain the word 'auth'.
const Set<String> sensitiveWords = {
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'jwt',
  'credential',
  'credentials',
  'apikey',
  'auth',
  'session',
  'pin',
  'cvv',
  'ssn',
};

/// Splits camelCase, snake_case and kebab-case identifiers into
/// lowercase words.
List<String> splitIdentifierWords(String identifier) {
  final withBreaks = identifier.replaceAllMapped(
    RegExp('([a-z0-9])([A-Z])'),
    (m) => '${m[1]} ${m[2]}',
  );
  return withBreaks
      .split(RegExp('[^A-Za-z0-9]+'))
      .where((w) => w.isNotEmpty)
      .map((w) => w.toLowerCase())
      .toList();
}

/// Whether an identifier or key is sensitive: any of its words — or any
/// adjacent word pair, so 'apiKey' can match 'apikey' — is in
/// [sensitiveWords].
bool isSensitiveName(String name) {
  final words = splitIdentifierWords(name);
  final pairs = [
    for (var i = 0; i + 1 < words.length; i++) words[i] + words[i + 1],
  ];
  return words.followedBy(pairs).any(sensitiveWords.contains);
}
