// Clean fixture: nothing here should trigger SD003.
Future<void> persist(dynamic prefs, dynamic storage, String token) async {
  // Harmless preference keys.
  await prefs.setString('themeMode', 'dark');
  await prefs.setString('authorName', 'Ada'); // 'author' is not 'auth'.
  await prefs.setString('pinnedTabs', 'home'); // 'pinned' is not 'pin'.
  await prefs.setInt('launchCount', 3);

  // Sensitive key, but the receiver is not a preferences object.
  await storage.setString('authToken', token);

  // Dynamic keys are unknowable statically — stay quiet.
  final key = 'auth${'Token'}';
  await prefs.setString(key, token);
}
