// Deliberately vulnerable fixture: secrets written to SharedPreferences.
Future<void> persist(dynamic prefs, String token, String password) async {
  await prefs.setString('authToken', token);
  await prefs.setString('user_password', password);
  await prefs.setStringList('session_tokens', [token]);
  await prefs.setString('apiKey', token);
  await prefs.setString('card_pin', password);
}
