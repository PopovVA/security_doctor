// Intentionally vulnerable demo code. Every SD00x Dart rule fires in
// this file; the native config rules fire on the manifest and plist
// next to it. Do not copy anything from here into a real app.
import 'dart:developer';

// SD001 — hardcoded secrets: a known credential format and a
// high-entropy literal bound to a secret-named variable.
const awsAccessKey = 'AKIAIOSFODNN7RE4LKEY';
const dbPassword = 'q7RkX2mV9tLpZ4wY8bNcE3hJ';

// SD002 — cleartext HTTP endpoint.
const apiBase = 'http://api.example.com/v1';

Future<void> persistSession(dynamic prefs, String authToken) async {
  // SD003 — a sensitive value stored in SharedPreferences.
  await prefs.setString('authToken', authToken);
}

void weakHash(dynamic md5, List<int> payload) {
  // SD004 — MD5 is broken; so is AES in ECB mode.
  md5.convert(payload);
  const transformation = 'AES/ECB/PKCS5Padding';
  log(transformation);
}

void debugDump(String password) {
  // SD008 — credentials in log output.
  print('password: $password');
}
