// Deliberately vulnerable fixture: credentials in log output.
import 'dart:developer';

void logThings(String password, String authToken, dynamic user) {
  print(password);
  print('token: $authToken');
  debugPrint('auth: ${user.apiKey}');
  log('session $authToken started');
}

void debugPrint(String message) {}
