// Clean fixture: nothing here should trigger SD008.
import 'dart:developer';

void logThings(String authorName, int pinnedTabs, String password) {
  print('hello');
  print('author: $authorName');
  print('pinned: $pinnedTabs');
  log('startup complete');

  // Sensitive identifier used, but not in a logging call.
  final masked = password.length;
  print('length: $masked');
}
