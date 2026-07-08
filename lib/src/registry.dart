import 'rule.dart';
import 'rules/sd001_hardcoded_secrets.dart';
import 'rules/sd002_cleartext_http.dart';
import 'rules/sd003_shared_preferences.dart';
import 'rules/sd004_weak_crypto.dart';
import 'rules/sd005_cleartext_config.dart';
import 'rules/sd006_debug_flags.dart';
import 'rules/sd007_dangerous_permissions.dart';

/// Built-in rules in id order. SD008 lands in the next milestone.
const List<Rule> builtInRules = [
  HardcodedSecretsRule(),
  CleartextHttpRule(),
  SharedPreferencesRule(),
  WeakCryptoRule(),
  CleartextConfigRule(),
  DebugFlagsRule(),
  DangerousPermissionsRule(),
];
