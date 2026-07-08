import 'rule.dart';
import 'rules/sd001_hardcoded_secrets.dart';
import 'rules/sd002_cleartext_http.dart';
import 'rules/sd003_shared_preferences.dart';
import 'rules/sd004_weak_crypto.dart';

/// Built-in rules in id order. SD005-SD008 land in later milestones.
const List<Rule> builtInRules = [
  HardcodedSecretsRule(),
  CleartextHttpRule(),
  SharedPreferencesRule(),
  WeakCryptoRule(),
];
