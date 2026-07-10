import 'rule.dart';
import 'rules/sd001_hardcoded_secrets.dart';
import 'rules/sd002_cleartext_http.dart';
import 'rules/sd003_shared_preferences.dart';
import 'rules/sd004_weak_crypto.dart';
import 'rules/sd005_cleartext_config.dart';
import 'rules/sd006_debug_flags.dart';
import 'rules/sd007_dangerous_permissions.dart';
import 'rules/sd008_sensitive_logging.dart';
import 'rules/sd009_gradle_release_config.dart';
import 'rules/sd010_debuggable_entitlements.dart';

/// Built-in rules in id order.
const List<Rule> builtInRules = [
  HardcodedSecretsRule(),
  CleartextHttpRule(),
  SharedPreferencesRule(),
  WeakCryptoRule(),
  CleartextConfigRule(),
  DebugFlagsRule(),
  DangerousPermissionsRule(),
  SensitiveLoggingRule(),
  GradleReleaseConfigRule(),
  DebuggableEntitlementsRule(),
];
