/// Security audit for Flutter and Dart apps: OWASP MASVS and CWE mapped
/// checks for Dart code, configs and native manifests.
library;

export 'src/baseline.dart';
export 'src/cli.dart';
export 'src/compliance.dart';
export 'src/config.dart';
export 'src/engine.dart';
export 'src/registry.dart';
export 'src/reporter.dart';
export 'src/rule.dart';
export 'src/rules/sd001_hardcoded_secrets.dart';
export 'src/rules/sd002_cleartext_http.dart';
export 'src/rules/sd003_shared_preferences.dart';
export 'src/rules/sd004_weak_crypto.dart';
export 'src/rules/sd005_cleartext_config.dart';
export 'src/rules/sd006_debug_flags.dart';
export 'src/rules/sd007_dangerous_permissions.dart';
export 'src/rules/sd008_sensitive_logging.dart';
export 'src/rules/sd009_gradle_release_config.dart';
export 'src/rules/sd010_debuggable_entitlements.dart';
export 'src/rules/sensitive_words.dart';
export 'src/scan_file.dart';
