// Deliberately vulnerable fixture: hardcoded credentials.
//
// Formats that GitHub push protection would reject as real secrets
// (Stripe, Slack, GitHub tokens) are exercised in sd001_test.dart with
// runtime-assembled sources instead of committed literals.
const awsKey = 'AKIAIOSFODNN7RE4LKEY';
const googleKey = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY';
const pem = '-----BEGIN RSA PRIVATE KEY-----';

// High-entropy literal bound to a secret-looking name.
const dbPassword = 'q7RkX2mV9tLpZ4wY8bNcE3hJ';
final apiKey = 'f3A9zQ1xW5vB7nM2kD6gT8yU';

// Secrets hidden in collection literals, defaults and call sites.
final config = {
  'dbPassword': 'p2Xw8kQ5rT7mB4nV9cZ1hL3j',
  authToken: 'u5Rp9zW3xK7qM2vT8bN4cJ6h',
};

void connect({String apiKey = 'j9Kt4wR2xQ8mZ6vB3nC7pF5d'}) {}

void run() {
  connect(apiKey: 'e8Hs3nD6wJ1uP9xF4aG7kM2q');
}
