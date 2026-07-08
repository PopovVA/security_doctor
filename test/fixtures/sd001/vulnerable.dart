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
