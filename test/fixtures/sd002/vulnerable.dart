// Deliberately vulnerable fixture: cleartext URLs.
const api = 'http://api.example.com/v1/users';
const withPort = 'http://internal.example.com:8080/health';
const uppercase = 'HTTP://api.example.com/login';

// The host is known even though the tail is computed.
const adjacent = 'http://'
    'api.example.com';
String withPath(String path) => 'http://api.example.com/' + path;
String withEnv(Object env) => 'http://api.$env.example.com';
