// Clean fixture: nothing here should trigger SD002.
const secure = 'https://api.example.com/v1/users';
const local = 'http://localhost:8080/api';
const loopback = 'http://127.0.0.1/health';
const emulatorHost = 'http://10.0.2.2:3000/api';
const ipv6Loopback = 'http://[::1]:8080/';
const xmlNamespace = 'http://www.w3.org/2000/svg';
const androidSchema = 'http://schemas.android.com/apk/res/android';
const notAUrl = 'http:// is insecure, prefer https://';

// The host is computed at runtime — unknowable, so no finding.
String dynamicHost(String host) => 'http://' + host;
String localWithPort(int port) => 'http://localhost:$port/api';
