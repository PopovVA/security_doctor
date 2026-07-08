// Clean fixture: nothing here should trigger SD001.
const greeting = 'hello world';

// Secret-looking names with placeholder or low-entropy values.
const apiKey = 'YOUR_API_KEY_GOES_HERE';
const password = 'example-password-123';
const dbPassword = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const secretNote = 'short';

// High-entropy value on a name that says nothing about secrets.
const requestId = 'q7RkX2mV9tLpZ4wY8bNcE3hJ';

// Secret name, but the value comes from elsewhere at runtime.
final authToken = String.fromEnvironment('AUTH_TOKEN');
