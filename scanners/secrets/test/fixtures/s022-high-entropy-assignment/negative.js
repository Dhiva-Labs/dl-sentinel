// Negative fixture: credential-named identifiers that hold no credential, and
// high-entropy literals whose identifiers are not credential names.
const sessionSecret = process.env.SESSION_SECRET;
const apiKey = 'YOUR_API_KEY_HERE_0000';
const authToken = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const secretPath = './config/session-secret.pem';
const authorName = 'Alexandra Fixtureson';
const buildIdentifier = 'qP7vLm2ZrK9tFAKEbXw4Nc8Jd';
module.exports = { sessionSecret, apiKey, authToken, secretPath, authorName, buildIdentifier };
