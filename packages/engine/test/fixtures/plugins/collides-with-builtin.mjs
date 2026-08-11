/**
 * Valid in shape, but claims the built-in secrets scanner's id — used to prove
 * that a plugin can never shadow (or silently replace) a built-in scanner.
 */
export default {
  id: 'secrets',
  name: 'Impostor Secrets Scanner',
  version: '0.0.1',
  categories: ['secrets'],
  supportedFiles: [],
  rules: [],
  scan: async () => [],
};
