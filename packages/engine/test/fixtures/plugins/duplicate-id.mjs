/**
 * Valid on its own, but claims the same id as `valid.mjs` — used to prove that
 * loading two plugins with one id is rejected.
 */
export default {
  id: 'fixture-plugin',
  name: 'Fixture Plugin (impostor)',
  version: '9.9.9',
  categories: ['other'],
  supportedFiles: [],
  rules: [],
  scan: async () => [],
};
