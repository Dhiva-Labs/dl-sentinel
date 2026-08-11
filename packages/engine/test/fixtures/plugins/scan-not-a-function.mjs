/** Invalid: `scan` must be a function. */
export default {
  id: 'scan-not-a-function',
  name: 'Unscannable Plugin',
  version: '0.0.1',
  categories: ['other'],
  supportedFiles: [],
  rules: [],
  scan: 'definitely not a function',
};
