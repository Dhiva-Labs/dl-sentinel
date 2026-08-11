/** Invalid: a plugin module must default-export its ScannerPlugin. */
export const plugin = {
  id: 'no-default',
  name: 'No Default Export',
  version: '0.0.1',
  categories: ['other'],
  supportedFiles: [],
  rules: [],
  scan: async () => [],
};
