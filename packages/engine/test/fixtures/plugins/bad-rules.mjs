/** Invalid: `rules[0].severity` is not one of the Severity values. */
export default {
  id: 'bad-rules',
  name: 'Bad Rules Plugin',
  version: '0.0.1',
  categories: ['other'],
  supportedFiles: [],
  rules: [
    {
      id: 'BR001',
      title: 'Rule with an invented severity',
      severity: 'urgent',
      defaultConfidence: 'medium',
      category: 'other',
      description: 'The severity above is not part of the Severity union.',
      recommendation: 'Use one of critical, high, medium, low, info.',
    },
  ],
  scan: async () => [],
};
