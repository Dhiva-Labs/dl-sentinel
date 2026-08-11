/**
 * A second well-formed plugin with its own id, used to prove that several
 * plugins load and register in flag order (after the built-ins).
 */
export default {
  id: 'fixture-plugin-two',
  name: 'Second Fixture Plugin',
  version: '0.2.0',
  categories: ['config'],
  supportedFiles: ['**/*.ini'],
  rules: [
    {
      id: 'FX101',
      title: 'Second fixture rule',
      severity: 'low',
      defaultConfidence: 'low',
      category: 'config',
      description: 'Exists only so a second plugin contributes a distinct rule.',
      recommendation: 'Nothing to do; this rule exists only to exercise plugin loading.',
      references: [],
    },
  ],
  scan: async () => [],
};
