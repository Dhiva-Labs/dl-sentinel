/**
 * A well-formed third-party scanner plugin, used as the fixture for plugin
 * loading across the engine, CLI and API test suites.
 *
 * Deliberately dependency-free plain ESM: it is imported by the real loader at
 * runtime (not through the test bundler's aliases), so it must run exactly as a
 * published plugin package would, without needing the workspace to be built.
 * That is also why the finding is assembled by hand instead of via
 * `createFinding` from `@dl-sentinel/core` — its `id` is a fixed string, which
 * keeps findings deterministic across runs.
 */

/** @type {import('@dl-sentinel/core').RuleMeta[]} */
const rules = [
  {
    id: 'FX001',
    title: 'Fixture rule fired',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'other',
    description: 'Every text file the fixture plugin receives produces this finding.',
    recommendation: 'Nothing to do; this rule exists only to exercise plugin loading.',
    references: [],
  },
];

export default {
  id: 'fixture-plugin',
  name: 'Fixture Plugin',
  version: '1.2.3',
  categories: ['other'],
  supportedFiles: ['**/*.txt'],
  rules,
  async scan(context) {
    return context.files.map((file) => ({
      id: `fixture-plugin:${file.relPath}`,
      ruleId: 'FX001',
      title: 'Fixture rule fired',
      description: 'The fixture plugin reports every text file it is given.',
      severity: 'high',
      confidence: 'medium',
      category: 'other',
      file: file.relPath,
      line: 1,
      evidence: 'fixture finding (no file contents are read)',
      recommendation: 'Nothing to do; this rule exists only to exercise plugin loading.',
      references: [],
      scanner: 'fixture-plugin',
    }));
  },
};
