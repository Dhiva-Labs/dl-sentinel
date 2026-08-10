import { describe, expect, it } from 'vitest';
import defaultExport, { infraScanner } from '../src/index.js';

describe('infraScanner plugin shape', () => {
  it('exposes the plugin as both the default export and the named export', () => {
    expect(defaultExport).toBe(infraScanner);
  });

  it('declares a stable id, name, version, and categories', () => {
    expect(infraScanner.id).toBe('infra');
    expect(infraScanner.name).toBeTruthy();
    expect(infraScanner.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(infraScanner.categories).toEqual(expect.arrayContaining(['docker', 'infrastructure']));
  });

  it('declares every I00x-I03x rule with no gaps or duplicates', () => {
    const ids = infraScanner.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length); // no duplicates

    const expected = [
      'I001',
      'I002',
      'I003',
      'I004',
      'I005',
      'I006',
      'I010',
      'I011',
      'I012',
      'I013',
      'I014',
      'I015',
      'I016',
      'I020',
      'I021',
      'I022',
      'I023',
      'I024',
      'I025',
      'I026',
      'I027',
      'I028',
      'I030',
      'I031',
      'I032',
      'I033',
    ];
    expect(ids.sort()).toEqual(expected.sort());
  });

  it('every rule has non-empty title/description/recommendation and a valid category', () => {
    for (const rule of infraScanner.rules) {
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.recommendation.length).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
      expect(['high', 'medium', 'low']).toContain(rule.defaultConfidence);
    }
  });

  it('categorizes Dockerfile/compose rules as docker, k8s/terraform rules as infrastructure', () => {
    const byId = new Map(infraScanner.rules.map((r) => [r.id, r]));
    for (const id of [
      'I001',
      'I002',
      'I003',
      'I004',
      'I005',
      'I006',
      'I010',
      'I011',
      'I012',
      'I013',
      'I014',
      'I015',
      'I016',
    ]) {
      expect(byId.get(id)?.category).toBe('docker');
    }
    for (const id of [
      'I020',
      'I021',
      'I022',
      'I023',
      'I024',
      'I025',
      'I026',
      'I027',
      'I028',
      'I030',
      'I031',
      'I032',
      'I033',
    ]) {
      expect(byId.get(id)?.category).toBe('infrastructure');
    }
  });

  it('declares the documented supportedFiles glob patterns', () => {
    expect(infraScanner.supportedFiles).toEqual(
      expect.arrayContaining([
        '**/Dockerfile',
        '**/Dockerfile.*',
        '**/*.dockerfile',
        '**/docker-compose.yml',
        '**/docker-compose.yaml',
        '**/docker-compose.*.yml',
        '**/compose.yml',
        '**/compose.yaml',
        '**/*.yml',
        '**/*.yaml',
        '**/*.tf',
      ]),
    );
  });
});
