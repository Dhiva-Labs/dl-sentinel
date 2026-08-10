import { describe, expect, it } from 'vitest';
import { OsvDataSource, type FetchFn } from '../../src/datasource/osv.js';

interface FetchCall {
  url: string;
  init?: RequestInit;
}

/** A fake `fetch`: routes /querybatch and /vulns/{id} to canned JSON bodies,
 * and records every call so tests can assert on request shape. Never touches
 * the network. */
function fakeFetch(options: {
  querybatch: unknown;
  vulnsById?: Record<string, unknown>;
  batchStatus?: number;
  detailStatus?: Record<string, number>;
}): { fetchFn: FetchFn; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const fetchFn = (async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ url, init });

    if (url.endsWith('/querybatch')) {
      const status = options.batchStatus ?? 200;
      return new Response(JSON.stringify(options.querybatch), {
        status,
        statusText: status === 200 ? 'OK' : 'Error',
      });
    }

    const match = /\/vulns\/([^/]+)$/.exec(url);
    if (match?.[1] !== undefined) {
      const id = decodeURIComponent(match[1]);
      const status = options.detailStatus?.[id] ?? 200;
      if (status !== 200) {
        return new Response('not found', { status, statusText: 'Not Found' });
      }
      const body = options.vulnsById?.[id];
      return new Response(JSON.stringify(body ?? { id }), { status: 200, statusText: 'OK' });
    }

    throw new Error(`fakeFetch: unexpected URL in test: ${url}`);
  }) as FetchFn;
  return { fetchFn, calls };
}

describe('OsvDataSource', () => {
  it('never calls fetch for an empty package list', async () => {
    const { fetchFn, calls } = fakeFetch({ querybatch: { results: [] } });
    const source = new OsvDataSource(fetchFn);
    expect(await source.query([])).toEqual([]);
    expect(calls.length).toBe(0);
  });

  it('sends one batched POST to /v1/querybatch with {name, ecosystem} only — no version field', async () => {
    const { fetchFn, calls } = fakeFetch({
      querybatch: { results: [{ vulns: [] }, { vulns: [] }] },
    });
    const source = new OsvDataSource(fetchFn);
    await source.query([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
      { ecosystem: 'pip', name: 'django', version: '>=2.0.0' },
    ]);

    expect(calls.length).toBe(1);
    expect(calls[0]?.url).toBe('https://api.osv.dev/v1/querybatch');
    expect(calls[0]?.init?.method).toBe('POST');
    const body = JSON.parse(String(calls[0]?.init?.body)) as unknown;
    expect(body).toEqual({
      queries: [
        { package: { name: 'lodash', ecosystem: 'npm' } },
        { package: { name: 'django', ecosystem: 'PyPI' } },
      ],
    });
  });

  it('fetches full details for each distinct vuln id and maps ecosystem/severity/references', async () => {
    const { fetchFn, calls } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'GHSA-TEST-1111' }] }] },
      vulnsById: {
        'GHSA-TEST-1111': {
          id: 'GHSA-TEST-1111',
          summary: 'Test summary',
          database_specific: { severity: 'HIGH' },
          affected: [
            {
              package: { ecosystem: 'npm', name: 'lodash' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
            },
          ],
          references: [{ url: 'https://example.invalid/advisory' }, {}],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
    ]);

    expect(calls.length).toBe(2);
    expect(calls[1]?.url).toBe('https://api.osv.dev/v1/vulns/GHSA-TEST-1111');
    expect(advisories).toEqual([
      {
        id: 'GHSA-TEST-1111',
        ecosystem: 'npm',
        name: 'lodash',
        affectedRanges: [{ fixed: '4.17.21' }], // "0" introduced -> normalized away (no lower bound)
        severity: 'high',
        summary: 'Test summary',
        references: ['https://example.invalid/advisory'],
      },
    ]);
  });

  it('walks multiple introduced/fixed event pairs into separate disjoint ranges', async () => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'MULTI-1' }] }] },
      vulnsById: {
        'MULTI-1': {
          id: 'MULTI-1',
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [
                {
                  type: 'SEMVER',
                  events: [
                    { introduced: '1.0.0' },
                    { fixed: '1.0.5' },
                    { introduced: '2.0.0' },
                    { fixed: '2.0.3' },
                  ],
                },
              ],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '1.0.1' }]);
    expect(advisories[0]?.affectedRanges).toEqual([
      { introduced: '1.0.0', fixed: '1.0.5' },
      { introduced: '2.0.0', fixed: '2.0.3' },
    ]);
  });

  it('a trailing introduced with no following fixed means "still vulnerable, no fix yet"', async () => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'NOFIX-1' }] }] },
      vulnsById: {
        'NOFIX-1': {
          id: 'NOFIX-1',
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }] }],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '3.0.0' }]);
    expect(advisories[0]?.affectedRanges).toEqual([{ introduced: '3.0.0' }]);
  });

  it('skips GIT-type ranges, keeping only usable version ranges', async () => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'GIT-MIX-1' }] }] },
      vulnsById: {
        'GIT-MIX-1': {
          id: 'GIT-MIX-1',
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [
                { type: 'GIT', events: [{ introduced: 'abc123' }] },
                { type: 'SEMVER', events: [{ fixed: '1.0.0' }] },
              ],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '0.5.0' }]);
    expect(advisories[0]?.affectedRanges).toEqual([{ fixed: '1.0.0' }]);
  });

  it('excludes a vuln entirely when none of its "affected" entries match the requested package', async () => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'OTHER-PKG-1' }] }] },
      vulnsById: {
        'OTHER-PKG-1': {
          id: 'OTHER-PKG-1',
          affected: [
            {
              package: { ecosystem: 'PyPI', name: 'foo' }, // different ecosystem than requested
              ranges: [{ type: 'SEMVER', events: [{ fixed: '1.0.0' }] }],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '0.5.0' }]);
    expect(advisories).toEqual([]);
  });

  it.each([
    [{ severity: 'CRITICAL' }, 'critical'],
    [{ severity: 'High' }, 'high'],
    [{ severity: 'moderate' }, 'medium'],
    [{ severity: 'MEDIUM' }, 'medium'],
    [{ severity: 'low' }, 'low'],
    [undefined, 'medium'], // absent severity: documented conservative default
    [{ severity: 'not-a-real-bucket' }, 'medium'],
  ])('maps database_specific %j to severity %s', async (databaseSpecific, expected) => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'SEV-1' }] }] },
      vulnsById: {
        'SEV-1': {
          id: 'SEV-1',
          ...(databaseSpecific ? { database_specific: databaseSpecific } : {}),
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [{ events: [{ fixed: '1.0.0' }] }],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '0.5.0' }]);
    expect(advisories[0]?.severity).toBe(expected);
  });

  it('falls back to a truncated "details" field, then to a generic label, when summary is absent', async () => {
    const longDetails = 'x'.repeat(250);
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'A' }, { id: 'B' }] }] },
      vulnsById: {
        A: {
          id: 'A',
          details: longDetails,
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [{ events: [{ fixed: '1.0.0' }] }],
            },
          ],
        },
        B: {
          id: 'B',
          affected: [
            {
              package: { ecosystem: 'npm', name: 'foo' },
              ranges: [{ events: [{ fixed: '1.0.0' }] }],
            },
          ],
        },
      },
    });
    const source = new OsvDataSource(fetchFn);
    const advisories = await source.query([{ ecosystem: 'npm', name: 'foo', version: '0.5.0' }]);

    expect(advisories.find((a) => a.id === 'A')?.summary).toBe(`${'x'.repeat(200)}…`);
    expect(advisories.find((a) => a.id === 'B')?.summary).toBe('Vulnerability B');
  });

  it('throws when the querybatch request itself fails', async () => {
    const { fetchFn } = fakeFetch({ querybatch: {}, batchStatus: 500 });
    const source = new OsvDataSource(fetchFn);
    await expect(
      source.query([{ ecosystem: 'npm', name: 'foo', version: '1.0.0' }]),
    ).rejects.toThrow(/querybatch.*500/);
  });

  it('throws when a vuln detail request fails', async () => {
    const { fetchFn } = fakeFetch({
      querybatch: { results: [{ vulns: [{ id: 'BOOM' }] }] },
      detailStatus: { BOOM: 404 },
    });
    const source = new OsvDataSource(fetchFn);
    await expect(
      source.query([{ ecosystem: 'npm', name: 'foo', version: '1.0.0' }]),
    ).rejects.toThrow(/BOOM.*404/);
  });
});
