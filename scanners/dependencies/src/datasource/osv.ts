import type {
  Advisory,
  AdvisorySeverity,
  AffectedRange,
  Ecosystem,
  PackageQuery,
  VulnDataSource,
} from '../types.js';

const OSV_API_BASE = 'https://api.osv.dev/v1';

/** Matches the global `fetch` signature so a test fake can be dropped in unchanged. */
export type FetchFn = typeof fetch;

const ECOSYSTEM_TO_OSV: Record<Ecosystem, string> = {
  npm: 'npm',
  pip: 'PyPI',
  go: 'Go',
  cargo: 'crates.io',
};

interface OsvBatchVulnRef {
  id: string;
}

interface OsvBatchResult {
  vulns?: OsvBatchVulnRef[];
}

interface OsvBatchResponse {
  results?: OsvBatchResult[];
}

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}

interface OsvAffectedPackage {
  ecosystem?: string;
  name?: string;
}

interface OsvAffected {
  package?: OsvAffectedPackage;
  ranges?: OsvRange[];
}

interface OsvReference {
  url?: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
  references?: OsvReference[];
}

/**
 * OSV (api.osv.dev) uses "0" as a conventional stand-in for "the beginning
 * of time" in an `introduced` event. Translate it to "no lower bound"
 * rather than feeding the literal string "0" to the semver comparator, which
 * would (correctly) refuse to parse it and mask the advisory entirely.
 */
function normalizeIntroduced(value: string): string | undefined {
  return value === '0' ? undefined : value;
}

/**
 * Walk one OSV range's `events` into our `{introduced, fixed}` pairs. Events
 * are chronological: an `introduced` opens a window, the next `fixed` closes
 * it. Multiple introduced/fixed pairs in one events array describe multiple
 * disjoint vulnerable windows. A trailing `introduced` with no following
 * `fixed` means "still vulnerable, no fix yet". `last_affected` (inclusive)
 * and `limit` events aren't modeled — treated conservatively as closing the
 * current window without asserting a boundary we're not sure of.
 */
function eventsToRanges(events: readonly OsvEvent[]): AffectedRange[] {
  const ranges: AffectedRange[] = [];
  let currentIntroduced: string | undefined;
  let haveOpenWindow = false;

  for (const event of events) {
    if (typeof event.introduced === 'string') {
      currentIntroduced = normalizeIntroduced(event.introduced);
      haveOpenWindow = true;
    } else if (typeof event.fixed === 'string') {
      // OSV's schema expects an `introduced` before a `fixed`, but a bare
      // `fixed` with none seen yet is still meaningful — treat it as
      // "vulnerable since the beginning" rather than silently dropping the
      // range, so a slightly nonconformant record can't mask a real advisory.
      ranges.push({ introduced: currentIntroduced, fixed: event.fixed });
      haveOpenWindow = false;
      currentIntroduced = undefined;
    } else if (typeof event.last_affected === 'string' || typeof event.limit === 'string') {
      haveOpenWindow = false;
      currentIntroduced = undefined;
    }
  }
  if (haveOpenWindow) {
    ranges.push({ introduced: currentIntroduced });
  }
  return ranges;
}

/** Prefer OSV's own bucketed severity; CVSS vector strings are not decoded
 * here (that requires the full CVSS scoring algorithm — out of scope, and
 * guessing a bucket from the vector would risk misrepresenting it). Unknown
 * severity defaults to 'medium': a deliberate, documented middle ground,
 * never silently 'low'. */
function mapOsvSeverity(vuln: OsvVuln): AdvisorySeverity {
  const raw = vuln.database_specific?.severity;
  if (typeof raw === 'string') {
    const normalized = raw.trim().toLowerCase();
    if (normalized === 'critical') return 'critical';
    if (normalized === 'high') return 'high';
    if (normalized === 'moderate' || normalized === 'medium') return 'medium';
    if (normalized === 'low') return 'low';
  }
  return 'medium';
}

function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
}

/**
 * Map one full OSV vuln record to our `Advisory` shape for one queried
 * package. Returns `null` when the vuln has no usable ranges for that
 * package's (ecosystem, name) — e.g. it affects the package on a different
 * ecosystem, or only carries range types we don't model (GIT commit
 * ranges).
 */
function mapOsvVulnToAdvisory(vuln: OsvVuln, pkg: PackageQuery): Advisory | null {
  const osvEcosystem = ECOSYSTEM_TO_OSV[pkg.ecosystem];
  const relevant = (vuln.affected ?? []).filter(
    (a) => a.package?.ecosystem === osvEcosystem && a.package?.name === pkg.name,
  );
  if (relevant.length === 0) return null;

  const affectedRanges: AffectedRange[] = [];
  for (const affected of relevant) {
    for (const range of affected.ranges ?? []) {
      if (range.type === 'GIT') continue; // commit ranges: not a version comparison we can make
      affectedRanges.push(...eventsToRanges(range.events ?? []));
    }
  }
  if (affectedRanges.length === 0) return null;

  return {
    id: vuln.id,
    ecosystem: pkg.ecosystem,
    name: pkg.name,
    affectedRanges,
    severity: mapOsvSeverity(vuln),
    summary:
      vuln.summary ?? (vuln.details ? truncate(vuln.details, 200) : `Vulnerability ${vuln.id}`),
    references: (vuln.references ?? [])
      .map((r) => r.url)
      .filter((url): url is string => typeof url === 'string' && url.length > 0),
  };
}

function toOsvQuery(pkg: PackageQuery): { package: { name: string; ecosystem: string } } {
  return { package: { name: pkg.name, ecosystem: ECOSYSTEM_TO_OSV[pkg.ecosystem] } };
}

/**
 * Live vulnerability data source backed by OSV (https://osv.dev). Two-step
 * lookup, both via the injected fetch function:
 *
 * 1. POST /v1/querybatch once for every requested package, batched — this
 *    endpoint only returns vulnerability ids (not full details).
 * 2. GET /v1/vulns/{id} for each distinct id found, to get the affected
 *    ranges, severity, summary, and references our `Advisory` shape needs.
 *
 * Deliberately does not send a `version` in the querybatch request: this
 * scanner's own comparator (src/version/) is the single source of truth for
 * whether a specific installed version or declared range is affected, and
 * it needs the full affected ranges regardless of which version triggered
 * the query — sending one here would only narrow (and for a declared range
 * spec like "^4.17.0", which isn't a real version, incorrectly narrow) what
 * OSV returns.
 *
 * `fetchFn` defaults to `globalThis.fetch`; tests always inject a fake, so
 * this class never makes a real network call unless a running scan is
 * actually configured with `dataSource: 'osv'`.
 */
export class OsvDataSource implements VulnDataSource {
  constructor(private readonly fetchFn: FetchFn = globalThis.fetch) {}

  async query(packages: readonly PackageQuery[]): Promise<Advisory[]> {
    if (packages.length === 0) return [];

    const queries = packages.map(toOsvQuery);
    const batchResponse = await this.fetchFn(`${OSV_API_BASE}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
    });
    if (!batchResponse.ok) {
      throw new Error(`OSV querybatch request failed with status ${batchResponse.status}`);
    }
    const batchBody = (await batchResponse.json()) as OsvBatchResponse;
    const results = batchBody.results ?? [];

    const idToPackages = new Map<string, PackageQuery[]>();
    for (let i = 0; i < results.length; i += 1) {
      const pkg = packages[i];
      if (!pkg) continue;
      for (const vulnRef of results[i]?.vulns ?? []) {
        const existing = idToPackages.get(vulnRef.id);
        if (existing) existing.push(pkg);
        else idToPackages.set(vulnRef.id, [pkg]);
      }
    }

    const advisories: Advisory[] = [];
    for (const [id, pkgs] of idToPackages) {
      const vuln = await this.fetchVulnDetail(id);
      for (const pkg of pkgs) {
        const advisory = mapOsvVulnToAdvisory(vuln, pkg);
        if (advisory) advisories.push(advisory);
      }
    }
    return advisories;
  }

  private async fetchVulnDetail(id: string): Promise<OsvVuln> {
    const response = await this.fetchFn(`${OSV_API_BASE}/vulns/${encodeURIComponent(id)}`);
    if (!response.ok) {
      throw new Error(`OSV vuln detail request for "${id}" failed with status ${response.status}`);
    }
    return (await response.json()) as OsvVuln;
  }
}
