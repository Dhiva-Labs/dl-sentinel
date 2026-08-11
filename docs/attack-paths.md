# Attack paths

Attack-path analysis correlates a **completed report** — the findings the scanners already
produced — plus the [infrastructure graph](architecture.md#infrastructure-graph) into *candidate
attack chains*: small combinations of findings that are worth looking at together, because
together they describe more than they do apart.

Package: `packages/attack-paths` (`@dl-sentinel/attack-paths`). Entry point:

```ts
findAttackPaths(report: Report, graph?: InfraGraph): AttackPath[]
```

Surfaced by [`sentinel scan --paths`](cli.md#sentinel-scan-target). Contract:
[Architecture § Attack paths](architecture.md#attack-paths).

## The honesty contract

This is the part of the feature that matters most. An analyzer that guesses at exploit chains is
worse than no analyzer at all: it buries real findings under speculation and teaches people to
ignore the tool.

- **Candidates, not exploits.** A path says "these findings could combine". It never says a
  system *is* exploitable, and nothing here is executed, probed, or reached over a network.
- **Confidence is capped at `likely`.** There is no level above it. `AttackPath.confidence` is a
  core `Confidence`, so the two levels the analyzer uses map onto it — and `high` is never
  produced, which is what makes the cap visible in a serialized report:

  | Analyzer level | `AttackPath.confidence` | Means |
  | --- | --- | --- |
  | `likely` | `medium` | The findings are linked by the graph (same service/workload) or by the document that declares both. |
  | `potential` | `low` | The findings only co-occur in the same repository. |

  Terminal and Markdown output print the analyzer's word (`likely` / `potential`); JSON and SARIF
  consumers see the `Confidence` value.
- **"Could allow" phrasing.** Narratives describe what a combination *could allow*. The words
  "exploitable" and "will allow" do not appear in any narrative, and a test sweeps every path the
  catalog can build to keep it that way.
- **Every step is a real finding.** A step's `findingId` always names a finding present in
  `report.findings`; the analyzer never fabricates one to complete a chain. When the *only*
  evidence for a link is a graph edge (a published port, say), the path simply has fewer steps and
  the narrative names the graph observation instead.
- **No invented linkage.** Without a graph, graph-level linkage is unavailable — never inferred
  from file paths. Rules that depend on it degrade to `potential`.

## Data model

```ts
interface AttackPath {
  id: string;          // "AP001:<fingerprint of the constituent finding ids>"
  title: string;
  severity: Severity;
  confidence: Confidence;   // never 'high'
  steps: AttackPathStep[];  // 1-3, each on a real finding
  narrative: string;        // 1-3 sentences, "could allow"
}

interface AttackPathStep {
  findingId: string;                          // a Finding.id from this report
  ruleId: string;
  file: string;
  role: 'entry' | 'escalation' | 'impact';
  note: string;
}
```

Path ids are **stable**: the correlation rule id plus a fingerprint of the constituent finding
ids (sorted before hashing, so re-ordering a path's steps never changes its identity). The same
report always produces the same paths in the same order, whatever order the findings arrive in.

## Linkage: what makes a chain more than co-occurrence

Two findings in one repository prove nothing about each other. Exactly two links raise a
candidate above "both of these exist":

1. **Graph linkage** — the infrastructure graph resolves both findings to the same service or
   workload node, by the node's `source.file` and the nearest preceding `source.line`. A
   Kubernetes container folds into its parent workload (the graph's `connects` edge), so a
   `securityContext` finding on a container and a `hostNetwork` finding on its pod spec land in
   one unit. This is the strong link.
2. **File linkage** — both findings are declared in the same document. Weaker, because one
   compose file can declare several unrelated services, but still concrete. Some rules accept it
   as `likely` (AP005, AP007, where the two halves belong to one artifact by construction);
   AP001 does not, precisely because of the several-services case.

Anything else is repository co-occurrence, reported as `potential` and said plainly in the
narrative.

## Catalog

Every correlation is declared — id, title, the co-occurrence it requires, the severity it
assigns, and the confidence it can reach. A combination not in this table is not reported.

| Id | Title | Conditions (all must hold) | Severity | Confidence |
| --- | --- | --- | --- | --- |
| `AP001` | Privileged workload on an exposed surface | A privileged/host-namespace infra finding (`I010`, `I011`, `I013`, `I020`, `I021`, `I025`) **and** a *different* exposed-surface signal in the same service unit: `I006`, `I016`, host networking (`I011`; `I021` only when its `field` metadata is `hostNetwork`), or a graph `exposes` edge. Adds the unit's host mount (`I012`/`I022`) as the impact step when there is one. | `critical` | `likely` only with graph linkage, else `potential` |
| `AP002` | Leaked credential and a reachable service | A critical/high secrets finding (`S001`-`S022`) **and** an exposed surface: an infra exposure finding, a graph `exposes` edge, or a non-loopback `A003`. | `critical` | `likely` when the credential and the surface share a file or directory, else `potential` |
| `AP003` | Known-vulnerable dependency behind an exposed surface | A `D001` finding **and** an exposed surface (same set as AP002). | `D001`'s severity, floored at `high` | always `potential` |
| `AP004` | Cloud storage exposure with committed credentials | `I031` public bucket ACL **and** an AWS credential finding (`S001`/`S002`). | `critical` | `likely` |
| `AP005` | Unauthenticated operation reachable over cleartext | `A001` or `A005` **and** a non-loopback `A003`, in the same API document (`finding.file`). `A005` is preferred over `A001`. | `high` | `likely` |
| `AP006` | Injection-class code alongside an API surface | At least one `C001`/`C002`/`C003` finding **and** at least one API-scanner finding. | derived from the two steps | always `potential` |
| `AP007` | Container credential with a host mount | An environment-credential finding (`I004`, `I014`, `I028`) **and** a sensitive host mount (`I012`, `I022`) on the same service unit. | `critical` | `likely` |

Notes on two deliberate choices:

- **Host networking counts as exposure.** `I011`/`I021` appear in both the privilege set and the
  exposure set of AP001, because a container on the host network has every port it listens on
  bound directly to the host's interfaces — there is no port mapping to review. AP001 always
  requires the two roles to be filled by two *different* findings, so a lone `I011` can never pair
  with itself.
- **`A003` excludes loopback.** The API scanner downgrades a `http://localhost` server entry to
  `info`; that is a developer's own machine, not a surface anyone else can reach, so it is not
  treated as an exposure.

## Flood control

A correlator that pairs every finding with every other finding produces a quadratic wall that no
one reads. Every rule is bounded by construction:

- AP001 and AP007: at most one path per **service unit**.
- AP002 and AP003: at most one path per **exposed surface** — the credential (or advisory) closest
  to that surface represents it, and the narrative carries how many others exist.
- AP004: at most one path per `I031` finding.
- AP005: at most one path per **API document**.
- AP006: **exactly one** path per report, ever. Pairing every injection site with every endpoint
  would say nothing that an aggregate does not, so the single path carries the counts in its
  narrative.

On top of that, `MAX_PATHS_PER_RULE` (10) is a backstop for a repository with a pathological number
of services: the highest-severity matches survive in the report's own ordering, the rest are
dropped rather than flooding the section.

Paths are sorted by severity, then confidence, then id.

## Usage

```bash
sentinel scan . --paths                      # terminal report + "Attack paths" section
sentinel scan . --paths --format json        # report.attackPaths in the JSON document
sentinel scan . --paths --format markdown    # "## Attack paths" section with a step table
sentinel scan . --paths --baseline base.json # correlates only the NEW findings
```

`--paths` discovers the target's infrastructure files (the same discovery `sentinel graph` uses),
builds the graph, and correlates the findings the report is about to show — so with `--baseline`
it correlates the new findings only.

**Exit codes are unaffected.** Attack paths re-present findings the policy has already counted;
adding `--paths` never changes whether a scan exits `0` or `1`. When no candidates are found, no
section is rendered and a note goes to stderr (suppressed by `--quiet`).

`--format sarif` is unchanged by `--paths`: SARIF describes results, and a candidate chain is not
a result.

Example section (from `sentinel scan tests/fixtures/vulnerable-app --paths --quiet`):

```
Attack paths (9)
Candidate chains for review. DL Sentinel does not verify exploitability.

  1. AP001  critical  likely
     Privileged workload on an exposed surface
     1. entry      I021  k8s/deployment.yaml:18
        Host networking binds the workload directly on the node interfaces.
     2. escalation I020  k8s/deployment.yaml:23
        The pod container runs with a privileged security context.
     3. impact     I022  k8s/deployment.yaml:30
        A sensitive hostPath volume is mounted into the pod.
     A container that is not separated from its host sits on an exposed surface: the privilege
     and the exposure are declared in the same workload `Deployment/vulnerable-app-fixture`
     (`k8s/deployment.yaml`). Together with the host filesystem mounted into it, a foothold in
     this container could allow an attacker to read or change host state rather than staying
     confined. Review whether the exposure is intended and whether the privilege can be dropped.
```

## Adding a correlation rule

1. Add a module under `packages/attack-paths/src/rules/` exporting a `CorrelationRule` —
   `{ id, title, severity, conditions, find, buildNarrative }` — with JSDoc stating its
   conditions, its bound, and why its confidence is what it is.
2. Register it in `src/catalog.ts`.
3. Add a row to the catalog table above.
4. Test it both ways: the positive case, and each condition **alone** producing no path. A
   correlation that fires on one finding is not a correlation.

## See also

- [Architecture § Attack paths](architecture.md#attack-paths) — the binding contract.
- [Architecture § Infrastructure graph](architecture.md#infrastructure-graph) — what linkage is
  built on.
- [CLI reference](cli.md#sentinel-scan-target) — the `--paths` flag.
- [Rules](rules.md) — the `S`/`D`/`C`/`I`/`A`/`SC` rule catalogs these paths correlate over.
