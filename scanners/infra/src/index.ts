import type { Finding, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { sortFindings } from '@dl-sentinel/core';
import { scanCompose } from './compose/rules.js';
import { scanDockerfile } from './dockerfile/rules.js';
import { scanKubernetes } from './kubernetes/rules.js';
import { SCANNER_ID } from './util/build-finding.js';
import { splitLines } from './util/text-lines.js';
import { isComposeDoc, isKubernetesDoc, parseYamlFile } from './util/yaml-docs.js';
import { toRuleMetaList } from './rules-meta.js';
import { scanTerraform } from './terraform/rules.js';

type FileKind = 'terraform' | 'yaml' | 'dockerfile';

/**
 * Classify a file purely by extension. The engine only ever hands this
 * scanner files matching `supportedFiles` (Dockerfiles, compose/generic
 * YAML, and `.tf`), so anything that isn't YAML or Terraform is treated as
 * Dockerfile-shaped content; semantic classification of YAML into
 * Kubernetes/compose/"not ours" happens by content below.
 */
function classifyFile(relPath: string): FileKind {
  if (relPath.endsWith('.tf')) return 'terraform';
  if (relPath.endsWith('.yml') || relPath.endsWith('.yaml')) return 'yaml';
  return 'dockerfile';
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function scanYamlFile(
  text: string,
  relPath: string,
  warn: (msg: string) => void,
): Promise<Finding[]> {
  const parsed = parseYamlFile(text);
  if (!parsed) {
    warn(`infra: could not parse YAML in ${relPath}; skipping`);
    return [];
  }

  const lines = splitLines(text);
  const withJs = parsed.documents.map((doc) => ({ doc, js: doc.toJS() as unknown }));

  if (withJs.some(({ js }) => isKubernetesDoc(js))) {
    return scanKubernetes(withJs, parsed.lineCounter, lines, relPath);
  }

  const first = withJs[0];
  if (first && isComposeDoc(first.js)) {
    return scanCompose(first.doc, parsed.lineCounter, lines, relPath);
  }

  // Generic YAML that is neither a Kubernetes manifest nor a compose file:
  // not this scanner's concern. Skip silently (not a warning — this is
  // expected and common, e.g. arbitrary app config YAML).
  return [];
}

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of context.files) {
    if (context.signal.aborted) {
      throw new Error('infra scanner: scan aborted');
    }

    try {
      const text = await context.readFile(file);
      const kind = classifyFile(file.relPath);
      switch (kind) {
        case 'dockerfile':
          findings.push(...scanDockerfile(text, file.relPath));
          break;
        case 'terraform':
          findings.push(...scanTerraform(text, file.relPath));
          break;
        case 'yaml':
          findings.push(
            ...(await scanYamlFile(text, file.relPath, (msg) => context.logger.warn(msg))),
          );
          break;
      }
    } catch (err) {
      context.logger.warn(`infra: skipping ${file.relPath}: ${errorMessage(err)}`);
    }
  }

  return sortFindings(findings);
}

export const infraScanner: ScannerPlugin = {
  id: SCANNER_ID,
  name: 'Infrastructure Scanner',
  version: '0.1.0',
  categories: ['docker', 'infrastructure'],
  supportedFiles: [
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
  ],
  rules: toRuleMetaList(),
  scan,
};

export default infraScanner;
