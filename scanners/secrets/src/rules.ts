import type { RuleMeta } from '@dl-sentinel/core';

/**
 * Every rule the secrets scanner can emit, declared statically so
 * `sentinel rules` can render the catalogue without running a scan.
 *
 * Severity follows docs/finding-schema.md: a usable production credential is
 * `critical`, a credential scoped to test/staging data or a value that still
 * needs a second factor to abuse is `high` or `medium`.
 *
 * Confidence describes detection certainty only. Vendor formats carry a
 * checkable prefix and length, so they are `high`; rules that lean on
 * surrounding words or entropy are `medium`. There are deliberately no
 * low-confidence rules — a rule that floods is worse than no rule
 * (docs/scanner-interface.md).
 */

const CWE_798 = 'https://cwe.mitre.org/data/definitions/798.html';
const CWE_312 = 'https://cwe.mitre.org/data/definitions/312.html';

const ROTATE = 'Revoke and rotate the credential, then load it from a secret manager at runtime.';
const ROTATE_AND_PURGE = `${ROTATE} Purge it from git history — a committed secret is compromised even after the file is edited.`;

export const RULE_IDS = {
  awsAccessKeyId: 'S001',
  awsSecretAccessKey: 'S002',
  githubToken: 'S003',
  gitlabToken: 'S004',
  slackToken: 'S005',
  slackWebhook: 'S006',
  stripeLiveKey: 'S007',
  stripeTestKey: 'S008',
  googleApiKey: 'S009',
  twilioApiKey: 'S010',
  twilioAccount: 'S011',
  sendgridKey: 'S012',
  npmToken: 'S013',
  openaiKey: 'S014',
  azureStorageKey: 'S015',
  azureSasToken: 'S016',
  privateKey: 'S017',
  databaseUrlPassword: 'S018',
  basicAuthUrl: 'S019',
  jsonWebToken: 'S020',
  sensitiveAssignment: 'S021',
  highEntropyAssignment: 'S022',
} as const;

export const rules: RuleMeta[] = [
  {
    id: RULE_IDS.awsAccessKeyId,
    title: 'AWS access key id committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'An AWS access key id (AKIA + 16 uppercase alphanumerics) appears in tracked content. Paired with its secret access key it grants API access to the account.',
    recommendation: `Deactivate the key in IAM and delete it. ${ROTATE_AND_PURGE}`,
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
      CWE_798,
    ],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.awsSecretAccessKey,
    title: 'AWS secret access key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A 40-character AWS-shaped secret access key appears on a line that also names AWS or a secret access key. This is the half of an AWS key pair that authenticates requests.',
    recommendation: `Deactivate the associated access key in IAM. ${ROTATE_AND_PURGE}`,
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
      CWE_798,
    ],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.githubToken,
    title: 'GitHub token committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A GitHub access token (ghp_/gho_/ghu_/ghs_/ghr_ or github_pat_) appears in tracked content. GitHub tokens carry repository, package, and workflow scopes.',
    recommendation: `Revoke the token in GitHub developer settings. ${ROTATE_AND_PURGE}`,
    references: [
      'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github',
      CWE_798,
    ],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.gitlabToken,
    title: 'GitLab personal access token committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A GitLab personal access token (glpat- prefix) appears in tracked content. These tokens can carry api scope, which is full account access.',
    recommendation: `Revoke the token in GitLab access-token settings. ${ROTATE_AND_PURGE}`,
    references: ['https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.slackToken,
    title: 'Slack API token committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Slack API token (xoxb/xoxa/xoxp/xoxr/xoxs prefix) appears in tracked content. Slack tokens can read and post messages as the app or the user that issued them.',
    recommendation: `Revoke the token in the Slack app configuration. ${ROTATE_AND_PURGE}`,
    references: ['https://api.slack.com/authentication/token-types', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.slackWebhook,
    title: 'Slack incoming webhook URL committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Slack incoming-webhook URL appears in tracked content. The path after /services/ is the credential: anyone holding it can post into the channel.',
    recommendation: `Delete the webhook in the Slack app configuration and issue a new one. ${ROTATE_AND_PURGE}`,
    references: ['https://api.slack.com/messaging/webhooks', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.stripeLiveKey,
    title: 'Stripe live secret key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Stripe live-mode secret or restricted key (sk_live_/rk_live_) appears in tracked content. Live keys move real money.',
    recommendation: `Roll the key in the Stripe dashboard immediately. ${ROTATE_AND_PURGE}`,
    references: ['https://stripe.com/docs/keys', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.stripeTestKey,
    title: 'Stripe test secret key committed',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Stripe test-mode secret key (sk_test_/rk_test_) appears in tracked content. Test keys cannot move real money, but they expose test data and signal that live keys are handled the same way.',
    recommendation:
      'Roll the test key and load it from the environment, so the same code path is safe when it runs with a live key.',
    references: ['https://stripe.com/docs/keys', CWE_312],
    compliance: { cwe: ['CWE-312'], owasp: ['A04:2021'] },
  },
  {
    id: RULE_IDS.googleApiKey,
    title: 'Google API key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Google API key (AIza prefix) appears in tracked content. Unrestricted keys can be used by anyone and are billed to the project that owns them.',
    recommendation: `Delete the key in the Google Cloud console and issue a restricted replacement. ${ROTATE_AND_PURGE}`,
    references: ['https://cloud.google.com/docs/authentication/api-keys', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.twilioApiKey,
    title: 'Twilio API key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Twilio API key SID (SK + 32 hex characters) appears in tracked content. Twilio credentials can send messages and place calls at the account owner’s expense.',
    recommendation: `Delete the API key in the Twilio console. ${ROTATE_AND_PURGE}`,
    references: ['https://www.twilio.com/docs/iam/api-keys', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.twilioAccount,
    title: 'Twilio account credentials committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A Twilio account SID (AC + 32 hex) or a 32-hex auth token appears on a line whose context names Twilio and an auth token. The SID and auth token together are full account credentials.',
    recommendation: `Rotate the auth token in the Twilio console. ${ROTATE_AND_PURGE}`,
    references: ['https://www.twilio.com/docs/iam/access-tokens', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.sendgridKey,
    title: 'SendGrid API key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A SendGrid API key (SG.<id>.<secret>) appears in tracked content. It allows sending mail from the account’s verified domains.',
    recommendation: `Delete the key in the SendGrid console. ${ROTATE_AND_PURGE}`,
    references: [
      'https://docs.sendgrid.com/ui/account-and-settings/api-keys',
      'https://cwe.mitre.org/data/definitions/798.html',
    ],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.npmToken,
    title: 'npm access token committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'An npm access token (npm_ prefix) appears in tracked content. Publish-scoped tokens allow pushing package versions, which is a supply-chain compromise.',
    recommendation: `Revoke the token with npm token revoke. ${ROTATE_AND_PURGE}`,
    references: ['https://docs.npmjs.com/about-access-tokens', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.openaiKey,
    title: 'OpenAI-style API key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A model-provider API key in the sk-<random> form appears in tracked content. These keys are bearer credentials billed to the owning account.',
    recommendation: `Revoke the key in the provider console. ${ROTATE_AND_PURGE}`,
    references: ['https://platform.openai.com/docs/api-reference/authentication', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.azureStorageKey,
    title: 'Azure storage account key committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'An Azure storage connection string with an embedded AccountKey appears in tracked content. The account key grants full control of the storage account.',
    recommendation: `Rotate the storage account key in the Azure portal. ${ROTATE_AND_PURGE}`,
    references: [
      'https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage',
      CWE_798,
    ],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.azureSasToken,
    title: 'Azure SAS token signature committed',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A shared access signature (the sig= parameter of an Azure SAS URL) appears in tracked content. It grants whatever the SAS permissions allow until it expires.',
    recommendation:
      'Revoke the signing key or the stored access policy behind the signature, then issue short-lived SAS tokens at runtime.',
    references: ['https://learn.microsoft.com/azure/storage/common/storage-sas-overview', CWE_798],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.privateKey,
    title: 'Private key block committed',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A PEM private key block appears in tracked content. Whoever holds the key can impersonate the identity it belongs to. Evidence is the BEGIN line only — key material is never read into a finding.',
    recommendation: `Treat the key as compromised: reissue the certificate or key pair and revoke the old one. ${ROTATE_AND_PURGE}`,
    references: ['https://cwe.mitre.org/data/definitions/321.html', CWE_312],
    // Both CWEs already cited above are kept: CWE-321 (hard-coded
    // cryptographic key) is the specific, defining weakness; CWE-312
    // (cleartext storage of sensitive information) is also literally true
    // and was already vetted by whoever added it to `references`. The
    // OWASP mapping is derived from the more specific/central CWE-321.
    compliance: { cwe: ['CWE-321', 'CWE-312'], owasp: ['A02:2021'] },
  },
  {
    id: RULE_IDS.databaseUrlPassword,
    title: 'Database connection string with embedded password',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A database or broker URL (postgres, mysql, mongodb, redis, amqp) carries an inline user:password. The password is a live credential for the data store.',
    recommendation: `Rotate the database user’s password and build the URL from environment variables. ${ROTATE_AND_PURGE}`,
    references: [CWE_798, CWE_312],
    compliance: { cwe: ['CWE-798', 'CWE-312'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.basicAuthUrl,
    title: 'URL with embedded basic-auth credentials',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'An http(s) URL carries inline user:password basic-auth credentials. Such URLs leak through logs, proxies, and browser history.',
    recommendation: `Rotate the password and pass credentials in an Authorization header sourced from the environment. ${ROTATE_AND_PURGE}`,
    references: ['https://cwe.mitre.org/data/definitions/522.html', CWE_312],
    compliance: { cwe: ['CWE-522', 'CWE-312'], owasp: ['A04:2021'] },
  },
  {
    id: RULE_IDS.jsonWebToken,
    title: 'JSON Web Token committed',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'secrets',
    description:
      'A JWT (header.payload.signature, all base64url) appears in tracked content. Committed JWTs are often documentation samples, but a live one is a bearer credential until it expires.',
    recommendation:
      'Confirm whether the token is live. If it is, revoke the session or signing key and load tokens at runtime; if it is a sample, replace it with an obviously non-functional value.',
    references: ['https://datatracker.ietf.org/doc/html/rfc7519', CWE_312],
    compliance: { cwe: ['CWE-312'], owasp: ['A04:2021'] },
  },
  {
    id: RULE_IDS.sensitiveAssignment,
    title: 'Credential assigned in an environment or config file',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'secrets',
    description:
      'A setting whose name denotes a credential (password, secret, token, api key, auth, credential) is assigned a literal value in an environment or configuration file. Placeholders, template references, and env-var lookups are excluded.',
    recommendation:
      'Move the value to a secret manager or CI secret and reference it from the environment; commit only a placeholder in the checked-in file.',
    references: [CWE_798, CWE_312],
    compliance: { cwe: ['CWE-798', 'CWE-312'], owasp: ['A07:2021'] },
  },
  {
    id: RULE_IDS.highEntropyAssignment,
    title: 'High-entropy value assigned to a credential-named identifier',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'secrets',
    description:
      'A credential-named identifier is assigned a quoted literal of at least 16 characters whose Shannon entropy exceeds 4.0 bits per character — the profile of a generated secret rather than of prose or a path.',
    recommendation:
      'Confirm whether the value is a live credential. If it is, rotate it and load it from the environment; if it is not, rename the identifier or use an obviously inert value.',
    references: [CWE_798, CWE_312],
    compliance: { cwe: ['CWE-798', 'CWE-312'], owasp: ['A07:2021'] },
  },
];

const ruleById = new Map(rules.map((rule) => [rule.id, rule]));

/** Look up a declared rule. Throws for an unknown id — a programming error. */
export function ruleMeta(ruleId: string): RuleMeta {
  const rule = ruleById.get(ruleId);
  if (rule === undefined) {
    throw new Error(`secrets scanner: undeclared rule id "${ruleId}"`);
  }
  return rule;
}
