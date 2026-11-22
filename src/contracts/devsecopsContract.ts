export type DevSecOpsSeatId = 'developer' | 'appsec-gate';

export type CognitivePhase = 1 | 2 | 3 | 4;

export type PrPresetId =
  | 'TYPOSQUAT_DEP'
  | 'LEAKED_SECRET'
  | 'UNPINNED_ACTION'
  | 'PUBLIC_IAC_ACL'
  | 'CLEAN_PR';

export type PoePrediction = 'ALLOW' | 'DENY';

export type GateStageStatus = 'WAITING' | 'CHECKING' | 'PASS' | 'BLOCK' | 'WARN';

export interface PolicyClauses {
  require_pinned_sha: boolean;
  block_secrets: boolean;
  require_cosign_oidc: boolean;
  block_public_acl: boolean;
}

export const INITIAL_PERMISSIVE_CLAUSES: PolicyClauses = {
  require_pinned_sha: false,
  block_secrets: true,
  require_cosign_oidc: false,
  block_public_acl: false
};

export const HARDENED_POLICY_CLAUSES: PolicyClauses = {
  require_pinned_sha: true,
  block_secrets: true,
  require_cosign_oidc: true,
  block_public_acl: true
};

export interface ScannerFinding {
  id: string;
  scanner: 'SYFT_SBOM' | 'GITLEAKS' | 'GH_ACTIONS_LINT' | 'CHECKOV_IAC';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  rule_id: string;
  file: string;
  line: number;
  smoking_gun_code: string;
  title: string;
  remediation_hint: string;
}

export interface PrPresetDefinition {
  id: PrPresetId;
  trapLabel: string;
  prNumber: string;
  branch: string;
  title: string;
  commitSha: string;
  author: string;
  summary: string;
  changedFiles: string[];
  diffPreview: Array<{
    lineNo: number;
    file: string;
    content: string;
    isSmokingGun?: boolean;
  }>;
  findings: ScannerFinding[];
  sbomComponents: Array<{
    name: string;
    version: string;
    purl: string;
    risk: 'CLEAN' | 'TYPOSQUAT_SUSPECT';
  }>;
  cosignSigned: boolean;
}

export const PR_PRESETS: Record<PrPresetId, PrPresetDefinition> = {
  TYPOSQUAT_DEP: {
    id: 'TYPOSQUAT_DEP',
    trapLabel: 'Trap 4A · Typosquatting',
    prNumber: 'PR #418',
    branch: 'feat/oauth-helper',
    title: 'feat(auth): add lightweight OAuth token helper',
    commitSha: '9f4a21c8e3d1b7a205c9f11a44e8029c1a7b33d0',
    author: 'jordan.lee@0trust.dev',
    summary: 'Introduces typosquatted package `reqeusts-oauth` (1-char transposition of `requests-oauthlib`) in requirements.txt.',
    changedFiles: ['services/auth/requirements.txt', 'services/auth/oauth_client.py'],
    diffPreview: [
      { lineNo: 11, file: 'services/auth/requirements.txt', content: 'cryptography==43.0.1' },
      { lineNo: 12, file: 'services/auth/requirements.txt', content: 'pydantic==2.9.2' },
      {
        lineNo: 13,
        file: 'services/auth/requirements.txt',
        content: '+reqeusts-oauth==1.3.1  # typosquat package with postinstall exfil',
        isSmokingGun: true
      }
    ],
    findings: [
      {
        id: 'FND-4A-001',
        scanner: 'SYFT_SBOM',
        severity: 'CRITICAL',
        rule_id: 'SBOM-TYPOSQUAT-001',
        file: 'services/auth/requirements.txt',
        line: 13,
        smoking_gun_code: 'reqeusts-oauth==1.3.1',
        title: 'Typosquatted PyPI dependency detected in Syft CycloneDX SBOM',
        remediation_hint: 'Replace `reqeusts-oauth` with verified `requests-oauthlib==2.0.0` pinned by SHA-256.'
      }
    ],
    sbomComponents: [
      {
        name: 'cryptography',
        version: '43.0.1',
        purl: 'pkg:pypi/cryptography@43.0.1',
        risk: 'CLEAN'
      },
      {
        name: 'reqeusts-oauth',
        version: '1.3.1',
        purl: 'pkg:pypi/reqeusts-oauth@1.3.1',
        risk: 'TYPOSQUAT_SUSPECT'
      }
    ],
    cosignSigned: false
  },
  LEAKED_SECRET: {
    id: 'LEAKED_SECRET',
    trapLabel: 'Trap 4B · Leaked Secret',
    prNumber: 'PR #419',
    branch: 'fix/s3-export-script',
    title: 'fix(billing): quick export script for finance bucket',
    commitSha: '7c12b80f2e4d991a0f3b8c6e12a4d5f7890e1123',
    author: 'jordan.lee@0trust.dev',
    summary: 'Commits a synthetic hardcoded AWS IAM access key & API token inside `scripts/export_ledger.ts`.',
    changedFiles: ['scripts/export_ledger.ts'],
    diffPreview: [
      { lineNo: 4, file: 'scripts/export_ledger.ts', content: 'const REGION = "us-east-1";' },
      {
        lineNo: 5,
        file: 'scripts/export_ledger.ts',
        content: '+const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // synthetic trap token',
        isSmokingGun: true
      },
      { lineNo: 6, file: 'scripts/export_ledger.ts', content: 'export async function runExport() { ... }' }
    ],
    findings: [
      {
        id: 'FND-4B-001',
        scanner: 'GITLEAKS',
        severity: 'CRITICAL',
        rule_id: 'aws-access-token',
        file: 'scripts/export_ledger.ts',
        line: 5,
        smoking_gun_code: 'AKIAIOSFODNN7EXAMPLE',
        title: 'Hardcoded AWS Access Key ID detected by Gitleaks entropy & regex scanner',
        remediation_hint: 'Remove hardcoded credential and use ephemeral GitHub OIDC -> AWS STS AssumeRoleWithWebIdentity.'
      }
    ],
    sbomComponents: [
      {
        name: '@aws-sdk/client-s3',
        version: '3.682.0',
        purl: 'pkg:npm/%40aws-sdk/client-s3@3.682.0',
        risk: 'CLEAN'
      }
    ],
    cosignSigned: false
  },
  UNPINNED_ACTION: {
    id: 'UNPINNED_ACTION',
    trapLabel: 'Trap 4C · Unpinned Action',
    prNumber: 'PR #420',
    branch: 'ci/add-release-workflow',
    title: 'ci: add automated release workflow',
    commitSha: '3b89d01a4c6e77881290ab34cd56ef7890123456',
    author: 'jordan.lee@0trust.dev',
    summary: 'References mutable branch tag `actions/checkout@main` instead of an immutable 40-char commit SHA.',
    changedFiles: ['.github/workflows/release.yml'],
    diffPreview: [
      { lineNo: 12, file: '.github/workflows/release.yml', content: '    steps:' },
      {
        lineNo: 13,
        file: '.github/workflows/release.yml',
        content: '+      - uses: actions/checkout@main  # mutable ref vulnerable to tag hijack',
        isSmokingGun: true
      },
      { lineNo: 14, file: '.github/workflows/release.yml', content: '      - run: npm ci && npm run build' }
    ],
    findings: [
      {
        id: 'FND-4C-001',
        scanner: 'GH_ACTIONS_LINT',
        severity: 'HIGH',
        rule_id: 'OPA-PINNED-SHA-001',
        file: '.github/workflows/release.yml',
        line: 13,
        smoking_gun_code: 'uses: actions/checkout@main',
        title: 'GitHub Action uses mutable branch ref (@main) instead of 40-char commit SHA',
        remediation_hint: 'Pin action to immutable 40-char SHA: `uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332`.'
      }
    ],
    sbomComponents: [
      {
        name: 'vite',
        version: '5.4.11',
        purl: 'pkg:npm/vite@5.4.11',
        risk: 'CLEAN'
      }
    ],
    cosignSigned: false
  },
  PUBLIC_IAC_ACL: {
    id: 'PUBLIC_IAC_ACL',
    trapLabel: 'Trap 4D · Checkov IaC',
    prNumber: 'PR #421',
    branch: 'infra/r2-artifacts-bucket',
    title: 'infra(tf): provision build artifacts bucket',
    commitSha: '5e21f44b8d9a0123456789abcdef0123456789ab',
    author: 'jordan.lee@0trust.dev',
    summary: 'Configures `acl = "public-read"` on Terraform storage bucket, exposing build artifacts to public internet.',
    changedFiles: ['infra/terraform/storage.tf'],
    diffPreview: [
      { lineNo: 7, file: 'infra/terraform/storage.tf', content: 'resource "aws_s3_bucket_acl" "artifacts" {' },
      {
        lineNo: 8,
        file: 'infra/terraform/storage.tf',
        content: '+  acl = "public-read"  # Checkov CKV_AWS_20 violation',
        isSmokingGun: true
      },
      { lineNo: 9, file: 'infra/terraform/storage.tf', content: '}' }
    ],
    findings: [
      {
        id: 'FND-4D-001',
        scanner: 'CHECKOV_IAC',
        severity: 'CRITICAL',
        rule_id: 'CKV_AWS_20',
        file: 'infra/terraform/storage.tf',
        line: 8,
        smoking_gun_code: 'acl = "public-read"',
        title: 'Checkov IaC violation: Public-read ACL on S3/R2 artifact bucket',
        remediation_hint: 'Set `acl = "private"` and enable `block_public_acls = true`.'
      }
    ],
    sbomComponents: [
      {
        name: 'terraform-provider-cloudflare',
        version: '5.1.0',
        purl: 'pkg:golang/github.com/cloudflare/terraform-provider-cloudflare@5.1.0',
        risk: 'CLEAN'
      }
    ],
    cosignSigned: false
  },
  CLEAN_PR: {
    id: 'CLEAN_PR',
    trapLabel: 'Clean Remediated PR',
    prNumber: 'PR #422',
    branch: 'feat/attested-release',
    title: 'feat(release): pinned SHA actions, OIDC STS, private ACL, verified SBOM',
    commitSha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    author: 'jordan.lee@0trust.dev',
    summary: 'All dependencies verified in Syft SBOM, zero Gitleaks secrets, 40-char SHA pinned Actions, private IaC ACL, and Cosign OIDC keyless signature.',
    changedFiles: ['.github/workflows/release.yml', 'infra/terraform/storage.tf', 'services/auth/requirements.txt'],
    diffPreview: [
      { lineNo: 13, file: '.github/workflows/release.yml', content: '      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7' },
      { lineNo: 8, file: 'infra/terraform/storage.tf', content: '  acl = "private"' },
      { lineNo: 13, file: 'services/auth/requirements.txt', content: 'requests-oauthlib==2.0.0' }
    ],
    findings: [],
    sbomComponents: [
      {
        name: 'requests-oauthlib',
        version: '2.0.0',
        purl: 'pkg:pypi/requests-oauthlib@2.0.0',
        risk: 'CLEAN'
      },
      {
        name: 'cryptography',
        version: '43.0.1',
        purl: 'pkg:pypi/cryptography@43.0.1',
        risk: 'CLEAN'
      }
    ],
    cosignSigned: true
  }
};

export interface CosignAttestationRecord {
  mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2';
  verification_status: 'VERIFIED_KEYLESS_OIDC';
  oidc_issuer: 'https://token.actions.githubusercontent.com';
  subject_san: 'https://github.com/c2pig/0trust-lab-devsecops-gatekeeper/.github/workflows/deploy.yml@refs/heads/main';
  rekor_log_index: number;
  artifact_digest_sha256: string;
  sbom_digest_sha256: string;
  signed_at: string;
}

export interface EvaluatePrResponse {
  decision: 'ALLOW' | 'DENY';
  http_status: 200 | 403;
  pr_preset: PrPresetId;
  pr_number: string;
  policy_clauses: PolicyClauses;
  unmet_clauses: string[];
  findings: ScannerFinding[];
  syft_sbom: {
    bomFormat: 'CycloneDX';
    specVersion: '1.5';
    serialNumber: string;
    components: PrPresetDefinition['sbomComponents'];
  };
  opa_trace: {
    package: '0trust.admission';
    entrypoint: 'data.0trust.admission.allow';
    allow: boolean;
    deny_reasons: string[];
    evaluated_at: string;
  };
  cosign_attestation: CosignAttestationRecord | null;
  storage: 'cloudflare-kv' | 'browser-fallback' | 'ephemeral-edge';
  kv_ttl_seconds: number;
  session_id: string;
  timestamp: string;
  message: string;
}

export interface DevSecOpsLabState {
  session_id: string;
  correlation_id: string;
  traceparent: string;
  active_phase: CognitivePhase;
  selected_preset: PrPresetId;
  prediction: PoePrediction | null;
  smoking_gun_inspected: boolean;
  policy_clauses: PolicyClauses;
  last_evaluation: EvaluatePrResponse | null;
  deployed_attested: boolean;
  evaluated_presets: Record<PrPresetId, boolean>;
}
