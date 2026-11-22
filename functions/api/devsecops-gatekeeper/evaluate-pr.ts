export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface DevSecOpsEnv {
  STATE_KV?: KVNamespace;
  ENVIRONMENT?: string;
}

type PrPresetId =
  | 'TYPOSQUAT_DEP'
  | 'LEAKED_SECRET'
  | 'UNPINNED_ACTION'
  | 'PUBLIC_IAC_ACL'
  | 'CLEAN_PR';

interface PolicyClauses {
  require_pinned_sha: boolean;
  block_secrets: boolean;
  require_cosign_oidc: boolean;
  block_public_acl: boolean;
}

interface EvaluatePrRequest {
  sessionId?: string;
  pr_preset?: string;
  policy_clauses?: Partial<PolicyClauses>;
}

interface DevSecOpsKvRecord {
  session_id: string;
  last_preset: PrPresetId;
  last_decision: 'ALLOW' | 'DENY';
  evaluations_count: number;
  updated_at: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const KV_TTL_SECONDS = 3600;
const VALID_PRESETS = new Set<PrPresetId>([
  'TYPOSQUAT_DEP',
  'LEAKED_SECRET',
  'UNPINNED_ACTION',
  'PUBLIC_IAC_ACL',
  'CLEAN_PR'
]);

const ephemeralDevSecOpsStore = new Map<string, DevSecOpsKvRecord>();

function sanitizeSessionId(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') return 'demo-visitor';
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return cleaned || 'demo-visitor';
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

const PRESET_METADATA: Record<
  PrPresetId,
  {
    prNumber: string;
    findings: Array<{
      id: string;
      scanner: 'SYFT_SBOM' | 'GITLEAKS' | 'GH_ACTIONS_LINT' | 'CHECKOV_IAC';
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
      rule_id: string;
      file: string;
      line: number;
      smoking_gun_code: string;
      title: string;
      remediation_hint: string;
    }>;
    sbomComponents: Array<{
      name: string;
      version: string;
      purl: string;
      risk: 'CLEAN' | 'TYPOSQUAT_SUSPECT';
    }>;
  }
> = {
  TYPOSQUAT_DEP: {
    prNumber: 'PR #418',
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
      { name: 'cryptography', version: '43.0.1', purl: 'pkg:pypi/cryptography@43.0.1', risk: 'CLEAN' },
      { name: 'reqeusts-oauth', version: '1.3.1', purl: 'pkg:pypi/reqeusts-oauth@1.3.1', risk: 'TYPOSQUAT_SUSPECT' }
    ]
  },
  LEAKED_SECRET: {
    prNumber: 'PR #419',
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
      { name: '@aws-sdk/client-s3', version: '3.682.0', purl: 'pkg:npm/%40aws-sdk/client-s3@3.682.0', risk: 'CLEAN' }
    ]
  },
  UNPINNED_ACTION: {
    prNumber: 'PR #420',
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
      { name: 'vite', version: '5.4.11', purl: 'pkg:npm/vite@5.4.11', risk: 'CLEAN' }
    ]
  },
  PUBLIC_IAC_ACL: {
    prNumber: 'PR #421',
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
    ]
  },
  CLEAN_PR: {
    prNumber: 'PR #422',
    findings: [],
    sbomComponents: [
      { name: 'requests-oauthlib', version: '2.0.0', purl: 'pkg:pypi/requests-oauthlib@2.0.0', risk: 'CLEAN' },
      { name: 'cryptography', version: '43.0.1', purl: 'pkg:pypi/cryptography@43.0.1', risk: 'CLEAN' }
    ]
  }
};

export async function onRequestPost(context: {
  request: Request;
  env: DevSecOpsEnv;
}): Promise<Response> {
  const rawText = await context.request.text();
  if (rawText.length > MAX_BODY_BYTES) {
    return jsonResponse(
      { error: 'PAYLOAD_TOO_LARGE', message: 'Request payload exceeds 64KB limit.' },
      413
    );
  }

  let body: EvaluatePrRequest = {};
  if (rawText.trim().length > 0) {
    try {
      body = JSON.parse(rawText) as EvaluatePrRequest;
    } catch {
      return jsonResponse(
        { error: 'INVALID_JSON', message: 'Request body must be valid JSON.' },
        400
      );
    }
  }

  if (!body.pr_preset || !VALID_PRESETS.has(body.pr_preset as PrPresetId)) {
    return jsonResponse(
      {
        error: 'INVALID_PR_PRESET',
        message: 'pr_preset must be one of TYPOSQUAT_DEP, LEAKED_SECRET, UNPINNED_ACTION, PUBLIC_IAC_ACL, CLEAN_PR.'
      },
      400
    );
  }

  const preset = body.pr_preset as PrPresetId;
  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const kvKey = `lab4:devsecops:${sessionId}`;

  const clauses: PolicyClauses = {
    require_pinned_sha: Boolean(body.policy_clauses?.require_pinned_sha),
    block_secrets: Boolean(body.policy_clauses?.block_secrets),
    require_cosign_oidc: Boolean(body.policy_clauses?.require_cosign_oidc),
    block_public_acl: Boolean(body.policy_clauses?.block_public_acl)
  };

  const unmetClauses: string[] = [];
  if (!clauses.require_pinned_sha) unmetClauses.push('require_pinned_sha');
  if (!clauses.block_secrets) unmetClauses.push('block_secrets');
  if (!clauses.require_cosign_oidc) unmetClauses.push('require_cosign_oidc');
  if (!clauses.block_public_acl) unmetClauses.push('block_public_acl');

  const meta = PRESET_METADATA[preset];
  const denyReasons: string[] = [];
  for (const f of meta.findings) {
    denyReasons.push(`[${f.scanner}] ${f.rule_id}: ${f.title}`);
  }
  for (const c of unmetClauses) {
    denyReasons.push(`[OPA_POLICY_GAP] Required clause ${c} is disabled (fail-closed).`);
  }

  const isAllowed = preset === 'CLEAN_PR' && unmetClauses.length === 0;
  const decision: 'ALLOW' | 'DENY' = isAllowed ? 'ALLOW' : 'DENY';
  const httpStatus: 200 | 403 = isAllowed ? 200 : 403;
  const timestamp = new Date().toISOString();

  let prevCount = 0;
  if (context.env.STATE_KV) {
    try {
      const raw = await context.env.STATE_KV.get(kvKey);
      if (raw) {
        const parsed = JSON.parse(raw) as DevSecOpsKvRecord;
        prevCount = parsed.evaluations_count ?? 0;
      }
    } catch {
      prevCount = 0;
    }
  } else {
    prevCount = ephemeralDevSecOpsStore.get(kvKey)?.evaluations_count ?? 0;
  }

  const record: DevSecOpsKvRecord = {
    session_id: sessionId,
    last_preset: preset,
    last_decision: decision,
    evaluations_count: prevCount + 1,
    updated_at: timestamp
  };

  const storage = context.env.STATE_KV ? 'cloudflare-kv' : 'ephemeral-edge';
  if (context.env.STATE_KV) {
    await context.env.STATE_KV.put(kvKey, JSON.stringify(record), {
      expirationTtl: KV_TTL_SECONDS
    });
  } else {
    ephemeralDevSecOpsStore.set(kvKey, record);
  }

  return jsonResponse(
    {
      decision,
      http_status: httpStatus,
      pr_preset: preset,
      pr_number: meta.prNumber,
      policy_clauses: clauses,
      unmet_clauses: unmetClauses,
      findings: meta.findings,
      syft_sbom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber: `urn:uuid:0trust-lab4-${sessionId.slice(0, 12)}`,
        components: meta.sbomComponents
      },
      opa_trace: {
        package: '0trust.admission',
        entrypoint: 'data.0trust.admission.allow',
        allow: isAllowed,
        deny_reasons: denyReasons,
        evaluated_at: timestamp
      },
      cosign_attestation: isAllowed
        ? {
            mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
            verification_status: 'VERIFIED_KEYLESS_OIDC',
            oidc_issuer: 'https://token.actions.githubusercontent.com',
            subject_san:
              'https://github.com/c2pig/0trust-lab-devsecops-gatekeeper/.github/workflows/deploy.yml@refs/heads/main',
            rekor_log_index: 94827104,
            artifact_digest_sha256: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            sbom_digest_sha256: 'sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
            signed_at: timestamp
          }
        : null,
      storage,
      kv_ttl_seconds: KV_TTL_SECONDS,
      session_id: sessionId,
      timestamp,
      message: isAllowed
        ? `ALLOW: ${meta.prNumber} passed all scanners, OPA/Rego clauses (4/4), and keyless Cosign OIDC attestation.`
        : `DENY (403): ${meta.prNumber} blocked by fail-closed OPA/Rego gate (${meta.findings.length} finding(s), ${unmetClauses.length} unmet policy clause(s)).`
    },
    httpStatus
  );
}
