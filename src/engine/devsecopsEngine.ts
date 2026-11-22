import {
  DevSecOpsLabState,
  EvaluatePrResponse,
  INITIAL_PERMISSIVE_CLAUSES,
  PR_PRESETS,
  PolicyClauses,
  PrPresetId
} from '../contracts/devsecopsContract';
import { ObservabilitySpan } from '../types';

function randomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteCount; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function createSessionId(): string {
  return `lab4-${randomHex(6)}`;
}

export function createTraceparent(): string {
  return `00-${randomHex(16)}-${randomHex(8)}-01`;
}

export function createSpan(params: {
  sessionId: string;
  traceparent: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
  origin: 'cloudflare-edge' | 'browser-webcrypto-fallback';
  summary: Record<string, unknown>;
}): ObservabilitySpan {
  const parts = params.traceparent.split('-');
  const traceId = parts[1] || randomHex(16);
  const spanId = parts[2] || randomHex(8);

  return {
    id: `span-${randomHex(6)}`,
    traceparent: params.traceparent,
    trace_id: traceId,
    span_id: spanId,
    parent_span_id: '0000000000000000',
    session_id: params.sessionId,
    method: params.method,
    path: params.path,
    status: params.status,
    latency_ms: params.latencyMs,
    timestamp: new Date().toISOString(),
    otlp_export: 'in-lab-only',
    redacted_auth_header: null,
    redaction_applied: false,
    execution_origin: params.origin,
    response_summary: params.summary
  };
}

export function createInitialLabState(sessionId: string): DevSecOpsLabState {
  return {
    session_id: sessionId,
    correlation_id: `corr-${randomHex(4)}`,
    traceparent: createTraceparent(),
    active_phase: 1,
    selected_preset: 'TYPOSQUAT_DEP',
    prediction: null,
    smoking_gun_inspected: false,
    policy_clauses: { ...INITIAL_PERMISSIVE_CLAUSES },
    last_evaluation: null,
    deployed_attested: false,
    evaluated_presets: {
      TYPOSQUAT_DEP: false,
      LEAKED_SECRET: false,
      UNPINNED_ACTION: false,
      PUBLIC_IAC_ACL: false,
      CLEAN_PR: false
    }
  };
}

export function evaluatePrLocally(
  presetId: PrPresetId,
  clauses: PolicyClauses,
  sessionId: string
): EvaluatePrResponse {
  const preset = PR_PRESETS[presetId];
  const unmetClauses: string[] = [];
  if (!clauses.require_pinned_sha) unmetClauses.push('require_pinned_sha');
  if (!clauses.block_secrets) unmetClauses.push('block_secrets');
  if (!clauses.require_cosign_oidc) unmetClauses.push('require_cosign_oidc');
  if (!clauses.block_public_acl) unmetClauses.push('block_public_acl');

  const denyReasons: string[] = [];
  for (const f of preset.findings) {
    denyReasons.push(`[${f.scanner}] ${f.rule_id}: ${f.title}`);
  }
  for (const c of unmetClauses) {
    denyReasons.push(`[OPA_POLICY_GAP] Required clause ${c} is disabled (fail-closed).`);
  }

  const isAllowed = presetId === 'CLEAN_PR' && unmetClauses.length === 0;
  const decision: 'ALLOW' | 'DENY' = isAllowed ? 'ALLOW' : 'DENY';
  const httpStatus: 200 | 403 = isAllowed ? 200 : 403;
  const timestamp = new Date().toISOString();

  return {
    decision,
    http_status: httpStatus,
    pr_preset: presetId,
    pr_number: preset.prNumber,
    policy_clauses: { ...clauses },
    unmet_clauses: unmetClauses,
    findings: preset.findings,
    syft_sbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:0trust-lab4-${sessionId.slice(0, 12)}`,
      components: preset.sbomComponents
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
    storage: 'browser-fallback',
    kv_ttl_seconds: 3600,
    session_id: sessionId,
    timestamp,
    message: isAllowed
      ? `ALLOW: ${preset.prNumber} passed all scanners, OPA/Rego clauses (4/4), and keyless Cosign OIDC attestation.`
      : `DENY (403): ${preset.prNumber} blocked by fail-closed OPA/Rego gate (${preset.findings.length} finding(s), ${unmetClauses.length} unmet policy clause(s)).`
  };
}

let edgeApiAvailable: boolean | null = null;

export async function evaluatePrWithEdgeFallback(params: {
  presetId: PrPresetId;
  clauses: PolicyClauses;
  sessionId: string;
}): Promise<{ result: EvaluatePrResponse; span: ObservabilitySpan }> {
  const traceparent = createTraceparent();
  const startedAt = performance.now();

  const isViteDev = Boolean(
    (import.meta as unknown as { env?: { DEV?: boolean } }).env?.DEV
  );

  if (!isViteDev && edgeApiAvailable !== false) {
    try {
      const response = await fetch('/api/devsecops-gatekeeper/evaluate-pr', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': params.sessionId,
          traceparent
        },
        body: JSON.stringify({
          sessionId: params.sessionId,
          pr_preset: params.presetId,
          policy_clauses: params.clauses
        })
      });

      const contentType = response.headers.get('Content-Type') || '';
      if (contentType.includes('application/json') && (response.status === 200 || response.status === 403)) {
        edgeApiAvailable = true;
        const data = (await response.json()) as EvaluatePrResponse & {
          _telemetry?: { traceparent?: string; latency_ms?: number };
        };
        const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
        return {
          result: data,
          span: createSpan({
            sessionId: params.sessionId,
            traceparent: data._telemetry?.traceparent || traceparent,
            method: 'POST',
            path: '/api/devsecops-gatekeeper/evaluate-pr',
            status: response.status,
            latencyMs: data._telemetry?.latency_ms ?? latencyMs,
            origin: 'cloudflare-edge',
            summary: {
              pr_preset: data.pr_preset,
              decision: data.decision,
              findings_count: data.findings.length,
              unmet_clauses: data.unmet_clauses,
              cosign_verified: Boolean(data.cosign_attestation)
            }
          })
        };
      }
      edgeApiAvailable = false;
    } catch {
      edgeApiAvailable = false;
    }
  }

  const localResult = evaluatePrLocally(params.presetId, params.clauses, params.sessionId);
  const latencyMs = Math.max(1, Math.round(performance.now() - startedAt));
  return {
    result: localResult,
    span: createSpan({
      sessionId: params.sessionId,
      traceparent,
      method: 'POST',
      path: '/api/devsecops-gatekeeper/evaluate-pr',
      status: localResult.http_status,
      latencyMs,
      origin: 'browser-webcrypto-fallback',
      summary: {
        pr_preset: localResult.pr_preset,
        decision: localResult.decision,
        findings_count: localResult.findings.length,
        unmet_clauses: localResult.unmet_clauses,
        cosign_verified: Boolean(localResult.cosign_attestation)
      }
    })
  };
}

export function renderOpaRegoPolicy(clauses: PolicyClauses): string {
  return `package 0trust.admission

import future.keywords.if

default allow := false

# 1. Immutable 40-char SHA Action pinning
require_pinned_sha := ${clauses.require_pinned_sha}
# 2. Zero hardcoded secrets (Gitleaks)
block_secrets := ${clauses.block_secrets}
# 3. Sigstore Cosign OIDC keyless signature
require_cosign_oidc := ${clauses.require_cosign_oidc}
# 4. Private IaC ACLs (Checkov)
block_public_acl := ${clauses.block_public_acl}

allow if {
  require_pinned_sha
  block_secrets
  require_cosign_oidc
  block_public_acl
  count(input.scanner_findings) == 0
  input.cosign.verified_oidc == true
}`;
}

export function exportAttestationReport(state: DevSecOpsLabState): string {
  return JSON.stringify(
    {
      lab_id: 'devsecops-gatekeeper',
      session_id: state.session_id,
      correlation_id: state.correlation_id,
      policy_clauses: state.policy_clauses,
      deployed_attested: state.deployed_attested,
      evaluated_presets: state.evaluated_presets,
      last_evaluation: state.last_evaluation,
      exported_at: new Date().toISOString()
    },
    null,
    2
  );
}
