import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { onRequestPost } from '../functions/api/devsecops-gatekeeper/evaluate-pr.ts';
import { MemoryKvAdapter } from '../server/kvAdapter.ts';
import { evaluatePrLocally } from '../src/engine/devsecopsEngine.ts';
import {
  PolicyClauses,
  PrPresetId
} from '../src/contracts/devsecopsContract.ts';

const ALL_HARDENED_CLAUSES: PolicyClauses = {
  require_pinned_sha: true,
  block_secrets: true,
  require_cosign_oidc: true,
  block_public_acl: true
};

function buildEvaluateRequest(
  body: unknown,
  sessionId = 'lab4-api-test-session'
): Request {
  return new Request('https://lab.0trust.dev/api/devsecops-gatekeeper/evaluate-pr', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

describe('Lab 4 API — /api/devsecops-gatekeeper/evaluate-pr', () => {
  it('enforces 4-clause OPA/Rego truth table: any single disabled clause returns 403 DENY, all 4 enabled returns 200 ALLOW', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });
    const clauseKeys: Array<keyof PolicyClauses> = [
      'require_pinned_sha',
      'block_secrets',
      'require_cosign_oidc',
      'block_public_acl'
    ];

    for (const disabledClause of clauseKeys) {
      const clauses: PolicyClauses = {
        ...ALL_HARDENED_CLAUSES,
        [disabledClause]: false
      };
      const res = await onRequestPost({
        request: buildEvaluateRequest(
          { pr_preset: 'CLEAN_PR', policy_clauses: clauses },
          `truth-${disabledClause}`
        ),
        env: { STATE_KV: kv, ENVIRONMENT: 'test' }
      });

      assert.equal(res.status, 403, `Expected 403 when ${disabledClause} is false`);
      const data = (await res.json()) as {
        decision: string;
        unmet_clauses: string[];
        cosign_attestation: unknown;
        opa_trace: { allow: boolean };
      };
      assert.equal(data.decision, 'DENY');
      assert.equal(data.opa_trace.allow, false);
      assert.equal(data.cosign_attestation, null);
      assert.deepEqual(data.unmet_clauses, [disabledClause]);
    }

    const allowRes = await onRequestPost({
      request: buildEvaluateRequest(
        { pr_preset: 'CLEAN_PR', policy_clauses: ALL_HARDENED_CLAUSES },
        'truth-all-enabled'
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(allowRes.status, 200);
    const allowData = (await allowRes.json()) as {
      decision: string;
      unmet_clauses: string[];
      cosign_attestation: { verification_status: string } | null;
      opa_trace: { allow: boolean };
    };
    assert.equal(allowData.decision, 'ALLOW');
    assert.equal(allowData.opa_trace.allow, true);
    assert.deepEqual(allowData.unmet_clauses, []);
    assert.equal(allowData.cosign_attestation?.verification_status, 'VERIFIED_KEYLESS_OIDC');
  });

  it('maintains edge fallback parity between evaluatePrLocally and /evaluate-pr across all presets', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });
    const presets: PrPresetId[] = [
      'TYPOSQUAT_DEP',
      'LEAKED_SECRET',
      'UNPINNED_ACTION',
      'PUBLIC_IAC_ACL',
      'CLEAN_PR'
    ];

    for (const preset of presets) {
      const local = evaluatePrLocally(preset, ALL_HARDENED_CLAUSES, 'parity-session');
      const res = await onRequestPost({
        request: buildEvaluateRequest(
          { pr_preset: preset, policy_clauses: ALL_HARDENED_CLAUSES },
          'parity-session'
        ),
        env: { STATE_KV: kv, ENVIRONMENT: 'test' }
      });

      assert.equal(res.status, local.http_status);
      const api = (await res.json()) as {
        decision: string;
        http_status: number;
        unmet_clauses: string[];
        opa_trace: { allow: boolean };
        findings: Array<{ id: string }>;
      };
      assert.equal(api.decision, local.decision);
      assert.equal(api.http_status, local.http_status);
      assert.deepEqual(api.unmet_clauses, local.unmet_clauses);
      assert.equal(api.opa_trace.allow, local.opa_trace.allow);
      assert.equal(api.findings.length, local.findings.length);
    }
  });

  it('fails closed on invalid payloads (413, 400) and isolates KV state per session', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });

    const oversizedRes = await onRequestPost({
      request: buildEvaluateRequest(
        JSON.stringify({ pr_preset: 'CLEAN_PR', pad: 'a'.repeat(65 * 1024) }),
        'oversized'
      ),
      env: { STATE_KV: kv }
    });
    assert.equal(oversizedRes.status, 413);

    const badJsonRes = await onRequestPost({
      request: buildEvaluateRequest('{broken', 'bad-json'),
      env: { STATE_KV: kv }
    });
    assert.equal(badJsonRes.status, 400);

    const invalidPresetRes = await onRequestPost({
      request: buildEvaluateRequest({ pr_preset: 'UNKNOWN_PRESET' }, 'bad-preset'),
      env: { STATE_KV: kv }
    });
    assert.equal(invalidPresetRes.status, 400);

    await onRequestPost({
      request: buildEvaluateRequest(
        { pr_preset: 'CLEAN_PR', policy_clauses: ALL_HARDENED_CLAUSES },
        'session-alpha'
      ),
      env: { STATE_KV: kv }
    });
    await onRequestPost({
      request: buildEvaluateRequest(
        { pr_preset: 'LEAKED_SECRET', policy_clauses: ALL_HARDENED_CLAUSES },
        'session-beta'
      ),
      env: { STATE_KV: kv }
    });

    const alphaRaw = await kv.get('lab4:devsecops:session-alpha');
    const betaRaw = await kv.get('lab4:devsecops:session-beta');
    assert.ok(alphaRaw && betaRaw);
    const alpha = JSON.parse(alphaRaw) as { evaluations_count: number; last_decision: string };
    const beta = JSON.parse(betaRaw) as { evaluations_count: number; last_decision: string };
    assert.equal(alpha.evaluations_count, 1);
    assert.equal(alpha.last_decision, 'ALLOW');
    assert.equal(beta.evaluations_count, 1);
    assert.equal(beta.last_decision, 'DENY');
  });
});
