import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCloudRunApp, verifyRouterSecret } from '../server/app';
import {
  buildKvDocId,
  FirestoreKvAdapter,
  MemoryKvAdapter,
  type FirestoreCollectionLike,
  type FirestoreKvDoc
} from '../server/kvAdapter';
import { resolvePublicOrigin } from '../server/origin';

const TEST_ROUTER_SECRET = 'test-router-secret-value-0123456789';

function createMockFirestoreCollection(): {
  collection: FirestoreCollectionLike;
  store: Map<string, FirestoreKvDoc>;
} {
  const store = new Map<string, FirestoreKvDoc>();
  const collection: FirestoreCollectionLike = {
    doc(id: string) {
      return {
        async get() {
          const data = store.get(id);
          return {
            exists: Boolean(data),
            data: () => data
          };
        },
        async set(data: FirestoreKvDoc) {
          store.set(id, data);
        },
        async delete() {
          store.delete(id);
        }
      };
    }
  };
  return { collection, store };
}

const ALL_CLAUSES_ENABLED = {
  require_pinned_sha: true,
  block_secrets: true,
  require_cosign_oidc: true,
  block_public_acl: true
};

describe('Lab 4 (DevSecOps Gatekeeper) Cloud Run Adapter — Security & API Invariants', () => {
  it('blocks direct *.run.app /api/* requests without or with invalid X-Lab-Router-Secret (fail-closed 403)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'devsecops-gatekeeper',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' })
    });

    const payload = JSON.stringify({
      pr_preset: 'CLEAN_PR',
      policy_clauses: ALL_CLAUSES_ENABLED
    });

    // Missing header
    const resMissing = await app.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
      }
    );
    assert.equal(resMissing.status, 403);
    assert.deepEqual(await resMissing.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Wrong secret (same length & different length)
    const resWrongSameLen = await app.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'wrong-router-secret-value-987654321'
        },
        body: payload
      }
    );
    assert.equal(resWrongSameLen.status, 403);
    assert.deepEqual(await resWrongSameLen.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    const resWrongDiffLen = await app.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'short'
        },
        body: payload
      }
    );
    assert.equal(resWrongDiffLen.status, 403);

    // Fail-closed when LAB_ROUTER_SECRET is unset in production
    const appUnconfigured = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'devsecops-gatekeeper'
      },
      kv: new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' })
    });
    const resUnconfigured = await appUnconfigured.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: payload
      }
    );
    assert.equal(resUnconfigured.status, 403);
    assert.deepEqual(await resUnconfigured.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Valid secret succeeds
    const resValid = await app.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: payload
      }
    );
    assert.equal(resValid.status, 200);
    const json = (await resValid.json()) as { decision: string };
    assert.equal(json.decision, 'ALLOW');
    assert.equal(verifyRouterSecret(TEST_ROUTER_SECRET, TEST_ROUTER_SECRET), true);
  });

  it('serves GET /healthz without X-Lab-Router-Secret (Cloud Run probe)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'devsecops-gatekeeper',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' })
    });

    const res = await app.request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/healthz'
    );
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, lab: 'devsecops-gatekeeper' });
  });

  it('synchronously returns null on expired TTL docs in FirestoreKvAdapter & MemoryKvAdapter', async () => {
    let nowMs = 1_700_000_000_000;
    const { collection, store } = createMockFirestoreCollection();
    const firestoreKv = new FirestoreKvAdapter({
      labSlug: 'devsecops-gatekeeper',
      collectionRef: collection,
      nowFn: () => nowMs
    });

    await firestoreKv.put('lab4:devsecops:session/1', '{"evaluations_count":1}', {
      expirationTtl: 3600
    });
    const expectedDocId = buildKvDocId('devsecops-gatekeeper', 'lab4:devsecops:session/1');
    assert.equal(expectedDocId, 'devsecops-gatekeeper:lab4%3Adevsecops%3Asession%2F1');

    const storedDoc = store.get(expectedDocId);
    assert.ok(storedDoc);
    assert.equal(storedDoc.labSlug, 'devsecops-gatekeeper');
    assert.equal(storedDoc.value, '{"evaluations_count":1}');
    assert.equal(storedDoc.expireAt?.toMillis(), nowMs + 3_600_000);

    // Before expiry
    assert.equal(await firestoreKv.get('lab4:devsecops:session/1'), '{"evaluations_count":1}');

    // Advance clock past TTL without deleting the doc from Firestore (simulating delayed reaper)
    nowMs += 3_600_000;
    assert.equal(store.has(expectedDocId), true);
    assert.equal(await firestoreKv.get('lab4:devsecops:session/1'), null);

    // MemoryKvAdapter parity
    let memNow = 1_700_000_000_000;
    const memKv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper', nowFn: () => memNow });
    await memKv.put('lab4:devsecops:abc', 'ok', { expirationTtl: 10 });
    assert.equal(await memKv.get('lab4:devsecops:abc'), 'ok');
    memNow += 10_000;
    assert.equal(await memKv.get('lab4:devsecops:abc'), null);
  });

  it('rejects forged X-Forwarded-Host headers and allows lab.0trust.dev & localhost:5179', () => {
    const forgedReq = new Request(
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
      { headers: { 'x-forwarded-host': 'evil.com', 'x-forwarded-proto': 'https' } }
    );
    assert.equal(
      resolvePublicOrigin(forgedReq),
      'https://0trust-lab-devsecops-gatekeeper-abc.run.app'
    );

    const localReq = new Request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      { headers: { 'x-forwarded-host': 'localhost:5179', 'x-forwarded-proto': 'http' } }
    );
    assert.equal(resolvePublicOrigin(localReq), 'http://localhost:5179');
  });

  it('redacts JWT signatures in _telemetry and never leaks X-Lab-Router-Secret or OTLP_AUTH_HEADER', async () => {
    const otlpAuthSecret = 'Bearer otlp-super-secret-header-token';
    const capturedOtlpBodies: string[] = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      capturedOtlpBodies.push(String(init?.body || ''));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    try {
      const app = createCloudRunApp({
        env: {
          ENVIRONMENT: 'production',
          LAB_SLUG: 'devsecops-gatekeeper',
          LAB_ROUTER_SECRET: TEST_ROUTER_SECRET,
          OTLP_ENDPOINT: 'https://otlp.example.com',
          OTLP_AUTH_HEADER: otlpAuthSecret
        },
        kv: new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' })
      });

      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.SuperSecretSignatureXYZ123';
      const res = await app.request(
        'https://0trust-lab-devsecops-gatekeeper-abc.run.app/api/devsecops-gatekeeper/evaluate-pr',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-lab-router-secret': TEST_ROUTER_SECRET,
            authorization: `Bearer ${fakeJwt}`,
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
          },
          body: JSON.stringify({
            pr_preset: 'CLEAN_PR',
            policy_clauses: ALL_CLAUSES_ENABLED
          })
        }
      );

      assert.equal(res.status, 200);
      assert.ok(res.headers.get('traceparent')?.startsWith('00-4bf92f3577b34da6a3ce929d0e0e4736-'));
      assert.ok(res.headers.get('X-Edge-Latency-Ms'));

      const bodyText = await res.text();
      assert.ok(!bodyText.includes('SuperSecretSignatureXYZ123'), 'JWT signature must be redacted');
      assert.ok(!bodyText.includes(TEST_ROUTER_SECRET), 'Router secret must never appear in response');
      assert.ok(!bodyText.includes(otlpAuthSecret), 'OTLP auth header must never appear in response');

      const parsed = JSON.parse(bodyText) as {
        _telemetry: { redacted_auth_header: string; redaction_applied: boolean };
      };
      assert.equal(parsed._telemetry.redaction_applied, true);
      assert.equal(
        parsed._telemetry.redacted_auth_header,
        'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.***REDACTED***'
      );

      await new Promise((r) => setTimeout(r, 10));
      assert.equal(capturedOtlpBodies.length, 2);
      for (const otlpBody of capturedOtlpBodies) {
        assert.ok(!otlpBody.includes(TEST_ROUTER_SECRET));
        assert.ok(!otlpBody.includes('SuperSecretSignatureXYZ123'));
        assert.ok(!otlpBody.includes(otlpAuthSecret));
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('executes happy-path DENY (poisoned PR) and ALLOW (clean PR + 4/4 clauses) with KV persistence', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'devsecops-gatekeeper'
      },
      kv
    });

    const sessionId = 'lab4-happy-session';

    // 1. Poisoned PR -> 403 DENY
    const denyRes = await app.request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
        body: JSON.stringify({
          pr_preset: 'LEAKED_SECRET',
          policy_clauses: ALL_CLAUSES_ENABLED
        })
      }
    );
    assert.equal(denyRes.status, 403);
    const denyData = (await denyRes.json()) as {
      decision: string;
      pr_preset: string;
      cosign_attestation: unknown;
      findings: Array<{ scanner: string }>;
    };
    assert.equal(denyData.decision, 'DENY');
    assert.equal(denyData.pr_preset, 'LEAKED_SECRET');
    assert.equal(denyData.cosign_attestation, null);
    assert.equal(denyData.findings[0]?.scanner, 'GITLEAKS');

    // 2. Clean PR with all 4 clauses -> 200 ALLOW + keyless Cosign attestation
    const allowRes = await app.request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
        body: JSON.stringify({
          pr_preset: 'CLEAN_PR',
          policy_clauses: ALL_CLAUSES_ENABLED
        })
      }
    );
    assert.equal(allowRes.status, 200);
    const allowData = (await allowRes.json()) as {
      decision: string;
      cosign_attestation: { verification_status: string } | null;
      opa_trace: { allow: boolean };
    };
    assert.equal(allowData.decision, 'ALLOW');
    assert.equal(allowData.opa_trace.allow, true);
    assert.equal(allowData.cosign_attestation?.verification_status, 'VERIFIED_KEYLESS_OIDC');

    // 3. Verify KV state persisted incremented evaluations_count = 2
    const storedRaw = await kv.get(`lab4:devsecops:${sessionId}`);
    assert.ok(storedRaw);
    const stored = JSON.parse(storedRaw) as { evaluations_count: number; last_decision: string };
    assert.equal(stored.evaluations_count, 2);
    assert.equal(stored.last_decision, 'ALLOW');
  });

  it('returns 413 PAYLOAD_TOO_LARGE for >64KB JSON bodies', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });
    const app = createCloudRunApp({
      env: { ENVIRONMENT: 'development', LAB_SLUG: 'devsecops-gatekeeper' },
      kv
    });

    const oversized = JSON.stringify({
      pr_preset: 'CLEAN_PR',
      policy_clauses: ALL_CLAUSES_ENABLED,
      padding: 'x'.repeat(65 * 1024)
    });

    const res = await app.request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Session-Id': 'lab4-oversized' },
        body: oversized
      }
    );
    assert.equal(res.status, 413);
    const data = (await res.json()) as { error: string };
    assert.equal(data.error, 'PAYLOAD_TOO_LARGE');
  });

  it('returns 400 fail-closed for malformed JSON and missing pr_preset', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'devsecops-gatekeeper' });
    const app = createCloudRunApp({
      env: { ENVIRONMENT: 'development', LAB_SLUG: 'devsecops-gatekeeper' },
      kv
    });

    const badJsonRes = await app.request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Session-Id': 'lab4-bad-json' },
        body: '{not-valid-json'
      }
    );
    assert.equal(badJsonRes.status, 400);
    const badJsonData = (await badJsonRes.json()) as { error: string };
    assert.equal(badJsonData.error, 'INVALID_JSON');

    const missingPresetRes = await app.request(
      'http://127.0.0.1:8080/api/devsecops-gatekeeper/evaluate-pr',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Session-Id': 'lab4-missing-preset' },
        body: JSON.stringify({ policy_clauses: ALL_CLAUSES_ENABLED })
      }
    );
    assert.equal(missingPresetRes.status, 400);
    const missingPresetData = (await missingPresetRes.json()) as { error: string };
    assert.equal(missingPresetData.error, 'INVALID_PR_PRESET');
  });
});
