import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  createInitialLabState,
  evaluatePrLocally,
  exportAttestationReport,
  renderOpaRegoPolicy
} from '../src/engine/devsecopsEngine.ts';
import {
  INITIAL_PERMISSIVE_CLAUSES,
  PolicyClauses
} from '../src/contracts/devsecopsContract.ts';

const ALL_HARDENED_CLAUSES: PolicyClauses = {
  require_pinned_sha: true,
  block_secrets: true,
  require_cosign_oidc: true,
  block_public_acl: true
};

describe('Lab 4 Engine — devsecopsEngine', () => {
  it('evaluatePrLocally enforces all 4 OPA/Rego clauses and blocks poisoned presets', () => {
    const cleanAllowed = evaluatePrLocally('CLEAN_PR', ALL_HARDENED_CLAUSES, 'eng-sess-1');
    assert.equal(cleanAllowed.decision, 'ALLOW');
    assert.equal(cleanAllowed.http_status, 200);
    assert.deepEqual(cleanAllowed.unmet_clauses, []);
    assert.ok(cleanAllowed.cosign_attestation);

    const poisonedDenied = evaluatePrLocally('TYPOSQUAT_DEP', ALL_HARDENED_CLAUSES, 'eng-sess-1');
    assert.equal(poisonedDenied.decision, 'DENY');
    assert.equal(poisonedDenied.http_status, 403);
    assert.equal(poisonedDenied.cosign_attestation, null);
    assert.ok(poisonedDenied.findings.length > 0);

    const clauseKeys: Array<keyof PolicyClauses> = [
      'require_pinned_sha',
      'block_secrets',
      'require_cosign_oidc',
      'block_public_acl'
    ];
    for (const key of clauseKeys) {
      const res = evaluatePrLocally(
        'CLEAN_PR',
        { ...ALL_HARDENED_CLAUSES, [key]: false },
        'eng-sess-1'
      );
      assert.equal(res.decision, 'DENY');
      assert.deepEqual(res.unmet_clauses, [key]);
    }
  });

  it('renderOpaRegoPolicy reflects toggled clauses accurately', () => {
    const permissive = renderOpaRegoPolicy(INITIAL_PERMISSIVE_CLAUSES);
    assert.ok(permissive.includes('require_cosign_oidc := false'));
    assert.ok(permissive.includes('block_public_acl := false'));

    const hardened = renderOpaRegoPolicy(ALL_HARDENED_CLAUSES);
    assert.ok(hardened.includes('require_pinned_sha := true'));
    assert.ok(hardened.includes('block_secrets := true'));
    assert.ok(hardened.includes('require_cosign_oidc := true'));
    assert.ok(hardened.includes('block_public_acl := true'));
  });

  it('exportAttestationReport produces deterministic JSON metadata and verdict', () => {
    const state = createInitialLabState('eng-export-sess');
    state.policy_clauses = { ...ALL_HARDENED_CLAUSES };
    state.last_evaluation = evaluatePrLocally('CLEAN_PR', ALL_HARDENED_CLAUSES, 'eng-export-sess');
    state.deployed_attested = true;

    const parsed = JSON.parse(exportAttestationReport(state)) as {
      lab_id: string;
      session_id: string;
      deployed_attested: boolean;
      last_evaluation: { decision: string };
      exported_at: string;
    };
    assert.equal(parsed.lab_id, 'devsecops-gatekeeper');
    assert.equal(parsed.session_id, 'eng-export-sess');
    assert.equal(parsed.deployed_attested, true);
    assert.equal(parsed.last_evaluation.decision, 'ALLOW');
    assert.ok(parsed.exported_at);
  });
});
