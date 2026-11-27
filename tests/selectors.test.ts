import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  areAllClausesHardened,
  buildDevSecOpsSeats,
  countEnabledClauses,
  getGlobalStatusLabel
} from '../src/engine/devsecopsSelectors.ts';
import { evaluatePrLocally } from '../src/engine/devsecopsEngine.ts';
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

describe('Lab 4 Selectors — devsecopsSelectors', () => {
  it('computes clause counts, hardening state, and global status label', () => {
    const initialCount = Object.values(INITIAL_PERMISSIVE_CLAUSES).filter(Boolean).length;
    assert.equal(countEnabledClauses(INITIAL_PERMISSIVE_CLAUSES), initialCount);
    assert.equal(areAllClausesHardened(INITIAL_PERMISSIVE_CLAUSES), false);
    assert.equal(getGlobalStatusLabel(false, INITIAL_PERMISSIVE_CLAUSES), `Policy ${initialCount}/4`);

    assert.equal(countEnabledClauses(ALL_HARDENED_CLAUSES), 4);
    assert.equal(areAllClausesHardened(ALL_HARDENED_CLAUSES), true);
    assert.equal(getGlobalStatusLabel(false, ALL_HARDENED_CLAUSES), 'Policy Hardened (4/4)');
    assert.equal(getGlobalStatusLabel(true, ALL_HARDENED_CLAUSES), 'Release Attested');
  });

  it('builds seat badges for permissive, denied, and attested states', () => {
    const permissiveSeats = buildDevSecOpsSeats({
      clauses: INITIAL_PERMISSIVE_CLAUSES,
      deployedAttested: false,
      activeEval: null
    });
    assert.equal(permissiveSeats[0]?.badge, null);
    assert.equal(
      permissiveSeats[1]?.badge?.text,
      `${Object.values(INITIAL_PERMISSIVE_CLAUSES).filter(Boolean).length}/4 Rules`
    );
    assert.equal(permissiveSeats[1]?.badge?.tone, 'amber');

    const deniedEval = evaluatePrLocally('LEAKED_SECRET', ALL_HARDENED_CLAUSES, 'sel-sess');
    const deniedSeats = buildDevSecOpsSeats({
      clauses: ALL_HARDENED_CLAUSES,
      deployedAttested: false,
      activeEval: deniedEval
    });
    assert.equal(deniedSeats[0]?.badge?.text, 'Checks Failed');
    assert.equal(deniedSeats[0]?.badge?.tone, 'crimson');
    assert.equal(deniedSeats[1]?.badge, null);

    const attestedSeats = buildDevSecOpsSeats({
      clauses: ALL_HARDENED_CLAUSES,
      deployedAttested: true,
      activeEval: evaluatePrLocally('CLEAN_PR', ALL_HARDENED_CLAUSES, 'sel-sess')
    });
    assert.equal(attestedSeats[0]?.badge, null);
    assert.equal(attestedSeats[1]?.badge, null);
  });
});
