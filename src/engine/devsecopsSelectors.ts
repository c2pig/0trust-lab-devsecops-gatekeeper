import { EvaluatePrResponse, PolicyClauses } from '../contracts/devsecopsContract';

export type DevSecOpsSeatId = 'developer' | 'appsec-gate';

export interface DevSecOpsSeatBadge {
  text: string;
  tone: 'crimson' | 'blue' | 'amber';
  pulse: boolean;
}

export interface DevSecOpsSeatDescriptor {
  id: DevSecOpsSeatId;
  name: string;
  roleLabel: string;
  appLabel: string;
  avatarInitials: string;
  badge: DevSecOpsSeatBadge | null;
}

export function countEnabledClauses(clauses: PolicyClauses): number {
  return Object.values(clauses).filter(Boolean).length;
}

export function areAllClausesHardened(clauses: PolicyClauses): boolean {
  return countEnabledClauses(clauses) === 4;
}

export function getGlobalStatusLabel(
  deployedAttested: boolean,
  clauses: PolicyClauses
): string {
  if (deployedAttested) {
    return 'Release Attested';
  }
  const enabledCount = countEnabledClauses(clauses);
  return enabledCount === 4 ? 'Policy Hardened (4/4)' : `Policy ${enabledCount}/4`;
}

export function buildDevSecOpsSeats(params: {
  clauses: PolicyClauses;
  deployedAttested: boolean;
  activeEval: EvaluatePrResponse | null;
}): DevSecOpsSeatDescriptor[] {
  const enabledClauseCount = countEnabledClauses(params.clauses);
  const allClausesHardened = enabledClauseCount === 4;

  const devNeedsAction =
    (allClausesHardened && !params.deployedAttested) ||
    params.activeEval?.decision === 'DENY';

  const appSecNeedsAction = !allClausesHardened;

  return [
    {
      id: 'developer',
      name: 'Jordan Lee',
      roleLabel: 'Developer',
      appLabel: 'Git Pull Requests & CI',
      avatarInitials: 'JL',
      badge: devNeedsAction
        ? {
            text: params.activeEval?.decision === 'DENY' ? 'Checks Failed' : 'Ready to Verify',
            tone: params.activeEval?.decision === 'DENY' ? 'crimson' : 'blue',
            pulse: true
          }
        : null
    },
    {
      id: 'appsec-gate',
      name: 'Sora Takahashi',
      roleLabel: 'AppSec',
      appLabel: 'Policy Gate & Release Approval',
      avatarInitials: 'ST',
      badge: appSecNeedsAction
        ? {
            text: `${enabledClauseCount}/4 Rules`,
            tone: 'amber',
            pulse: true
          }
        : null
    }
  ];
}
