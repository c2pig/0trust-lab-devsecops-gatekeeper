# Architecture — `0trust-lab-devsecops-gatekeeper` (Lab 4)

## Overview
`0trust-lab-devsecops-gatekeeper` is a standalone Model 1 Zero Trust interactive lab hosted on Cloudflare Pages (`0trust-lab-devsecops-gatekeeper.pages.dev`) and routed via `0trust-lab-router` at `https://lab.0trust.dev/devsecops-gatekeeper`.

![DevSecOps Gatekeeper Architecture](diagrams/devsecops_gatekeeper_architecture.svg)

## Key Boundaries & Components
1. **2-Seat Role Switcher (`developer` ↔ `appsec-gate`)**:
   - **Platform Dev (`Jordan Lee`)**: Authors Pull Requests (`PR #418`–`PR #422`), triggers CI scans, remediates findings, and runs `Deploy PR`.
   - **AppSec Gatekeeper (`Sora Takahashi`)**: Inspects smoking-gun scanner findings in POE mode to unlock the OPA/Rego policy patcher, enforces all 4 admission clauses (`require_pinned_sha`, `block_secrets`, `require_cosign_oidc`, `block_public_acl`), and verifies keyless Cosign OIDC attestations.
2. **4-Phase Cognitive Arc + POE Gate**:
   - **Discovery**: Interactive 5-stage PR-to-Production pipeline map.
   - **Understanding (POE)**: Predict-Observe-Explain across 4 poisoned PR presets (`TYPOSQUAT_DEP`, `LEAKED_SECRET`, `UNPINNED_ACTION`, `PUBLIC_IAC_ACL`). Clicking the smoking-gun diff line unlocks Phase 3.
   - **Practice**: Live OPA/Rego policy patcher + PR remediation & `Deploy PR` runner.
   - **Reflection**: Security vs. velocity scorecard, trap checklist, and exportable JSON attestation bundle.
3. **Edge API & `STATE_KV` Isolation (`functions/api/devsecops-gatekeeper/evaluate-pr.ts`)**:
   - Enforces `MAX_BODY_BYTES = 65536`, strict `Set`-based `pr_preset` validation, `sanitizeSessionId()`, `Cache-Control: no-store`, and `lab4:devsecops:<sessionId>` KV persistence with `expirationTtl: 3600` (1h TTL).
   - **Fail-Closed Policy Gate**: Returns `HTTP 403 DENY` whenever any required OPA/Rego clause is disabled or any scanner finding is active; returns `HTTP 200 ALLOW` with synthetic Sigstore Cosign OIDC bundle only when `CLEAN_PR` and all 4 clauses pass.
   - **`$0/mo` Client Fallback**: When Edge Functions are absent (e.g., `vite dev`), `src/engine/devsecopsEngine.ts` runs deterministic client-side evaluation with zero console errors.
