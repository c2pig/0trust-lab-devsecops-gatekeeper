import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Compass, Download, GitPullRequest, RotateCcw, ShieldCheck } from 'lucide-react';
import { driver } from 'driver.js';
import 'driver.js/dist/driver.css';
import {
  DevSecOpsLabState,
  DevSecOpsSeatId,
  EvaluatePrResponse,
  HARDENED_POLICY_CLAUSES,
  PR_PRESETS,
  PolicyClauses,
  PrPresetId
} from '../contracts/devsecopsContract';
import {
  createInitialLabState,
  createSessionId,
  createSpan,
  evaluatePrWithEdgeFallback,
  exportAttestationReport,
  renderOpaRegoPolicy
} from '../engine/devsecopsEngine';
import {
  areAllClausesHardened,
  buildDevSecOpsSeats,
  countEnabledClauses,
  getGlobalStatusLabel
} from '../engine/devsecopsSelectors';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import { XRayDecodedProofSection, XRayTelemetryDrawer } from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface DevSecOpsGatekeeperPageProps {
  onBack: () => void;
}

const PR_ORDER: PrPresetId[] = [
  'CLEAN_PR',
  'TYPOSQUAT_DEP',
  'LEAKED_SECRET',
  'UNPINNED_ACTION',
  'PUBLIC_IAC_ACL'
];

const CLAUSE_ROWS: Array<{
  key: keyof PolicyClauses;
  name: string;
  control: string;
  description: string;
}> = [
  {
    key: 'require_pinned_sha',
    name: 'require_pinned_sha',
    control: 'GitHub Actions Integrity',
    description: 'Require immutable 40-character commit SHAs for workflow actions instead of mutable branch tags.'
  },
  {
    key: 'block_secrets',
    name: 'block_secrets',
    control: 'Secret Detection (Gitleaks)',
    description: 'Fail closed whenever hardcoded credentials or high-entropy API keys are detected in diffs.'
  },
  {
    key: 'require_cosign_oidc',
    name: 'require_cosign_oidc',
    control: 'Artifact Attestation (Cosign OIDC)',
    description: 'Require verified keyless Sigstore Cosign OIDC attestation logged to Rekor before release.'
  },
  {
    key: 'block_public_acl',
    name: 'block_public_acl',
    control: 'IaC Storage Policy (Checkov)',
    description: 'Block public-read storage ACLs and overly permissive infrastructure definitions.'
  }
];

export function DevSecOpsGatekeeperPage({ onBack }: DevSecOpsGatekeeperPageProps) {
  const [sessionId, setSessionId] = useState<string>(() => createSessionId());
  const sessionIdRef = useRef<string>(sessionId);
  sessionIdRef.current = sessionId;

  const [activeSeat, setActiveSeat] = useState<DevSecOpsSeatId>('developer');
  const [state, setState] = useState<DevSecOpsLabState>(() => {
    const initial = createInitialLabState(sessionId);
    return { ...initial, selected_preset: 'CLEAN_PR' };
  });
  const [prEvaluations, setPrEvaluations] = useState<
    Partial<Record<PrPresetId, EvaluatePrResponse>>
  >({});
  const [evaluatingPr, setEvaluatingPr] = useState<PrPresetId | null>(null);
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);

  const tourLaunchedRef = useRef<boolean>(false);

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
  }, []);

  const startLabTour = useCallback(() => {
    const driverObj = driver({
      showProgress: true,
      animate: true,
      allowClose: true,
      overlayOpacity: 0.5,
      steps: [
        {
          popover: {
            title: 'Lab Orientation: DevSecOps & Supply-Chain Gatekeeper',
            description:
              'Explore how CI/CD supply-chain scanners (Syft SBOM, Gitleaks, Checkov, Cosign OIDC) and OPA/Rego admission policies govern Pull Request releases.'
          }
        },
        {
          element: '#tour-role-switcher',
          popover: {
            title: 'Role Switcher',
            description:
              'Switch between Jordan Lee (Developer) and Sora Takahashi (AppSec). Notification dots indicate pending policy rules or PR check results.'
          }
        },
        {
          element: '#tour-workspace',
          popover: {
            title: 'Role Workspace',
            description:
              'Start as Jordan Lee to inspect open Pull Requests and run CI security checks, then switch to Sora Takahashi to harden OPA admission rules and verify releases.'
          }
        },
        {
          element: '.xray-drawer',
          popover: {
            title: 'X-Ray Telemetry Drawer',
            description:
              'Expand this bottom drawer anytime to inspect live HTTP spans, CycloneDX SBOMs, scanner findings, OPA traces, and Cosign OIDC attestations.'
          }
        },
        {
          element: '#tour-lab-controls',
          popover: {
            title: 'Lab Controls',
            description:
              'Use Lab Tour to replay this orientation, or Reset to restore the initial PR queue and baseline policy state.'
          }
        }
      ]
    });
    driverObj.drive();
  }, []);

  useEffect(() => {
    if (tourLaunchedRef.current) return;
    tourLaunchedRef.current = true;
    const timer = window.setTimeout(() => {
      startLabTour();
    }, 300);
    return () => window.clearTimeout(timer);
  }, [startLabTour]);

  const enabledClauseCount = useMemo(
    () => countEnabledClauses(state.policy_clauses),
    [state.policy_clauses]
  );
  const allClausesHardened = areAllClausesHardened(state.policy_clauses);

  const handleReset = () => {
    const freshSid = createSessionId();
    sessionIdRef.current = freshSid;
    const freshState = createInitialLabState(freshSid);
    setSessionId(freshSid);
    setActiveSeat('developer');
    setState({ ...freshState, selected_preset: 'CLEAN_PR' });
    setPrEvaluations({});
    setEvaluatingPr(null);
    setSpans([
      createSpan({
        sessionId: freshSid,
        traceparent: freshState.traceparent,
        method: 'POST',
        path: '/api/devsecops-gatekeeper/reset',
        status: 200,
        latencyMs: 2,
        origin: 'browser-webcrypto-fallback',
        summary: {
          policy_posture: 'PERMISSIVE_BASELINE',
          session_id: freshSid
        }
      })
    ]);
  };

  const handleSelectPreset = (presetId: PrPresetId) => {
    setState((prev) => ({
      ...prev,
      selected_preset: presetId,
      last_evaluation: prEvaluations[presetId] ?? prev.last_evaluation
    }));
  };

  const handleRunGate = async (
    overridePreset?: PrPresetId,
    overrideClauses?: PolicyClauses
  ) => {
    const presetToRun = overridePreset ?? state.selected_preset;
    const clausesToUse = overrideClauses ?? state.policy_clauses;
    const currentSid = sessionIdRef.current;

    setEvaluatingPr(presetToRun);
    const { result, span } = await evaluatePrWithEdgeFallback({
      presetId: presetToRun,
      clauses: clausesToUse,
      sessionId: currentSid
    });

    if (sessionIdRef.current !== currentSid) return;

    recordSpan(span);
    setPrEvaluations((prev) => ({ ...prev, [presetToRun]: result }));
    setState((prev) => ({
      ...prev,
      selected_preset: presetToRun,
      policy_clauses: clausesToUse,
      last_evaluation: result,
      deployed_attested: prev.deployed_attested || result.decision === 'ALLOW',
      evaluated_presets: {
        ...prev.evaluated_presets,
        [presetToRun]: true
      }
    }));
    setEvaluatingPr(null);
  };

  const handleToggleClause = (key: keyof PolicyClauses) => {
    setState((prev) => ({
      ...prev,
      policy_clauses: {
        ...prev.policy_clauses,
        [key]: !prev.policy_clauses[key]
      }
    }));
  };

  const handleEnforceBaseline = () => {
    setState((prev) => ({
      ...prev,
      policy_clauses: { ...HARDENED_POLICY_CLAUSES }
    }));
  };

  const handleDownloadReport = () => {
    const blob = new Blob([exportAttestationReport(state)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lab4-devsecops-attestation-${state.correlation_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activePreset = PR_PRESETS[state.selected_preset];
  const activeEval = prEvaluations[state.selected_preset] ?? null;
  const regoCode = useMemo(
    () => renderOpaRegoPolicy(state.policy_clauses),
    [state.policy_clauses]
  );

  const globalStatusLabel = getGlobalStatusLabel(state.deployed_attested, state.policy_clauses);

  const seats: RoleSeatItem<DevSecOpsSeatId>[] = useMemo(
    () =>
      buildDevSecOpsSeats({
        clauses: state.policy_clauses,
        deployedAttested: state.deployed_attested,
        activeEval
      }),
    [state.policy_clauses, state.deployed_attested, activeEval]
  );

  const decodedProofSections: XRayDecodedProofSection[] = useMemo(() => {
    const evalData = activeEval ?? state.last_evaluation;
    return [
      {
        id: 'syft-sbom',
        label: 'Syft CycloneDX SBOM Snippet',
        payload: evalData?.syft_sbom ?? {
          bomFormat: 'CycloneDX',
          specVersion: '1.5',
          components: activePreset.sbomComponents
        }
      },
      {
        id: 'scanner-findings',
        label: 'Scanner Findings (Gitleaks / Checkov / Actions)',
        payload: evalData?.findings ?? activePreset.findings
      },
      {
        id: 'cosign-attestation',
        label: 'Sigstore Cosign OIDC Attestation',
        payload: evalData?.cosign_attestation ?? {
          status: 'PENDING_ATTESTATION',
          note: 'Requires clean scanner checks and 4/4 OPA admission rules.'
        }
      },
      {
        id: 'opa-rego-trace',
        label: 'OPA/Rego Admission Evaluation Trace',
        payload: evalData?.opa_trace ?? {
          package: '0trust.admission',
          policy_clauses: state.policy_clauses,
          allow: false
        }
      }
    ];
  }, [activeEval, state.last_evaluation, state.policy_clauses, activePreset]);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--bg-canvas)',
        color: 'var(--text-primary)'
      }}
    >
      {/* 1. Compact AppShell Top Header */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 40,
          backgroundColor: 'rgba(255, 255, 255, 0.96)',
          backdropFilter: 'blur(8px)',
          borderBottom: '1px solid var(--border-subtle)'
        }}
      >
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            padding: '0 16px',
            height: '56px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <button
              type="button"
              onClick={onBack}
              className="btn btn-sm"
              style={{ padding: '5px 9px' }}
              title="All Labs"
            >
              <ArrowLeft size={13} />
              <span>All Labs</span>
            </button>
            <span
              style={{
                fontSize: '14px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                whiteSpace: 'nowrap'
              }}
            >
              DevSecOps &amp; Supply-Chain Gatekeeper
            </span>
            <span
              className={`badge ${
                state.deployed_attested
                  ? 'badge-emerald'
                  : allClausesHardened
                    ? 'badge-blue'
                    : 'badge-amber'
              }`}
              style={{ whiteSpace: 'nowrap', fontSize: '12px' }}
            >
              {globalStatusLabel}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <RoleSwitcherBar
              seats={seats}
              activeSeatId={activeSeat}
              onSelectSeat={setActiveSeat}
              variant="dropdown"
              ariaLabel="Switch workspace persona"
            />

            <div id="tour-lab-controls" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                type="button"
                onClick={startLabTour}
                className="btn btn-sm"
                style={{
                  backgroundColor: 'var(--accent-primary-dim)',
                  borderColor: 'var(--accent-primary-border)',
                  color: 'var(--accent-primary-ink)',
                  fontSize: '13px'
                }}
              >
                <Compass size={14} />
                <span>Lab Tour</span>
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="btn btn-sm"
                style={{ fontSize: '13px' }}
              >
                <RotateCcw size={14} />
                <span>Reset</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* 2. Center Role Workspace */}
      <main id="tour-workspace" style={{ flex: 1, padding: '16px', paddingBottom: '88px' }}>
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px'
          }}
        >
          {/* ==================== SEAT 1: JORDAN LEE — GIT PULL REQUEST & CI CHECKS ==================== */}
          {activeSeat === 'developer' && (
            <section
              aria-label="Git Pull Request and CI Checks"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: '#0f172a',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#2563eb',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    <GitPullRequest size={15} />
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    GitHub Enterprise · Pull Requests &amp; CI Checks
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: '#e2e8f0' }}>
                  Jordan Lee · Developer
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                    Open Pull Requests
                  </h2>
                  <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '4px 0 0' }}>
                    Select a Pull Request to inspect changed files and run automated supply-chain CI checks.
                  </p>
                </div>

                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>PR</th>
                        <th>Title &amp; Branch</th>
                        <th>Files</th>
                        <th>CI Gate Status</th>
                        <th style={{ textAlign: 'right' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {PR_ORDER.map((presetId) => {
                        const pr = PR_PRESETS[presetId];
                        const evalRes = prEvaluations[presetId];
                        const isSelected = state.selected_preset === presetId;
                        const isRunning = evaluatingPr === presetId;
                        return (
                          <tr
                            key={presetId}
                            className={`clickable-row${isSelected ? ' selected-row' : ''}`}
                            onClick={() => handleSelectPreset(presetId)}
                          >
                            <td className="mono" style={{ fontWeight: 700, whiteSpace: 'nowrap' }}>
                              {pr.prNumber}
                            </td>
                            <td>
                              <div style={{ fontWeight: 600, fontSize: '14px' }}>{pr.title}</div>
                              <div className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                {pr.branch} · {pr.commitSha.slice(0, 8)}
                              </div>
                            </td>
                            <td style={{ whiteSpace: 'nowrap' }}>
                              {pr.changedFiles.length} {pr.changedFiles.length === 1 ? 'file' : 'files'}
                            </td>
                            <td>
                              {evalRes ? (
                                evalRes.decision === 'ALLOW' ? (
                                  <span className="badge badge-emerald">PASSED · ATTESTED</span>
                                ) : (
                                  <span className="badge badge-crimson">BLOCKED (403)</span>
                                )
                              ) : (
                                <span className="badge">OPEN</span>
                              )}
                            </td>
                            <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                              <button
                                type="button"
                                className="btn btn-primary btn-sm"
                                style={{ fontSize: '13px', padding: '6px 12px' }}
                                disabled={evaluatingPr !== null}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void handleRunGate(presetId);
                                }}
                              >
                                {isRunning ? 'Running CI…' : 'Run CI Checks'}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Selected PR Diff & CI Check Results */}
                <div
                  style={{
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-canvas)',
                    padding: '16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px'
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '14.5px', fontWeight: 700 }}>
                        {activePreset.prNumber}: {activePreset.title}
                      </div>
                      <div style={{ fontSize: '13.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        {activePreset.summary}
                      </div>
                    </div>
                    <span className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                      commit {activePreset.commitSha.slice(0, 12)}
                    </span>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      Changed Diff Preview
                    </div>
                    <pre
                      className="mono"
                      style={{
                        margin: 0,
                        padding: '12px 14px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--bg-surface)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '13px',
                        lineHeight: 1.6,
                        overflowX: 'auto',
                        color: 'var(--text-primary)'
                      }}
                    >
                      {activePreset.diffPreview
                        .map((line) => `${line.file}:${line.lineNo}  ${line.content}`)
                        .join('\n')}
                    </pre>
                  </div>

                  {activeEval && (
                    <div
                      style={{
                        padding: '12px 14px',
                        borderRadius: '8px',
                        backgroundColor:
                          activeEval.decision === 'ALLOW'
                            ? 'var(--accent-emerald-dim)'
                            : 'var(--accent-crimson-dim)',
                        border: `1px solid ${
                          activeEval.decision === 'ALLOW'
                            ? 'var(--accent-emerald-border)'
                            : 'var(--accent-crimson-border)'
                        }`,
                        color:
                          activeEval.decision === 'ALLOW'
                            ? 'var(--accent-emerald-ink)'
                            : 'var(--accent-crimson-ink)',
                        fontSize: '13.5px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px'
                      }}
                    >
                      <div>
                        <strong>
                          {activeEval.decision === 'ALLOW'
                            ? 'CI Checks Passed & Keyless Cosign Attested (HTTP 200):'
                            : 'CI Admission Gate Blocked (HTTP 403):'}
                        </strong>{' '}
                        {activeEval.message}
                      </div>
                      {activeEval.findings.map((finding) => (
                        <div key={finding.id} style={{ fontSize: '13.5px' }}>
                          • <strong>[{finding.scanner} · {finding.rule_id}]</strong> {finding.title} ({finding.file}:{finding.line})
                        </div>
                      ))}
                      {activeEval.unmet_clauses.length > 0 && (
                        <div style={{ fontSize: '13.5px' }}>
                          • <strong>Unmet OPA Policy Clauses:</strong>{' '}
                          <code className="mono">{activeEval.unmet_clauses.join(', ')}</code>
                        </div>
                      )}
                      {activeEval.cosign_attestation && (
                        <div className="mono" style={{ fontSize: '12.5px' }}>
                          Rekor Log #{activeEval.cosign_attestation.rekor_log_index} ·{' '}
                          {activeEval.cosign_attestation.artifact_digest_sha256.slice(0, 32)}…
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </section>
          )}

          {/* ==================== SEAT 2: SORA TAKAHASHI — POLICY GATE & RELEASE APPROVAL ==================== */}
          {activeSeat === 'appsec-gate' && (
            <section
              aria-label="Policy Gate and Release Approval"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: 'var(--bg-canvas)',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#7c3aed',
                      color: '#ffffff',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    AS
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    Policy Gate &amp; Release Approval Console
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  Sora Takahashi · AppSec
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Table 1: OPA/Rego Policy Rules */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap'
                    }}
                  >
                    <div>
                      <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                        OPA/Rego Admission Policy Clauses
                      </h2>
                      <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                        All four supply-chain clauses must be enforced for fail-closed production release approval.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      style={{ fontSize: '13px', padding: '7px 13px' }}
                      disabled={allClausesHardened}
                      onClick={handleEnforceBaseline}
                    >
                      <ShieldCheck size={14} />
                      <span>{allClausesHardened ? 'All 4 Clauses Enforced' : 'Enforce Recommended Baseline'}</span>
                    </button>
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Policy Clause</th>
                          <th>Control Scope</th>
                          <th>Status</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {CLAUSE_ROWS.map((clause) => {
                          const enabled = state.policy_clauses[clause.key];
                          return (
                            <tr key={clause.key}>
                              <td>
                                <div className="mono" style={{ fontWeight: 700, fontSize: '13.5px' }}>
                                  {clause.name}
                                </div>
                                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                                  {clause.description}
                                </div>
                              </td>
                              <td style={{ whiteSpace: 'nowrap', fontWeight: 500 }}>{clause.control}</td>
                              <td>
                                {enabled ? (
                                  <span className="badge badge-emerald">ENFORCED</span>
                                ) : (
                                  <span className="badge badge-amber">DISABLED</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className={`btn btn-sm ${enabled ? '' : 'btn-primary'}`}
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  onClick={() => handleToggleClause(clause.key)}
                                >
                                  {enabled ? 'Disable' : 'Enforce'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Table 2: Release Approval Queue */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '12px',
                      flexWrap: 'wrap'
                    }}
                  >
                    <div>
                      <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                        Release Approval Queue
                      </h2>
                      <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                        Evaluate candidate Pull Requests against active OPA/Rego policy clauses and Sigstore Cosign attestation.
                      </p>
                    </div>
                    {state.deployed_attested && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        style={{ fontSize: '13px', padding: '7px 12px' }}
                        onClick={handleDownloadReport}
                      >
                        <Download size={14} />
                        <span>Export Attestation JSON</span>
                      </button>
                    )}
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Pull Request</th>
                          <th>Findings</th>
                          <th>Cosign OIDC</th>
                          <th>Gate Decision</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {PR_ORDER.map((presetId) => {
                          const pr = PR_PRESETS[presetId];
                          const evalRes = prEvaluations[presetId];
                          const isRunning = evaluatingPr === presetId;
                          return (
                            <tr key={presetId}>
                              <td>
                                <div style={{ fontWeight: 700, fontSize: '14px' }}>
                                  {pr.prNumber} · {pr.title}
                                </div>
                                <div className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                  {pr.branch}
                                </div>
                              </td>
                              <td>
                                {pr.findings.length === 0 ? (
                                  <span className="badge badge-emerald">0 Findings</span>
                                ) : (
                                  <span className="badge badge-crimson">
                                    {pr.findings.length} {pr.findings[0].scanner}
                                  </span>
                                )}
                              </td>
                              <td>
                                {pr.cosignSigned ? (
                                  <span className="badge badge-emerald">SIGNED OIDC</span>
                                ) : (
                                  <span className="badge">UNSIGNED</span>
                                )}
                              </td>
                              <td>
                                {evalRes ? (
                                  evalRes.decision === 'ALLOW' ? (
                                    <span className="badge badge-emerald">ALLOW (200)</span>
                                  ) : (
                                    <span className="badge badge-crimson">DENY (403)</span>
                                  )
                                ) : (
                                  <span className="badge">PENDING</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className="btn btn-sm"
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  disabled={evaluatingPr !== null}
                                  onClick={() => void handleRunGate(presetId)}
                                >
                                  {isRunning ? 'Evaluating…' : 'Evaluate Gate'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Live Rego Policy Preview */}
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                    Active Policy (`policy/admission.rego`)
                  </div>
                  <pre
                    className="mono"
                    style={{
                      margin: 0,
                      padding: '12px 14px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--bg-canvas)',
                      border: '1px solid var(--border-subtle)',
                      fontSize: '13px',
                      lineHeight: 1.55,
                      overflowX: 'auto',
                      color: 'var(--text-primary)'
                    }}
                  >
                    {regoCode}
                  </pre>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>

      {/* 3. Sticky-Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}
