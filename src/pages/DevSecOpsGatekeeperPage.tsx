import React, { useCallback, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Copy,
  Download,
  FileCode2,
  GitPullRequest,
  Lock,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Unlock
} from 'lucide-react';
import {
  CognitivePhase,
  DevSecOpsLabState,
  DevSecOpsSeatId,
  HARDENED_POLICY_CLAUSES,
  PR_PRESETS,
  PoePrediction,
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
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import { XRayDecodedProofSection, XRayTelemetryDrawer } from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface DevSecOpsGatekeeperPageProps {
  onBack: () => void;
}

const POISONED_PRESET_IDS: PrPresetId[] = [
  'TYPOSQUAT_DEP',
  'LEAKED_SECRET',
  'UNPINNED_ACTION',
  'PUBLIC_IAC_ACL'
];

const PIPELINE_STAGES = [
  {
    id: 'pr-diff',
    step: '01',
    name: 'GitHub PR & Diff',
    tool: 'Pull Request Trigger',
    detail: 'Author pushes feature branch with code, workflow YAML, or Terraform changes.'
  },
  {
    id: 'sast-secret-iac',
    step: '02',
    name: 'Secret & IaC Scan',
    tool: 'Gitleaks + Checkov',
    detail: 'Detects hardcoded credentials/tokens and insecure Terraform/R2 ACLs.'
  },
  {
    id: 'sbom-typosquat',
    step: '03',
    name: 'SBOM & Typosquat',
    tool: 'Syft CycloneDX 1.5',
    detail: 'Generates dependency graph and flags typosquatted or unverified packages.'
  },
  {
    id: 'cosign-oidc',
    step: '04',
    name: 'Keyless Attestation',
    tool: 'Sigstore Cosign OIDC',
    detail: 'Mints ephemeral OIDC cert and logs artifact + SBOM digest to Rekor.'
  },
  {
    id: 'opa-gate',
    step: '05',
    name: 'Admission Gate',
    tool: 'OPA / Rego Policy',
    detail: 'Fail-closed evaluation: ALLOW only if 4/4 clauses pass & 0 findings.'
  }
];

const CLAUSE_META: Array<{
  key: keyof PolicyClauses;
  label: string;
  description: string;
}> = [
  {
    key: 'require_pinned_sha',
    label: 'require_pinned_sha',
    description: 'Reject mutable GitHub Action refs (@main/@v4); require 40-char commit SHA.'
  },
  {
    key: 'block_secrets',
    label: 'block_secrets',
    description: 'Fail closed on any Gitleaks entropy or regex secret match.'
  },
  {
    key: 'require_cosign_oidc',
    label: 'require_cosign_oidc',
    description: 'Require verified Sigstore Cosign OIDC keyless bundle in Rekor.'
  },
  {
    key: 'block_public_acl',
    label: 'block_public_acl',
    description: 'Block Checkov CKV_AWS_20 public-read ACLs or wildcard IAM policies.'
  }
];

export function DevSecOpsGatekeeperPage({ onBack }: DevSecOpsGatekeeperPageProps) {
  const [sessionId, setSessionId] = useState<string>(() => createSessionId());
  const [activeSeat, setActiveSeat] = useState<DevSecOpsSeatId>('developer');
  const [state, setState] = useState<DevSecOpsLabState>(() =>
    createInitialLabState(sessionId)
  );
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [spans, setSpans] = useState<ObservabilitySpan[]>(() => [
    createSpan({
      sessionId,
      traceparent: createInitialLabState(sessionId).traceparent,
      method: 'POST',
      path: '/api/devsecops-gatekeeper/init',
      status: 200,
      latencyMs: 2,
      origin: 'browser-webcrypto-fallback',
      summary: {
        stage: 'Discovery',
        policy_posture: 'PERMISSIVE_BASELINE',
        pr_preset: 'TYPOSQUAT_DEP'
      }
    })
  ]);

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
  }, []);

  const enabledClauseCount = useMemo(
    () => Object.values(state.policy_clauses).filter(Boolean).length,
    [state.policy_clauses]
  );
  const allClausesHardened = enabledClauseCount === 4;

  const seats: RoleSeatItem<DevSecOpsSeatId>[] = useMemo(() => {
    const evalRes = state.last_evaluation;
    const devBadge = state.deployed_attested
      ? { text: 'DEPLOYED · Attested', tone: 'emerald' as const }
      : evalRes?.decision === 'DENY'
        ? { text: `BLOCKED · ${evalRes.pr_number}`, tone: 'crimson' as const, pulse: true }
        : { text: `${PR_PRESETS[state.selected_preset].prNumber} · Ready`, tone: 'blue' as const };

    const appSecBadge = state.deployed_attested && allClausesHardened
      ? { text: 'Gate · Enforced 4/4', tone: 'emerald' as const }
      : !state.smoking_gun_inspected
        ? { text: 'POE · Patcher Locked', tone: 'amber' as const }
        : allClausesHardened
          ? { text: 'Rego · 4/4 Hardened', tone: 'blue' as const }
          : { text: `Rego · ${enabledClauseCount}/4 Clauses`, tone: 'amber' as const, pulse: true };

    return [
      {
        id: 'developer',
        name: 'Jordan Lee',
        roleLabel: 'Platform Dev · GitHub PR Author',
        appLabel: 'Pull Request & CI Runner',
        badge: devBadge
      },
      {
        id: 'appsec-gate',
        name: 'Sora Takahashi',
        roleLabel: 'AppSec · Policy-as-Code Gatekeeper',
        appLabel: 'Syft/Cosign & OPA/Rego Workbench',
        badge: appSecBadge
      }
    ];
  }, [state.deployed_attested, state.last_evaluation, state.selected_preset, state.smoking_gun_inspected, allClausesHardened, enabledClauseCount]);

  const handleReset = () => {
    const freshSid = createSessionId();
    const freshState = createInitialLabState(freshSid);
    setSessionId(freshSid);
    setActiveSeat('developer');
    setState(freshState);
    setCopiedReport(false);
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
          stage: 'Discovery',
          policy_posture: 'PERMISSIVE_BASELINE',
          session_id: freshSid
        }
      })
    ]);
  };

  const handleSelectPhase = (phase: CognitivePhase) => {
    setState((prev) => ({ ...prev, active_phase: phase }));
  };

  const handleSelectPreset = (presetId: PrPresetId) => {
    setState((prev) => ({
      ...prev,
      selected_preset: presetId,
      prediction: null,
      last_evaluation: null,
      deployed_attested: false
    }));
  };

  const handleSelectPrediction = (prediction: PoePrediction) => {
    setState((prev) => ({ ...prev, prediction }));
  };

  const handleRunGate = async (overridePreset?: PrPresetId, overrideClauses?: PolicyClauses) => {
    const presetToRun = overridePreset ?? state.selected_preset;
    const clausesToUse = overrideClauses ?? state.policy_clauses;
    setIsEvaluating(true);
    const { result, span } = await evaluatePrWithEdgeFallback({
      presetId: presetToRun,
      clauses: clausesToUse,
      sessionId
    });
    recordSpan(span);
    setState((prev) => ({
      ...prev,
      selected_preset: presetToRun,
      policy_clauses: clausesToUse,
      last_evaluation: result,
      deployed_attested: result.decision === 'ALLOW',
      evaluated_presets: {
        ...prev.evaluated_presets,
        [presetToRun]: true
      }
    }));
    setIsEvaluating(false);
  };

  const handleInspectSmokingGun = (findingCode: string) => {
    setState((prev) => ({
      ...prev,
      smoking_gun_inspected: true
    }));
    recordSpan(
      createSpan({
        sessionId,
        traceparent: state.traceparent,
        method: 'POST',
        path: '/api/devsecops-gatekeeper/poe-inspect',
        status: 200,
        latencyMs: 3,
        origin: 'browser-webcrypto-fallback',
        summary: {
          event: 'SMOKING_GUN_INSPECTED',
          smoking_gun: findingCode,
          opa_patcher_unlocked: true
        }
      })
    );
  };

  const handleToggleClause = (key: keyof PolicyClauses) => {
    if (!state.smoking_gun_inspected) return;
    setState((prev) => ({
      ...prev,
      policy_clauses: {
        ...prev.policy_clauses,
        [key]: !prev.policy_clauses[key]
      },
      deployed_attested: false
    }));
  };

  const handleApplyAllHardenedClauses = () => {
    if (!state.smoking_gun_inspected) return;
    setState((prev) => ({
      ...prev,
      policy_clauses: { ...HARDENED_POLICY_CLAUSES },
      deployed_attested: false
    }));
  };

  const handleGuidedWalkthrough = async () => {
    setActiveSeat('appsec-gate');
    const hardened = { ...HARDENED_POLICY_CLAUSES };
    setState((prev) => ({
      ...prev,
      active_phase: 3,
      selected_preset: 'CLEAN_PR',
      prediction: 'ALLOW',
      smoking_gun_inspected: true,
      policy_clauses: hardened,
      evaluated_presets: {
        ...prev.evaluated_presets,
        TYPOSQUAT_DEP: true
      }
    }));
    await handleRunGate('CLEAN_PR', hardened);
    setState((prev) => ({ ...prev, active_phase: 4 }));
  };

  const handleCopyReport = async () => {
    try {
      await navigator.clipboard.writeText(exportAttestationReport(state));
      setCopiedReport(true);
      window.setTimeout(() => setCopiedReport(false), 2000);
    } catch {
      setCopiedReport(false);
    }
  };

  const handleDownloadReport = () => {
    const blob = new Blob([exportAttestationReport(state)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lab4-devsecops-attestation-${state.correlation_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const activePreset = PR_PRESETS[state.selected_preset];
  const regoCode = useMemo(() => renderOpaRegoPolicy(state.policy_clauses), [state.policy_clauses]);

  const decodedProofSections: XRayDecodedProofSection[] = useMemo(() => {
    const evalData = state.last_evaluation;
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
        label: 'Gitleaks / Checkov / Actions Finding JSON',
        payload: evalData?.findings ?? activePreset.findings
      },
      {
        id: 'cosign-attestation',
        label: 'Sigstore Cosign OIDC Keyless Attestation Payload',
        payload: evalData?.cosign_attestation ?? {
          status: 'NOT_ATTESTED_YET',
          reason: 'Run Deploy PR with 4/4 OPA/Rego clauses enabled and CLEAN_PR to mint keyless OIDC bundle.'
        }
      },
      {
        id: 'opa-rego-trace',
        label: 'OPA/Rego Input & Allow/Deny Evaluation Trace',
        payload: evalData?.opa_trace ?? {
          package: '0trust.admission',
          policy_clauses: state.policy_clauses,
          allow: false,
          note: 'Awaiting PR Security Gate evaluation.'
        }
      }
    ];
  }, [state.last_evaluation, state.policy_clauses, activePreset]);

  const testedChecklist = [
    { key: 'TYPOSQUAT_DEP', label: 'Trap 4A: Typosquatted Dependency (reqeusts-oauth in Syft SBOM)', done: state.evaluated_presets.TYPOSQUAT_DEP },
    { key: 'LEAKED_SECRET', label: 'Trap 4B: Leaked AWS Access Key (Gitleaks aws-access-token)', done: state.evaluated_presets.LEAKED_SECRET },
    { key: 'UNPINNED_ACTION', label: 'Trap 4C: Unpinned GitHub Action (uses: actions/checkout@main)', done: state.evaluated_presets.UNPINNED_ACTION },
    { key: 'PUBLIC_IAC_ACL', label: 'Trap 4D: Public IaC Storage ACL (Checkov CKV_AWS_20)', done: state.evaluated_presets.PUBLIC_IAC_ACL },
    { key: 'CLEAN_PR', label: 'Patch & Deploy: 4/4 OPA/Rego Clauses + Clean PR -> Cosign OIDC ALLOW', done: state.deployed_attested }
  ];
  const completedCount = testedChecklist.filter((item) => item.done).length;

  return (
    <div className="lab-shell">
      <header className="lab-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <button type="button" className="btn btn-sm" onClick={onBack}>
            <ArrowLeft size={14} />
            <span>All Labs</span>
          </button>
          <div>
            <h1 style={{ fontSize: '15.5px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              DevSecOps &amp; Supply-Chain Gatekeeper
            </h1>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Archetype C + POE · Syft SBOM, Gitleaks, Checkov, OPA/Rego &amp; Keyless Cosign OIDC
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span className="badge badge-blue">
            $0.00 Guided Sandbox · Edge + Fallback
          </span>
          <button
            type="button"
            className="btn btn-emerald btn-sm"
            onClick={() => void handleGuidedWalkthrough()}
            disabled={isEvaluating}
          >
            <Play size={13} />
            <span>Guided Walkthrough (Attested PR)</span>
          </button>
          <button type="button" className="btn btn-sm" onClick={handleReset}>
            <RotateCcw size={13} />
            <span>↺ Reset</span>
          </button>
        </div>
      </header>

      <main className="lab-workspace" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <RoleSwitcherBar
          seats={seats}
          activeSeatId={activeSeat}
          onSelectSeat={setActiveSeat}
          ariaLabel="DevSecOps Gatekeeper 2-Seat Role Switcher"
        />

        {/* 4-Phase Cognitive Arc Stepper */}
        <nav aria-label="4-Phase Cognitive Arc" className="stepper-bar">
          {[
            { id: 1 as CognitivePhase, label: 'Discovery · Pipeline Map' },
            { id: 2 as CognitivePhase, label: 'Understanding · POE Gate' },
            { id: 3 as CognitivePhase, label: 'Practice · Patch OPA & Deploy' },
            { id: 4 as CognitivePhase, label: 'Reflection · Attestation' }
          ].map((step) => {
            const isActive = state.active_phase === step.id;
            const isCompleted = state.active_phase > step.id;
            return (
              <button
                key={step.id}
                type="button"
                className={`stage-pill${isActive ? ' active' : ''}${isCompleted ? ' completed' : ''}`}
                onClick={() => handleSelectPhase(step.id)}
              >
                <span className="stage-number">{step.id}</span>
                <span>{step.label}</span>
              </button>
            );
          })}
        </nav>

        {/* PHASE 1: DISCOVERY */}
        {state.active_phase === 1 && (
          <section className="pane" aria-label="Phase 1 Discovery">
            <div className="pane-header">
              <div>
                <strong>Phase 1 · Discovery: PR-to-Production Supply-Chain Pipeline</strong>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Active Seat: <strong>{activeSeat === 'developer' ? 'Jordan Lee (Platform Dev)' : 'Sora Takahashi (AppSec Gatekeeper)'}</strong>
                </div>
              </div>
              <button type="button" className="btn btn-primary btn-sm" onClick={() => handleSelectPhase(2)}>
                <span>Start POE Challenge</span>
                <ArrowRight size={13} />
              </button>
            </div>
            <div className="pane-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
                  gap: '12px'
                }}
              >
                {PIPELINE_STAGES.map((stage) => (
                  <div
                    key={stage.id}
                    className="surface-card"
                    style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '6px' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className="badge badge-blue">Stage {stage.step}</span>
                      <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {stage.tool}
                      </span>
                    </div>
                    <div style={{ fontWeight: 700, fontSize: '13.5px', color: 'var(--text-primary)' }}>
                      {stage.name}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                      {stage.detail}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mission-banner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '13px' }}>
                    Current OPA/Rego Baseline: Permissive ({enabledClauseCount}/4 clauses enabled)
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Inspect poisoned PRs in Phase 2 (POE) to unlock the OPA/Rego Policy Patcher.
                  </div>
                </div>
                <button type="button" className="btn btn-dark btn-sm" onClick={() => handleSelectPhase(2)}>
                  <span>Proceed to Phase 2: POE Gate</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          </section>
        )}

        {/* PHASE 2: UNDERSTANDING / POE */}
        {state.active_phase === 2 && (
          <section className="pane" aria-label="Phase 2 Predict Observe Explain">
            <div className="pane-header">
              <div>
                <strong>Phase 2 · Understanding (POE): Diagnose Poisoned Pull Requests</strong>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  1. Predict outcome → 2. Observe scanner output → 3. Click the smoking-gun diff line to unlock Phase 3 Patcher
                </div>
              </div>
              <span className={`badge ${state.smoking_gun_inspected ? 'badge-emerald' : 'badge-amber'}`}>
                {state.smoking_gun_inspected ? 'Smoking Gun Inspected · Patcher Unlocked' : 'POE Gate Active · Inspect Smoking Gun'}
              </span>
            </div>

            <div className="pane-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Preset Selector */}
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {POISONED_PRESET_IDS.map((pid) => {
                  const p = PR_PRESETS[pid];
                  const isSel = state.selected_preset === pid;
                  const tested = state.evaluated_presets[pid];
                  return (
                    <button
                      key={pid}
                      type="button"
                      className={`btn btn-sm ${isSel ? 'btn-primary' : ''}`}
                      onClick={() => handleSelectPreset(pid)}
                    >
                      <GitPullRequest size={13} />
                      <span>{p.trapLabel}</span>
                      {tested && <CheckCircle2 size={12} />}
                    </button>
                  );
                })}
              </div>

              {/* PR Diff & Prediction Row */}
              <div className="workbench-grid">
                <div className="surface-card" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px', minWidth: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <span className="badge badge-blue">{activePreset.prNumber} · {activePreset.branch}</span>
                    <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {activePreset.commitSha.slice(0, 10)}
                    </span>
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '13.5px' }}>{activePreset.title}</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{activePreset.summary}</div>

                  {/* Diff Viewer with clickable smoking gun */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                    <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)' }}>
                      PR Diff Preview {state.last_evaluation ? '(Click highlighted smoking-gun line to Explain & Unlock Patcher)' : ''}
                    </div>
                    {activePreset.diffPreview.map((line) => {
                      const canClick = Boolean(line.isSmokingGun && state.last_evaluation);
                      return (
                        <button
                          key={`${line.file}-${line.lineNo}`}
                          type="button"
                          disabled={!canClick}
                          onClick={() => line.isSmokingGun && handleInspectSmokingGun(line.content)}
                          className="mono"
                          style={{
                            textAlign: 'left',
                            padding: '7px 10px',
                            borderRadius: '6px',
                            fontSize: '11.5px',
                            border: line.isSmokingGun ? '1px solid #fca5a5' : '1px solid var(--border-subtle)',
                            backgroundColor: line.isSmokingGun ? '#fef2f2' : '#f8fafc',
                            color: line.isSmokingGun ? '#991b1b' : '#334155',
                            cursor: canClick ? 'pointer' : 'default',
                            overflowX: 'auto',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all'
                          }}
                        >
                          {line.file}:{line.lineNo} | {line.content}
                          {canClick && (
                            <span style={{ marginLeft: '8px', fontWeight: 700, textDecoration: 'underline' }}>
                              ← Click Smoking Gun
                            </span>
                          )}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Predict & Observe Panel */}
                <div className="surface-card" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '12px', minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: '13.5px' }}>Step 1: Predict PR Gate Decision</div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className={`btn btn-sm ${state.prediction === 'ALLOW' ? 'btn-emerald' : ''}`}
                      onClick={() => handleSelectPrediction('ALLOW')}
                    >
                      Predict: ALLOW (Pass Gate)
                    </button>
                    <button
                      type="button"
                      className={`btn btn-sm ${state.prediction === 'DENY' ? 'btn-danger-soft' : ''}`}
                      onClick={() => handleSelectPrediction('DENY')}
                    >
                      Predict: DENY (Block Gate)
                    </button>
                  </div>

                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={!state.prediction || isEvaluating}
                    onClick={() => void handleRunGate()}
                  >
                    <Terminal size={13} />
                    <span>{isEvaluating ? 'Running Scanners…' : 'Step 2: Run PR Security Gate'}</span>
                  </button>

                  {state.last_evaluation && (
                    <div
                      style={{
                        padding: '10px 12px',
                        borderRadius: '8px',
                        border: '1px solid #fecaca',
                        backgroundColor: '#fef2f2',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                        <span className="badge badge-crimson">
                          HTTP {state.last_evaluation.http_status} · {state.last_evaluation.decision}
                        </span>
                        <span style={{ fontSize: '11.5px', fontWeight: 600, color: '#991b1b' }}>
                          Prediction: {state.prediction} vs Observed: {state.last_evaluation.decision}
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#7f1d1d' }}>{state.last_evaluation.message}</div>
                      {state.last_evaluation.findings.map((f) => (
                        <div key={f.id} style={{ fontSize: '11.5px', color: '#991b1b' }}>
                          <strong>[{f.scanner} · {f.rule_id}]</strong> {f.title}
                        </div>
                      ))}
                    </div>
                  )}

                  {state.smoking_gun_inspected && (
                    <button
                      type="button"
                      className="btn btn-emerald btn-sm"
                      onClick={() => {
                        setActiveSeat('appsec-gate');
                        handleSelectPhase(3);
                      }}
                    >
                      <Unlock size={13} />
                      <span>Proceed to Phase 3: OPA/Rego Patcher</span>
                      <ArrowRight size={13} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* PHASE 3: PRACTICE (OPA/REGO PATCHER + DEPLOY PR) */}
        {state.active_phase === 3 && (
          <section className="pane" aria-label="Phase 3 Practice OPA Patcher">
            <div className="pane-header">
              <div>
                <strong>Phase 3 · Practice: Patch OPA/Rego Policy &amp; Remediate PR</strong>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Enforce all 4 OPA/Rego clauses and deploy a clean, Cosign-attested PR
                </div>
              </div>
              <span className={`badge ${allClausesHardened ? 'badge-emerald' : 'badge-amber'}`}>
                {enabledClauseCount}/4 Policy Clauses Enabled
              </span>
            </div>

            <div className="pane-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {!state.smoking_gun_inspected ? (
                <div className="mission-banner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Lock size={18} color="#b45309" />
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '13px' }}>OPA/Rego Policy Patcher Locked</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        Complete Phase 2 (POE): run a poisoned PR scan and click the smoking-gun diff line to unlock.
                      </div>
                    </div>
                  </div>
                  <button type="button" className="btn btn-primary btn-sm" onClick={() => handleSelectPhase(2)}>
                    <span>Go to Phase 2 (POE)</span>
                  </button>
                </div>
              ) : (
                <div className="workbench-grid">
                  {/* Left: OPA/Rego Clause Toggles + Code Preview */}
                  <div className="surface-card" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '12px', minWidth: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                      <strong style={{ fontSize: '13.5px' }}>OPA/Rego Admission Clauses</strong>
                      <button type="button" className="btn btn-sm" onClick={handleApplyAllHardenedClauses}>
                        <ShieldCheck size={13} />
                        <span>Enable All 4 Clauses</span>
                      </button>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {CLAUSE_META.map((clause) => {
                        const enabled = state.policy_clauses[clause.key];
                        return (
                          <label
                            key={clause.key}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '10px',
                              padding: '8px 10px',
                              borderRadius: '8px',
                              border: `1px solid ${enabled ? '#a7f3d0' : '#fde68a'}`,
                              backgroundColor: enabled ? '#ecfdf5' : '#fffbeb',
                              cursor: 'pointer'
                            }}
                          >
                            <input
                              type="checkbox"
                              checked={enabled}
                              onChange={() => handleToggleClause(clause.key)}
                              style={{ marginTop: '3px' }}
                            />
                            <div>
                              <div className="mono" style={{ fontSize: '12px', fontWeight: 700 }}>
                                {clause.label} = {String(enabled)}
                              </div>
                              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                                {clause.description}
                              </div>
                            </div>
                          </label>
                        );
                      })}
                    </div>

                    <div>
                      <div style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                        Live `policy/admission.rego`
                      </div>
                      <pre className="code-block" style={{ margin: 0, fontSize: '11px', overflowX: 'auto' }}>
                        {regoCode}
                      </pre>
                    </div>
                  </div>

                  {/* Right: PR Remediation & Deploy Runner */}
                  <div className="surface-card" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '12px', minWidth: 0 }}>
                    <strong style={{ fontSize: '13.5px' }}>PR Remediation &amp; Deploy Runner</strong>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Select PR target to test fail-closed enforcement or remediate to <code>CLEAN_PR</code>:
                    </div>

                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        className={`btn btn-sm ${state.selected_preset === 'CLEAN_PR' ? 'btn-emerald' : ''}`}
                        onClick={() => {
                          setActiveSeat('developer');
                          handleSelectPreset('CLEAN_PR');
                        }}
                      >
                        <CheckCircle2 size={13} />
                        <span>Remediate to CLEAN_PR (PR #422)</span>
                      </button>
                      <button
                        type="button"
                        className={`btn btn-sm ${state.selected_preset === 'UNPINNED_ACTION' ? 'btn-danger-soft' : ''}`}
                        onClick={() => handleSelectPreset('UNPINNED_ACTION')}
                      >
                        <AlertTriangle size={13} />
                        <span>Test Unpinned Action (PR #420)</span>
                      </button>
                    </div>

                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={isEvaluating}
                      onClick={() => void handleRunGate()}
                    >
                      <FileCode2 size={14} />
                      <span>{isEvaluating ? 'Evaluating Gate…' : 'Deploy PR (Evaluate Gate & Attest)'}</span>
                    </button>

                    {state.last_evaluation && (
                      <div
                        style={{
                          padding: '12px',
                          borderRadius: '8px',
                          border: `1px solid ${state.last_evaluation.decision === 'ALLOW' ? '#a7f3d0' : '#fecaca'}`,
                          backgroundColor: state.last_evaluation.decision === 'ALLOW' ? '#ecfdf5' : '#fef2f2',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '8px'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '6px' }}>
                          <span className={`badge ${state.last_evaluation.decision === 'ALLOW' ? 'badge-emerald' : 'badge-crimson'}`}>
                            HTTP {state.last_evaluation.http_status} · {state.last_evaluation.decision}
                          </span>
                          <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                            storage: {state.last_evaluation.storage}
                          </span>
                        </div>
                        <div style={{ fontSize: '12px', fontWeight: 600 }}>{state.last_evaluation.message}</div>
                        {state.last_evaluation.cosign_attestation && (
                          <div className="mono" style={{ fontSize: '11px', color: '#065f46' }}>
                            Cosign OIDC: {state.last_evaluation.cosign_attestation.verification_status} · Rekor #{state.last_evaluation.cosign_attestation.rekor_log_index}
                          </div>
                        )}
                      </div>
                    )}

                    {state.deployed_attested && (
                      <button
                        type="button"
                        className="btn btn-emerald btn-sm"
                        onClick={() => handleSelectPhase(4)}
                      >
                        <span>View Phase 4: Scorecard &amp; Attestation</span>
                        <ArrowRight size={13} />
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* PHASE 4: REFLECTION */}
        {state.active_phase === 4 && (
          <section className="pane" aria-label="Phase 4 Reflection Scorecard">
            <div className="pane-header">
              <div>
                <strong>Phase 4 · Reflection: Security vs. Velocity Scorecard &amp; Attestation</strong>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Keyless Sigstore Cosign OIDC bundle, Syft CycloneDX SBOM, and traps explored
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button type="button" className="btn btn-sm" onClick={() => void handleCopyReport()}>
                  <Copy size={13} />
                  <span>{copiedReport ? 'Copied JSON' : 'Copy Attestation'}</span>
                </button>
                <button type="button" className="btn btn-sm" onClick={handleDownloadReport}>
                  <Download size={13} />
                  <span>Export JSON</span>
                </button>
              </div>
            </div>

            <div className="pane-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: '12px'
                }}
              >
                <div className="surface-card" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>OPA/Rego Policy Coverage</div>
                  <div style={{ fontSize: '22px', fontWeight: 800, color: allClausesHardened ? '#059669' : '#d97706' }}>
                    {enabledClauseCount} / 4 Clauses
                  </div>
                </div>
                <div className="surface-card" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Cosign OIDC Attestation</div>
                  <div style={{ fontSize: '18px', fontWeight: 800, color: state.deployed_attested ? '#059669' : '#dc2626' }}>
                    {state.deployed_attested ? 'VERIFIED KEYLESS' : 'NOT ATTESTED'}
                  </div>
                </div>
                <div className="surface-card" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>Traps &amp; Patch Explored</div>
                  <div style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-primary)' }}>
                    {completedCount} / {testedChecklist.length}
                  </div>
                </div>
              </div>

              <div className="surface-card" style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ fontWeight: 700, fontSize: '13px' }}>Supply-Chain Traps &amp; Remediation Checklist</div>
                {testedChecklist.map((item) => (
                  <div
                    key={item.key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      fontSize: '12.5px',
                      color: item.done ? '#065f46' : 'var(--text-muted)'
                    }}
                  >
                    {item.done ? <ShieldCheck size={15} color="#059669" /> : <ShieldAlert size={15} color="#94a3b8" />}
                    <span>{item.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}
      </main>

      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}

export default DevSecOpsGatekeeperPage;
