# Agent & Contributor Instructions (`0trust-lab-devsecops-gatekeeper`)

## Two-Way Architecture Diagram Sync (Global <-> Local)

This repository powers **Lab 4 (`DevSecOps & Supply-Chain Gatekeeper` — `/devsecops-gatekeeper`)** on [`0trust.dev`](https://github.com/c2pig/0trust.dev/blob/main/docs/ECOSYSTEM_MAP.md), hosted at `https://lab.0trust.dev/devsecops-gatekeeper`.

Whenever you modify code, edge functions, or infrastructure under `src/`, `functions/`, `infra/`, or `.github/workflows/`:
1. **Local Sync**: Update [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/diagrams/devsecops_gatekeeper_architecture.svg`](docs/diagrams/devsecops_gatekeeper_architecture.svg) in the same Pull Request (enforced by [`.github/workflows/diagram-check.yml`](.github/workflows/diagram-check.yml)).
2. **Global Sync**: If public contracts (`lab.manifest.json`, `seats`, `apiEndpoints`, `kvPrefixes`), OPA/Rego gate invariants, or Cosign/Syft attestation schemas change, also update `docs/labs/devsecops-gatekeeper.md`, `docs/diagrams/platform_capability_zoomin.svg`, and `src/contracts/labManifest.ts` in [`c2pig/0trust.dev`](https://github.com/c2pig/0trust.dev).
