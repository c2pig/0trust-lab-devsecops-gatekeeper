import React from 'react';
import { LabLeaseGuard } from './shell';
import { DevSecOpsGatekeeperPage } from './pages/DevSecOpsGatekeeperPage';

export default function App(): React.ReactElement {
  return (
    <LabLeaseGuard labSlug="devsecops-gatekeeper" labTitle="DevSecOps & Supply-Chain Gatekeeper">
      <DevSecOpsGatekeeperPage
        onBack={() => {
          window.location.href =
            window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
              ? 'http://localhost:5173/'
              : 'https://0trust.dev/';
        }}
      />
    </LabLeaseGuard>
  );
}
