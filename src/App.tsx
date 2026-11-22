import React from 'react';
import { DevSecOpsGatekeeperPage } from './pages/DevSecOpsGatekeeperPage';

export default function App(): React.ReactElement {
  return (
    <DevSecOpsGatekeeperPage
      onBack={() => {
        window.location.href =
          window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://localhost:5173/'
            : 'https://0trust.dev/';
      }}
    />
  );
}
