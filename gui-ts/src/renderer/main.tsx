// SPDX-License-Identifier: Apache-2.0
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/tokens.css'
import './styles/app.css'

// When running in a plain browser (npm run dev:browser) the Electron
// contextBridge is absent.  Inject the mock so the UI is fully navigable.
if (!window.sbomBridge) {
  const { mockBridge } = await import('./mockBridge')
  window.sbomBridge = mockBridge
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
