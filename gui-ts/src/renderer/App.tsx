// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import { AppProvider } from './context/AppContext'
import Shell from './components/Shell'

export default function App() {
  const [version, setVersion] = useState('…')

  useEffect(() => {
    window.sbomBridge.getVersion().then(setVersion).catch(() => setVersion('?'))
  }, [])

  return (
    <AppProvider version={version}>
      <Shell />
    </AppProvider>
  )
}
