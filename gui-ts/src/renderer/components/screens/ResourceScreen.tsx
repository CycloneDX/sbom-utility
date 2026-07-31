// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import OptionsPanel from '../OptionsPanel'
import ResultsView  from '../ResultsView'
import styles from './Screen.module.css'

interface Props { active: boolean }

const FORMATS = ['txt', 'csv', 'md'] as const
type Fmt = typeof FORMATS[number]

const RESOURCE_TYPES = ['(all)', 'component', 'service'] as const
type RType = typeof RESOURCE_TYPES[number]

export default function ResourceScreen({ active }: Props) {
  const { bomFile } = useAppContext()

  const [output,  setOutput]  = useState('')
  const [loading, setLoading] = useState(false)
  const [dirty,   setDirty]   = useState(true)

  const [format,  setFormat]  = useState<Fmt>('txt')
  const [where,   setWhere]   = useState('')
  const [rtype,   setRtype]   = useState<RType>('(all)')

  const markDirty = () => setDirty(true)

  const run = async () => {
    if (!bomFile) return
    setLoading(true); setOutput(''); setDirty(false)
    try {
      const res = await window.sbomBridge.listResources({
        filePath:     bomFile,
        format,
        where,
        resourceType: rtype === '(all)' ? '' : rtype,
      })
      const combined = res.stdout + (res.stderr ? '\n' + res.stderr : '')
      setOutput(combined || '(no resources found)')
    } catch (e: unknown) {
      setOutput(`[ERROR] ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { if (active && bomFile) { run() } }, [active, bomFile])

  return (
    <div className={styles.screen}>
      <div className={styles.split}>
        <div className={styles.options}>
          <OptionsPanel title="Resource List Options">
            <div className="flag-row">
              <label className="flag-label">Resource type (--type):</label>
              <select className="select" value={rtype} onChange={e => { setRtype(e.target.value as RType); markDirty() }}>
                {RESOURCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div className="flag-row">
              <label className="flag-label">Output format (--format):</label>
              <select className="select" value={format} onChange={e => { setFormat(e.target.value as Fmt); markDirty() }}>
                {FORMATS.map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div className="flag-row">
              <label className="flag-label">Filter (--where key=regex,…):</label>
              <input
                className="input"
                value={where}
                onChange={e => { setWhere(e.target.value); markDirty() }}
                placeholder="e.g. name=log.*"
              />
              <span className="hint-text">
                {'Filter keys:\nresource-type, name, version, bom-ref, group, description'}
              </span>
            </div>
            <div className="separator" />
            <button className="btn btn-primary w-full" onClick={run} disabled={loading || !bomFile || !dirty}>
              🗄️ &nbsp;{loading ? 'Scanning…' : 'List Resources'}
            </button>
          </OptionsPanel>
        </div>
        <div className={styles.results}>
          <ResultsView text={output} loading={loading} markdown={format === 'md'} />
        </div>
      </div>
    </div>
  )
}
