// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import OptionsPanel from '../OptionsPanel'
import ResultsView  from '../ResultsView'
import styles from './Screen.module.css'

interface Props { active: boolean }

const FORMATS = ['txt', 'csv', 'json', 'md'] as const
type Fmt = typeof FORMATS[number]

export default function LicenseScreen({ active }: Props) {
  const { bomFile } = useAppContext()

  const [output,     setOutput]     = useState('')
  const [loading,    setLoading]    = useState(false)
  const [dirty,      setDirty]      = useState(true)
  const [noticeMsg,  setNoticeMsg]  = useState('')

  const [format,  setFormat]  = useState<Fmt>('md')
  const [where,   setWhere]   = useState('')
  const [summary, setSummary] = useState(false)

  const markDirty = () => { setDirty(true); setNoticeMsg('') }

  const run = async () => {
    if (!bomFile) return
    if (!dirty) { setNoticeMsg('No option changes — results are current'); return }
    setLoading(true); setOutput(''); setDirty(false); setNoticeMsg('')
    try {
      const res = await window.sbomBridge.listLicenses({ filePath: bomFile, format, where, summary })
      const combined = res.stdout + (res.stderr ? '\n' + res.stderr : '')
      setOutput(combined || '(no licenses found)')
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
          <OptionsPanel
            title="License List Options"
            notice={noticeMsg}
            action={
              <button className="btn btn-primary w-full" onClick={run} disabled={loading || !bomFile}>
                ℹ️ &nbsp;{loading ? 'Scanning…' : 'List Licenses'}
              </button>
            }
          >
            <label className="checkbox-row">
              <input type="checkbox" checked={summary} onChange={e => { setSummary(e.target.checked); markDirty() }} />
              Summary mode (--summary)
            </label>
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
                placeholder="e.g. usage-policy=allow,license=MIT"
              />
              <span className="hint-text">
                {'Filter keys: usage-policy, license-type, license, resource-name,\nbom-ref, bom-location, purl'}
              </span>
            </div>
          </OptionsPanel>
        </div>
        <div className={styles.results}>
          <ResultsView text={output} loading={loading} markdown={format === 'md'} />
        </div>
      </div>
    </div>
  )
}
