// SPDX-License-Identifier: Apache-2.0
import React from 'react'
import { useAppContext, DEFAULT_EDITOR_FONT } from '../../context/AppContext'
import styles from './Screen.module.css'

// ── Font choices (mirrors FontDialog) ─────────────────────────────────────────

const FONT_CHOICES: { label: string; value: string }[] = [
  { label: 'System Monospace',  value: 'ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace' },
  { label: 'Cascadia Code',     value: '"Cascadia Code", ui-monospace, Consolas, monospace' },
  { label: 'Fira Code',         value: '"Fira Code", ui-monospace, Consolas, monospace' },
  { label: 'Consolas',          value: 'Consolas, ui-monospace, "Courier New", monospace' },
  { label: 'Courier New',       value: '"Courier New", Courier, monospace' },
  { label: 'JetBrains Mono',    value: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
  { label: 'Source Code Pro',   value: '"Source Code Pro", ui-monospace, Consolas, monospace' },
  { label: 'Menlo',             value: 'Menlo, ui-monospace, Consolas, monospace' },
]

const SIZE_PRESETS = [10, 11, 12, 13, 14, 16, 18, 20, 24]

// ── Shared styles ──────────────────────────────────────────────────────────────

const sectionHeadStyle: React.CSSProperties = {
  marginBottom: 'var(--space-3)',
  color: 'var(--color-text-muted)',
  fontSize: 'var(--text-xs)',
  fontWeight: 'var(--weight-bold)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
}

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: 'var(--text-sm)',
  fontWeight: 'var(--weight-medium)',
  marginBottom: 'var(--space-2)',
}

// ── Reusable font picker ───────────────────────────────────────────────────────

interface FontPickerProps {
  family:    string
  size:      number
  onChange:  (family: string, size: number) => void
  preview:   string   // sample text shown in the preview strip
}

function FontPicker({ family, size, onChange, preview }: FontPickerProps) {
  return (
    <>
      {/* Family */}
      <label style={labelStyle}>Font Family</label>
      <select
        className="select"
        style={{ maxWidth: 360, marginBottom: 'var(--space-4)' }}
        value={family}
        onChange={e => onChange(e.target.value, size)}
      >
        {FONT_CHOICES.map(f => (
          <option key={f.label} value={f.value}>{f.label}</option>
        ))}
      </select>

      {/* Size */}
      <label style={labelStyle}>Font Size (px)</label>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)', marginBottom: 'var(--space-3)' }}>
        {SIZE_PRESETS.map(s => (
          <button
            key={s}
            onClick={() => onChange(family, s)}
            style={{
              height: 28,
              minWidth: 36,
              padding: '0 var(--space-2)',
              border: 'var(--border)',
              borderRadius: 'var(--radius-sm)',
              background: size === s ? 'var(--color-accent)' : 'var(--btn-default-bg)',
              color: size === s ? '#fff' : 'var(--color-text)',
              fontSize: 'var(--text-sm)',
              fontWeight: size === s ? 'var(--weight-bold)' : 'var(--weight-normal)',
              cursor: 'pointer',
            }}
          >
            {s}
          </button>
        ))}
        <input
          type="number"
          min={8}
          max={72}
          value={size}
          onChange={e => {
            const n = parseInt(e.target.value, 10)
            if (!isNaN(n) && n >= 8 && n <= 72) onChange(family, n)
          }}
          style={{
            height: 28,
            width: 56,
            padding: '0 var(--space-2)',
            border: 'var(--border)',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--input-bg)',
            color: 'var(--color-text)',
            fontSize: 'var(--text-sm)',
            textAlign: 'center',
          }}
        />
      </div>

      {/* Preview strip */}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-2)' }}>
        Preview
      </div>
      <div style={{
        fontFamily: family,
        fontSize:   size,
        background: 'var(--primitive-editor-bg)',
        color:      'var(--primitive-editor-fg)',
        borderRadius: 'var(--radius-sm)',
        padding:    'var(--space-3) var(--space-4)',
        maxWidth:   480,
        whiteSpace: 'nowrap',
        overflow:   'hidden',
        textOverflow: 'ellipsis',
        lineHeight: 1.6,
      }}>
        {preview}
      </div>
    </>
  )
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function SettingsScreen() {
  const {
    autoValidateOnLoad, setAutoValidateOnLoad,
    defaultEditorFont,  setDefaultEditorFont,
  } = useAppContext()

  return (
    <div className={styles.screen} style={{ padding: 'var(--space-6)', overflowY: 'auto' }}>
      <h2 style={{ marginBottom: 'var(--space-4)' }}>Preferences</h2>

      {/* ── JSON Editor Font ──────────────────────────────
          Drives: JSON editor body (View / Validate screen).
          The editor toolbar's Font… button can override this
          for the current session without changing this default. */}
      <section style={{ marginBottom: 'var(--space-6)' }}>
        <h3 style={sectionHeadStyle}>JSON Editor &amp; Output Font</h3>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--color-text-muted)', marginBottom: 'var(--space-4)', lineHeight: 'var(--leading-normal)' }}>
          Default monospace font for all JSON windows — the View / Validate editor and all
          JSON output panels (validation results, analysis output).
          <br />
          The <strong>Font…</strong> button in the editor toolbar can override this for the
          View / Validate editor for the current session only; it does not change this default.
        </p>

        <FontPicker
          family={defaultEditorFont.family}
          size={defaultEditorFont.size}
          onChange={(family, size) => setDefaultEditorFont({ family, size })}
          preview={`{ "specVersion": "1.6", "components": [ ] }`}
        />

        <button
          className="btn btn-default"
          style={{ marginTop: 'var(--space-3)' }}
          onClick={() => setDefaultEditorFont(DEFAULT_EDITOR_FONT)}
        >
          Reset to Default
        </button>
      </section>

      {/* ── Validation ───────────────────────────────── */}
      <section style={{ marginBottom: 'var(--space-6)' }}>
        <h3 style={sectionHeadStyle}>Validation</h3>

        <label className="checkbox-row" style={{ userSelect: 'none' }}>
          <input
            type="checkbox"
            checked={autoValidateOnLoad}
            onChange={e => setAutoValidateOnLoad(e.target.checked)}
          />
          <span>
            <strong>Auto-validate on BOM load</strong>
            <br />
            <span className="text-caption">
              Runs validation silently in the background whenever a new BOM file is opened.
              The result is shown in the status bar at the bottom of the window.
            </span>
          </span>
        </label>
      </section>

      {/* ── About ─────────────────────────────────────── */}
      <section>
        <h3 style={sectionHeadStyle}>About</h3>
        <p className="text-muted">
          SBOM Utility GUI — powered by CycloneDX sbom-utility.
        </p>
      </section>
    </div>
  )
}
