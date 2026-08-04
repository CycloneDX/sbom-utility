# sbom-utility TypeScript GUI

A React/Vite browser GUI for [sbom-utility](../README.md) backed by the local `sbom-utility serve` HTTP API.

No CGo. No native compiler. One `npm ci` and you are running.

---

## Table of contents

1. [What was built](#1-what-was-built)
2. [Design considerations](#2-design-considerations)
3. [Customising styles](#3-customising-styles)
4. [Architecture](#4-architecture)
5. [Prerequisites](#5-prerequisites)
6. [Quick start](#6-quick-start)
7. [Troubleshooting](#7-troubleshooting)
8. [Makefile targets](#8-makefile-targets)
9. [License](#9-license)

---

## 1. What was built

### Summary

A fully self-contained TypeScript browser GUI that communicates with the `sbom-utility` CLI via a local HTTP API (`sbom-utility serve`). It lives in `gui-ts/` — a **separate npm project** with its own `package.json`, `node_modules/`, and build output — and is completely independent of `go.mod`, `main.go`, and all existing Go tests.

### Feature inventory

| Feature | Description |
|---------|-------------|
| **Load BOM** | Browser file picker filtered to `.json` / `.xml`; auto-switches to the Validate screen on load |
| **Validate** | Runs `sbom-utility validate`; exposes `--variant`, `--force`, `--error-limit`, and `--error-value` flags; shows a colour-coded Valid / Invalid badge |
| **Licenses** | Runs `license list`; supports `--summary`, `--format` (txt/csv/json/md), and `--where` filter |
| **Components** | Runs `component list`; supports `--summary`, `--format` (txt/csv/md), and `--where` filter |
| **Resources** | Runs `resource list`; supports `--type` (all/component/service), `--format`, and `--where` |
| **Vulnerabilities** | Runs `vulnerability list`; supports `--summary`, `--format` (txt/csv/json/md), and `--where` |
| **JSON editor** | Editable BOM source pane with syntax highlighting; Save As writes back via the Go server |
| **Markdown rendering** | When `--format md` is selected, GFM pipe tables are parsed and rendered as native `<table>` elements |
| **Status bar** | Persistent bottom bar showing BOM format, spec version, and loaded filename |
| **Collapsible options panel** | Every command screen has a `▼ / ▶` toggle panel |
| **Auto-run on navigate** | Switching to any analysis screen while a BOM is loaded runs the default command automatically |
| **CSS design-token theming** | Every visual property is a named CSS custom property; the entire look can be changed without touching any `.tsx` file |

### Files

```
gui-ts/
├── README.md                        ← this file
├── package.json                     ← npm project; separate from go.mod
├── package-lock.json                ← reproducible installs (npm ci)
├── tsconfig.json                    ← TypeScript config
├── vite.browser.config.ts           ← Vite config for browser dev mode
├── index.html                       ← HTML shell
├── scripts/
│   └── dev-browser-with-serve.sh   ← starts Go server + Vite dev server
└── src/
    ├── preload/
    │   └── index.ts                 ← shared type definitions (SbomBridge interface)
    └── renderer/
        ├── main.tsx                 ← React root; injects mockBridge in browser mode
        ├── App.tsx                  ← AppProvider + Shell
        ├── mockBridge.ts            ← browser HTTP bridge to sbom-utility serve
        ├── vite-env.d.ts            ← window.sbomBridge type declaration
        ├── context/
        │   └── AppContext.tsx       ← Shared state: bomFile, bomInfo, active screen
        ├── styles/
        │   ├── tokens.css           ← ★ Design tokens — customise here
        │   └── app.css              ← Resets, typography, buttons, badges, tables
        └── components/
            ├── Shell.tsx / .module.css
            ├── Sidebar.tsx / .module.css
            ├── StatusBar.tsx / .module.css
            ├── OptionsPanel.tsx / .module.css
            ├── ResultsView.tsx / .module.css
            └── screens/
                ├── Screen.module.css       ← Shared two-column split layout
                ├── LoadScreen.tsx
                ├── ValidateScreen.tsx
                ├── LicenseScreen.tsx
                ├── ComponentScreen.tsx
                ├── ResourceScreen.tsx
                └── VulnerabilityScreen.tsx
```

---

## 2. Design considerations

### Visual design language

The GUI follows a **two-zone** layout:

```
┌──────────────────────────────────────────────────────────────────┐
│  dark sidebar (220 px)  │  light content area (fills remainder)  │
│                         │  ┌──────────────┬────────────────────┐ │
│  ● Load BOM             │  │ options panel│  results / viewer  │ │
│  ─────────────          │  │  (260 px)    │  (dark editor bg)  │ │
│  ● Validate             │  │              │                    │ │
│  ● Licenses             │  │              │                    │ │
│  ● Components           │  └──────────────┴────────────────────┘ │
│  ● Resources            ├────────────────────────────────────────┤
│  ● Vulnerabilities      │  status bar (28 px)                    │
│                         │  format · version · filename           │
└──────────────────────────────────────────────────────────────────┘
```

**Intentional contrast:** the sidebar is dark charcoal (`#2D2D2F`) while the content chrome is light (`#F5F5F5`). The results / viewer pane uses a dark editor background (`#1E1E1E`) so monospace BOM content is easy to read.

### Typography

The font stack resolves to the OS native sans-serif:

| Platform | Font resolved |
|----------|--------------|
| macOS | SF Pro Text |
| Windows | Segoe UI |
| Linux | Cantarell / DejaVu Sans |

Monospace output uses `ui-monospace` → Cascadia Code → Fira Code → Consolas → Courier New.

### Colour system

Colours are organised in two layers (see [`tokens.css`](src/renderer/styles/tokens.css)):

1. **Primitive colours** — named hex values (`--primitive-blue-600: #007AFF`). Never used directly in components.
2. **Semantic colours** — role aliases that reference primitives (`--color-accent: var(--primitive-blue-600)`). Components always reference semantic tokens.

### Accessibility baseline

- All interactive controls are standard HTML elements (`<button>`, `<select>`, `<input>`).
- Focus rings use `outline` + the accent colour (not removed).
- The status bar uses `role="status"` so screen readers announce BOM changes.
- Sidebar buttons use `aria-current="page"` for the active screen.

### Markdown table rendering

The built-in GFM table parser (`ResultsView.tsx`) requires no markdown library:

1. Split output into alternating text / pipe-table segments.
2. A pipe-table segment is only recognised when it contains a proper separator row (`|---|---|`).
3. Separator rows are stripped; row 0 becomes `<thead>`, the rest `<tbody>`.

---

## 3. Customising styles

The entire visual design is driven by CSS custom properties in [`src/renderer/styles/tokens.css`](src/renderer/styles/tokens.css).

### Token reference

| Section | Tokens | What it controls |
|---------|--------|-----------------|
| `§ 1` Primitive colours | `--primitive-*` | Raw hex values; never used in components directly |
| `§ 2` Semantic colours | `--color-bg`, `--color-accent`, `--color-error`, … | Role-based aliases |
| `§ 3` Typography | `--font-sans`, `--font-mono`, `--text-xs` … `--text-xl`, `--weight-*` | Font families, sizes, weights |
| `§ 4` Spacing & geometry | `--space-1` … `--space-8`, `--radius-sm/md/lg` | Padding scale, corner radii |
| `§ 5` Motion | `--duration-fast`, `--duration-normal`, `--ease-out` | Transition timing |
| `§ 6` Shadows | `--shadow-xs/sm/md` | Box-shadow definitions |
| `§ 7` Component tokens | `--sidebar-*`, `--statusbar-*`, `--viewer-*`, `--btn-*`, `--input-*`, `--badge-*` | Per-component overrides |

### Example A — corporate teal accent

```css
:root {
  --color-accent:        #00796B;
  --color-accent-hover:  #00695C;
  --color-accent-dim:    rgba(0, 121, 107, 0.15);
  --btn-primary-bg:      var(--color-accent);
  --btn-primary-hover:   var(--color-accent-hover);
  --sidebar-active-bg:   rgba(0, 121, 107, 0.30);
  --statusbar-bg:        #00695C;
}
```

### Example B — full dark mode for the app chrome

```css
@media (prefers-color-scheme: dark) {
  :root {
    --color-bg:           #1C1C1E;
    --color-surface:      #2C2C2E;
    --color-border:       #3A3A3C;
    --color-text:         #F2F2F7;
    --color-text-muted:   #8E8E93;
    --options-bg:         #2C2C2E;
    --options-border:     #3A3A3C;
    --table-header-bg:    #2C2C2E;
    --btn-default-bg:     #3A3A3C;
    --btn-default-border: #48484A;
    --input-bg:           #3A3A3C;
    --input-border:       #48484A;
  }
}
```

### Example C — swap to Inter font

```css
@font-face {
  font-family: 'Inter';
  src: url('../fonts/inter.woff2') format('woff2');
  font-weight: 100 900;
}
:root {
  --font-sans: 'Inter', -apple-system, "Segoe UI", system-ui, sans-serif;
}
```

### Example D — wider sidebar

```css
:root { --sidebar-width: 260px; }
```

---

## 4. Architecture

### Separation from the CLI

`gui-ts/` is a standalone npm project. It shares no source files with the Go CLI and makes no modifications to `go.mod`, `main.go`, or `cmd/`. The CLI binary is treated as an opaque executable invoked via the local HTTP API.

### Execution model

```
┌─────────────────────────────────────┐
│  Browser tab (Vite dev server)      │
│  React + TypeScript                 │
│  window.sbomBridge.validate(…)      │
│  (mockBridge — HTTP fetch)          │
└──────────────┬──────────────────────┘
               │ HTTP POST 127.0.0.1:8787
               ▼
┌─────────────────────────────────────┐
│  sbom-utility serve (Go HTTP API)   │
│  /api/validate, /api/bom-info, …    │
│  input validation + execFile        │
└──────────────┬──────────────────────┘
               │ argv array (no shell)
               ▼
┌─────────────────────────────────────┐
│  sbom-utility binary (Go)           │
│  stdout / stderr captured           │
└──────────────┬──────────────────────┘
               │
               ▼
         ResultsView component
```

### State management

| State | Type | Purpose |
|-------|------|---------|
| `bomFile` | `string` | Server-side path of the loaded BOM file |
| `bomDisplayName` | `string` | User-visible filename shown in the UI |
| `bomInfo` | `BomInfo` | Format and spec version (from `/api/bom-info`) |
| `screen` | `Screen` | Currently visible screen name |

### Bridge behaviour in browser mode

`mockBridge.ts` intercepts all `window.sbomBridge` calls and forwards them to the Go HTTP server. When a file is loaded via the browser file picker the server receives a multipart upload, writes it to a temporary directory, and returns the server-side path. `bomFile` holds that server path (used for all subsequent API calls); `bomDisplayName` holds the original filename shown in the UI.

---

## 5. Prerequisites

| Requirement | Minimum version | How to check |
|-------------|----------------|-------------|
| Node.js | 20 LTS | `node --version` |
| npm | 10 | `npm --version` (ships with Node 20) |
| sbom-utility binary | any | `go build -o sbom-utility .` from repo root |

No other global tools are required. `vite` is a devDependency and installs via `npm ci`.

---

## 6. Quick start

### Step 1 — build the CLI binary

```bash
# From the repo root
go build -o sbom-utility .          # macOS / Linux
go build -o sbom-utility.exe .      # Windows
```

Or use the Makefile:

```bash
make build
```

### Step 2 — install GUI dependencies

```bash
cd gui-ts && npm ci
```

### Step 3 — launch in development mode

```bash
# From repo root (builds Go binary first, then starts Vite + Go server)
make dev-gui-browser

# Or manually
cd gui-ts && npm run dev:browser:full
```

Then open **http://localhost:5173** in Chrome or Safari.

---

## 7. Troubleshooting

### Floating social-share overlay appears in Chrome

**Symptom:** A floating button appears in the bottom-right corner when loaded in Chrome.

**Cause:** A Chrome browser extension (commonly **Web Developer**) injecting a content script. The app's CSP blocks any outbound actions the overlay would take — it is visually present but completely inert.

**Fix:** Disable the extension while using the GUI:

1. Open `chrome://extensions`
2. Locate the offending extension
3. Toggle it off, or exclude `localhost` via **Details → On specific sites**

---

## 8. Makefile targets

| Target | Description |
|--------|-------------|
| `make dev-gui-browser` | Build Go binary, start Go HTTP server + Vite dev server |
| `make build` | Build the `sbom-utility` Go binary only |
| `make build-gui` | Build the legacy Fyne GUI binary |

---

## 9. License

The TypeScript GUI code (`gui-ts/`) is licensed under **Apache-2.0**, matching the rest of sbom-utility.

### Dependency licences

All dependencies are permissively licensed. No GPL, LGPL, AGPL, or SSPL code is present.

| Package | Licence |
|---------|---------|
| React | MIT |
| Vite | MIT |
| @vitejs/plugin-react | MIT |
| TypeScript | Apache-2.0 |
| @typescript-eslint/* | MIT |
| eslint | MIT |
