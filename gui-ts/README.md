# sbom-utility TypeScript GUI

A native desktop GUI for [sbom-utility](../README.md), built with
[Electron](https://www.electronjs.org) (MIT · OpenJS Foundation),
[React 18](https://react.dev) (MIT), [Vite 5](https://vitejs.dev) (MIT),
and TypeScript 5.

No CGo. No native compiler. One `npm ci` and you are running.

---

## Table of contents

1. [What was built](#1-what-was-built)
2. [Design considerations](#2-design-considerations)
3. [Security hardening](#3-security-hardening)
4. [Customising styles](#4-customising-styles)
5. [Architecture](#5-architecture)
6. [Prerequisites](#6-prerequisites)
7. [Quick start](#7-quick-start)
8. [Build & distribute](#8-build--distribute)
9. [Makefile targets](#9-makefile-targets)
10. [License](#10-license)

---

## 1. What was built

### Summary

A fully self-contained TypeScript/Electron desktop application that wraps the
`sbom-utility` CLI binary with a polished, themeable graphical interface.  It
lives in `gui-ts/` — a **separate npm project** with its own `package.json`,
`node_modules/`, and build output — and is completely independent of
`go.mod`, `main.go`, and all existing Go tests.

### Feature inventory

| Feature | Description |
|---------|-------------|
| **Load BOM** | OS-native file-open dialog filtered to `.json` / `.xml`; auto-switches to the View screen on load |
| **View** | Raw BOM source displayed in a scrollable dark-editor pane (VS Code-inspired palette); preserves all whitespace and Unicode |
| **Validate** | Runs `sbom-utility validate`; exposes `--variant`, `--force`, `--error-limit`, and `--error-value` flags; shows a colour-coded Valid / Invalid / Error badge |
| **Licenses** | Runs `license list`; supports `--summary`, `--format` (txt/csv/json/md), and `--where` filter with syntax hints |
| **Components** | Runs `component list`; supports `--summary`, `--format` (txt/csv/md), and `--where` filter with all 16 documented keys |
| **Resources** | Runs `resource list`; supports `--type` (all/component/service), `--format`, and `--where` |
| **Vulnerabilities** | Runs `vulnerability list`; supports `--summary`, `--format` (txt/csv/json/md), and `--where` with all documented filter keys |
| **Markdown rendering** | When `--format md` is selected, GFM pipe tables are parsed and rendered as native `<table>` elements; all other markdown blocks render as pre-formatted text |
| **Status bar** | Persistent bottom bar showing BOM format, spec version, and filename; hovering the filename shows the full absolute path |
| **Collapsible options panel** | Every command screen has a `▼ / ▶` toggle panel — identical behaviour to the Fyne `SidePanel` |
| **Auto-run on navigate** | Switching to any analysis screen while a BOM is loaded runs the default command automatically |
| **Async execution** | All CLI invocations run in Node.js child processes; the UI thread is never blocked |
| **Dark editor pane** | View and all results areas use the `--viewer-*` token group (charcoal `#1E1E1E` background, `#CECECE` foreground) — independent of the light app chrome |
| **CSS design-token theming** | Every visual property is a named CSS custom property; the entire look can be changed without touching any `.tsx` file |

### Feature parity with the Fyne GUI

| Feature | Fyne GUI | TypeScript GUI |
|---------|:--------:|:--------------:|
| Load BOM (`.json` / `.xml`) | ✅ | ✅ |
| View raw BOM source (dark editor) | ✅ | ✅ |
| Validate — variant, force, error-limit, show-values | ✅ | ✅ |
| Valid / Invalid status badge | ✅ | ✅ |
| Licenses — summary, format, --where | ✅ | ✅ |
| Components — summary, format, --where | ✅ | ✅ |
| Resources — type, format, --where | ✅ | ✅ |
| Vulnerabilities — summary, format, --where | ✅ | ✅ |
| Markdown output rendered as GFM tables | ✅ | ✅ |
| Status bar (format · version · filename) | ✅ | ✅ |
| Collapsible sidebar options panel | ✅ | ✅ |
| Auto-run on screen switch | ✅ | ✅ |
| Native OS file dialog | ✅ | ✅ |
| Async (non-blocking) command execution | ✅ | ✅ |
| CSS design-token theming | — | ✅ **new** |
| OS-native dark-mode media query support | — | ✅ **new** |
| Component-level CSS Module overrides | — | ✅ **new** |

### Files created

```
gui-ts/
├── README.md                        ← this file
├── package.json                     ← npm project; separate from go.mod
├── package-lock.json                ← reproducible installs (npm ci)
├── tsconfig.json                    ← TypeScript config (renderer)
├── tsconfig.node.json               ← TypeScript config (vite.config.ts)
├── vite.config.ts                   ← Vite + vite-plugin-electron config
├── index.html                       ← HTML shell with CSP meta tag
├── electron-builder.yml             ← Distribution packaging config
├── install.sh                       ← macOS / Linux install helper
├── install.ps1                      ← Windows PowerShell install helper
├── build/
│   └── entitlements.mac.plist      ← macOS Hardened Runtime (minimum entitlements)
└── src/
    ├── main/
    │   ├── index.ts                 ← Electron main process: window, menu, CSP, nav guards
    │   └── ipc-handlers.ts          ← IPC bridge: input validation → execFile → binary
    ├── preload/
    │   └── index.ts                 ← contextBridge: the only API surface the renderer sees
    └── renderer/
        ├── main.tsx                 ← React root (StrictMode)
        ├── App.tsx                  ← AppProvider + Shell
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
                ├── ViewScreen.tsx
                ├── ValidateScreen.tsx
                ├── LicenseScreen.tsx
                ├── ComponentScreen.tsx
                ├── ResourceScreen.tsx
                └── VulnerabilityScreen.tsx
```

---

## 2. Design considerations

### Why Electron

Electron was chosen after a structured evaluation of TypeScript desktop
frameworks against three constraints: 100 % open-source, no corporate upsell
tier, and governance that cannot be relicensed at a company's whim.

| Framework | Licence | Governance | Verdict |
|-----------|---------|-----------|---------|
| **Electron** ✅ | MIT | **OpenJS Foundation** (Linux Foundation sub-project) — IP held by a foundation; no single company can relicense | Best governance + highest consumer adoption |
| Tauri v2 | MIT + Apache-2.0 | Community working group; no foundation IP assignment | Best security architecture but governance risk |
| Wails v2 | MIT | Single primary maintainer; no foundation | Highest governance risk |
| NeutralinoJS | MIT | Has a paid cloud product from the same team | Fails "no upsell" constraint |

Electron's security architecture is sound when built with modern defaults
(see [§ 3 Security hardening](#3-security-hardening)).  The "Electron is
insecure" reputation applies to apps built with 2016–2019 defaults
(`nodeIntegration: true`, no sandbox) — none of which are used here.

### Visual design language

The GUI follows a **two-zone** layout:

```
┌──────────────────────────────────────────────────────────────────┐
│  dark sidebar (220 px)  │  light content area (fills remainder)  │
│                         │  ┌──────────────┬────────────────────┐ │
│  ● Load BOM             │  │ options panel│  results / viewer  │ │
│  ─────────────          │  │  (260 px)    │  (dark editor bg)  │ │
│  ● View                 │  │              │                    │ │
│  ● Validate             │  │              │                    │ │
│  ● Licenses             │  └──────────────┴────────────────────┘ │
│  ● Components           ├────────────────────────────────────────┤
│  ● Resources            │  status bar (26 px)                    │
│  ● Vulnerabilities      │  format · version · filename           │
└──────────────────────────────────────────────────────────────────┘
```

**Intentional contrast:** the sidebar is dark charcoal (`#2D2D2F`) while the
content chrome is light (`#F5F5F5`). This creates a clear visual boundary
between navigation and work area — a pattern common in professional developer
tools (VS Code, JetBrains IDEs, GitHub Desktop). The results / viewer pane
reverts to a dark editor background (`#1E1E1E`) so that monospace BOM content
is easy to read without eye strain.

### Typography

The font stack resolves to the OS native sans-serif:

| Platform | Font resolved |
|----------|--------------|
| macOS | SF Pro Text |
| Windows | Segoe UI |
| Linux | Cantarell / DejaVu Sans |

Body size is **13 px**, matching the macOS Human Interface Guidelines for
application body text. Monospace output uses `ui-monospace` → Cascadia Code →
Fira Code → Consolas → Courier New — whatever the OS provides, in that order.

### Colour system

Colours are organised in two layers (see [`tokens.css`](src/renderer/styles/tokens.css)):

1. **Primitive colours** — named hex values (`--primitive-blue-600: #007AFF`).
   These are never used directly in components.
2. **Semantic colours** — role aliases that reference primitives
   (`--color-accent: var(--primitive-blue-600)`).  Components always reference
   semantic tokens, never primitives.

This means you can retheme the entire application by changing only the semantic
layer, without touching any component code.

### Separation of concerns

| Layer | Responsibility |
|-------|---------------|
| `src/main/` | OS integration: window lifecycle, menu, CSP, file dialogs |
| `src/main/ipc-handlers.ts` | Security boundary: validates all input, invokes the binary |
| `src/preload/` | Bridge contract: typed, minimal API via `contextBridge` |
| `src/renderer/context/` | Shared application state (React context) |
| `src/renderer/styles/` | Visual design tokens and global resets |
| `src/renderer/components/` | Purely presentational React components |

No component imports from `src/main/` or `src/preload/`. No main-process code
imports from `src/renderer/`. These boundaries are enforced by TypeScript's
module resolution.

### Accessibility baseline

- All interactive controls are standard HTML elements (`<button>`, `<select>`,
  `<input>`) so they participate in the OS accessibility tree without custom
  ARIA gymnastics.
- Focus rings use `outline` + the accent colour (not removed).
- The status bar uses `role="status"` so screen readers announce BOM changes.
- Sidebar buttons use `aria-current="page"` for the active screen and
  `title` for disabled-state explanations.

### Markdown table rendering

The built-in GFM table parser (`ResultsView.tsx`) mirrors the logic in the
Fyne `widgets/results.go`:

1. Split output into alternating text / pipe-table segments.
2. A pipe-table segment is only recognised when it contains a proper separator
   row (`|---|---|`) — bare `|` characters in error messages are not mistaken
   for tables.
3. Separator rows are stripped; row 0 becomes `<thead>`, the rest `<tbody>`.
4. Column widths are estimated from cell content length.

This approach requires no markdown library dependency and produces a native,
styled HTML table that can be selected, copied, and printed.

---

## 3. Security hardening

### Electron BrowserWindow settings

All settings are declared explicitly in
[`src/main/index.ts`](src/main/index.ts) — defaults are never relied upon:

| Setting | Value | Rationale |
|---------|-------|-----------|
| `contextIsolation` | `true` | Renderer JS runs in a separate V8 context; cannot reach Node.js or Electron APIs |
| `nodeIntegration` | `false` | Node.js is not injected into the renderer process |
| `sandbox` | `true` | OS-level Chromium sandbox: seccomp-BPF on Linux, Win32 Job Objects on Windows, App Sandbox on macOS |
| `webSecurity` | `true` | Same-origin policy enforced (this is the Chromium default; it is set explicitly to prevent accidental override) |
| `allowRunningInsecureContent` | `false` | Mixed HTTP/HTTPS content is blocked |
| `experimentalFeatures` | `false` | No unstable Chromium features |

### Content Security Policy

A strict CSP is applied at **two independent layers** so it cannot be bypassed
by a renderer-level exploit:

1. A `<meta http-equiv="Content-Security-Policy">` tag in `index.html` (first
   line of defence, parsed by Chromium before any script runs).
2. A response header injected by `session.webRequest.onHeadersReceived` in the
   main process — this takes precedence over the meta tag.

```
default-src 'self';
script-src  'self';
style-src   'self' 'unsafe-inline';  ← Vite injects <style>; no CDN sheets
img-src     'self' data:;
font-src    'self' data:;
connect-src 'none';                  ← Zero outbound network from the renderer
object-src  'none';
base-uri    'none';
frame-ancestors 'none';
```

`connect-src 'none'` is **deliberately strict**: sbom-utility processes local
files only. If you add update-check or telemetry in future, change this to
`connect-src 'self' https://api.github.com` and document the change in a
security notice.

### Navigation and window.open guards

```typescript
// will-navigate — blocks any navigation to a URL outside the app origin
mainWindow.webContents.on('will-navigate', (event, url) => {
  if (!url.startsWith(appURL)) event.preventDefault()
})

// setWindowOpenHandler — denies all window.open() and <a target="_blank">
mainWindow.webContents.setWindowOpenHandler(({ url }) => {
  if (url.startsWith('https://')) shell.openExternal(url)
  return { action: 'deny' }
})
```

### IPC input validation

Every handler in [`src/main/ipc-handlers.ts`](src/main/ipc-handlers.ts)
validates its arguments before touching the file system or spawning a process.
Two validators are used:

**`validateFilePath(path)`**
- Rejects non-string and empty values.
- Rejects relative paths (`path.isAbsolute()` must be true).
- Normalises the path (`path.normalize()`) and rejects anything that still
  contains `..` after normalisation.
- Rejects paths that do not exist on disk (`fs.existsSync()`).

**`allowList(value, allowed, default)`**
- Checks string values (output format, resource type) against a frozen
  `as const` array of permitted strings.
- Any value not in the array throws; it is never forwarded to the binary.

**`execFile`, never `exec`**
- Arguments are passed as a `string[]` array — no shell interpolation is
  possible regardless of what the renderer sends.
- `maxBuffer` is capped at 32 MB to prevent memory exhaustion from
  pathologically large BOM files.

### Binary path isolation

The `sbom-utility` binary path is resolved **once at startup** by
`resolveBinaryPath()` in `src/main/index.ts`:

```typescript
// Packaged: always from process.resourcesPath
path.join(process.resourcesPath, 'sbom-utility')

// Development: always from the repo root relative to __dirname
path.resolve(__dirname, '..', '..', '..', '..', 'sbom-utility')
```

This path is stored in a `BridgeConfig` struct and passed into the IPC
handlers at registration time. **No renderer input can influence which
executable is invoked.**

### macOS Hardened Runtime

The [`build/entitlements.mac.plist`](build/entitlements.mac.plist) contains
only the minimum entitlements required by Electron and Chromium:

| Entitlement | Reason |
|-------------|--------|
| `com.apple.security.cs.allow-jit` | Required by V8 for JIT compilation |
| `com.apple.security.cs.disable-library-validation` | Required by Chromium's GPU process |
| `com.apple.security.files.user-selected.read-only` | Read files the user explicitly opens via the dialog |

`com.apple.security.network.client` is **absent** — the app makes no outbound
network connections.

### Dependency supply-chain

All dependencies are permissively licensed (MIT or Apache-2.0).  No GPL,
LGPL, AGPL, SSPL, or Commons Clause dependencies are present.  Run
`npm audit` at any time to check for known CVEs in the dependency tree.

Electron itself is maintained by the
[OpenJS Foundation](https://openjsf.org) (a Linux Foundation sub-project).
The IP is held by the foundation — no single company can relicense it.

---

## 4. Customising styles

The entire visual design is driven by CSS custom properties in
[`src/renderer/styles/tokens.css`](src/renderer/styles/tokens.css).
No component source code needs to change to retheme the application.

### Token reference

| Section | Tokens | What it controls |
|---------|--------|-----------------|
| `§ 1` Primitive colours | `--primitive-*` | Raw hex values; never used in components directly |
| `§ 2` Semantic colours | `--color-bg`, `--color-accent`, `--color-error`, … | Role-based aliases that reference § 1 |
| `§ 3` Typography | `--font-sans`, `--font-mono`, `--text-xs` … `--text-xl`, `--weight-*` | Font families, sizes, weights, line-heights |
| `§ 4` Spacing & geometry | `--space-1` … `--space-8`, `--radius-sm/md/lg`, `--border-width` | Padding scale, corner radii, border widths |
| `§ 5` Motion | `--duration-fast`, `--duration-normal`, `--ease-out` | Transition timing |
| `§ 6` Shadows | `--shadow-xs/sm/md` | Box-shadow definitions |
| `§ 7` Component tokens | `--sidebar-*`, `--statusbar-*`, `--viewer-*`, `--btn-*`, `--input-*`, `--badge-*` | Per-component overrides without touching layout |

### How to apply a custom theme

**Option A — override tokens in place.**
Edit the `:root` block at the bottom of `tokens.css`.  This is the simplest
approach for one-off customisations.

**Option B — separate override file.**
Create `src/renderer/styles/tokens-custom.css`, add it as a second
`<link>` in `index.html` after `tokens.css`.  Tokens in the second file win.
This keeps your changes separate from upstream and simplifies future merges.

**Option C — CSS Module override.**
Each component has a co-located `.module.css` file.  Override a single
component's layout or spacing without touching any token.

---

### Example A — corporate teal accent

```css
/* tokens-custom.css */
:root {
  --color-accent:        #00796B;
  --color-accent-hover:  #00695C;
  --color-accent-dim:    rgba(0, 121, 107, 0.15);
  --color-accent-dim2:   rgba(0, 121, 107, 0.30);
  --btn-primary-bg:      var(--color-accent);
  --btn-primary-hover:   var(--color-accent-hover);
  --sidebar-active-bg:   rgba(0, 121, 107, 0.30);
  --statusbar-bg:        #00695C;
  --color-border-focus:  #00796B;
}
```

### Example B — full dark mode for the app chrome

The results and viewer panes are already dark.  This example makes the
sidebar, content area, and options panel dark to match.

```css
@media (prefers-color-scheme: dark) {
  :root {
    /* App chrome */
    --color-bg:           #1C1C1E;
    --color-surface:      #2C2C2E;
    --color-border:       #3A3A3C;
    --color-text:         #F2F2F7;
    --color-text-muted:   #8E8E93;
    /* Options panel */
    --options-bg:         #2C2C2E;
    --options-border:     #3A3A3C;
    /* Table header */
    --table-header-bg:    #2C2C2E;
    /* Buttons */
    --btn-default-bg:     #3A3A3C;
    --btn-default-border: #48484A;
    --btn-default-hover:  #48484A;
    /* Inputs */
    --input-bg:           #3A3A3C;
    --input-border:       #48484A;
  }
}
```

### Example C — swap to Inter font

Place the `.woff2` file at `src/renderer/fonts/inter.woff2`, then:

```css
/* tokens-custom.css */
@font-face {
  font-family: 'Inter';
  src: url('../fonts/inter.woff2') format('woff2');
  font-weight: 100 900;
  font-style:  normal;
}

:root {
  --font-sans: 'Inter', -apple-system, "Segoe UI", system-ui, sans-serif;
}
```

> **Security note:** Do not use `url()` with external CDN origins (e.g. Google
> Fonts). The CSP's `font-src 'self' data:` directive blocks external font
> fetches. All font assets must be local to the bundle.

### Example D — wider sidebar

```css
/* Sidebar.module.css  (or tokens-custom.css) */
:root {
  --sidebar-width: 260px;
}
```

### Example E — light-coloured sidebar

```css
:root {
  --sidebar-bg:         #F0F0F5;
  --sidebar-text:       #1D1D1F;
  --sidebar-text-muted: #6E6E73;
  --sidebar-border:     #D2D2D7;
  --sidebar-hover-bg:   rgba(0, 0, 0, 0.05);
  --sidebar-active-bg:  rgba(0, 122, 255, 0.12);
  --sidebar-active-text: #007AFF;
}
```

---

## 5. Architecture

### Separation from the CLI

`gui-ts/` is a standalone npm project.  It shares no source files with the Go
CLI and makes no modifications to `go.mod`, `main.go`, or `cmd/`.  The CLI
binary is treated as an opaque executable — the GUI cannot see its source.

### Execution model

```
┌─────────────────────────────────────┐
│  Renderer (Chromium, sandboxed)     │
│  React + TypeScript                 │
│  window.sbomBridge.validate(…)      │
└──────────────┬──────────────────────┘
               │ contextBridge (preload/index.ts)
               │ Only 9 typed methods exposed
               ▼
┌─────────────────────────────────────┐
│  Main process (Node.js)             │
│  ipc-handlers.ts                    │
│  validateFilePath() + allowList()   │
│  execFile(binaryPath, args, …)      │
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

Application state is managed with React context
(`src/renderer/context/AppContext.tsx`).  No external state library is
required.  The state surface is minimal:

| State | Type | Purpose |
|-------|------|---------|
| `bomFile` | `string` | Absolute path of the loaded BOM file |
| `bomInfo` | `BomInfo` | Format, spec version, file path (from `bom:info` IPC) |
| `screen` | `Screen` | Currently visible screen name |
| `version` | `string` | App version string from `app.getVersion()` |

Listener callbacks (for BOM file change notifications) are stored in a `ref`
so they do not trigger context re-renders.

### Component model

All components are functional React components with TypeScript strict mode.
Each has a co-located CSS Module (`*.module.css`) for scoped styles.  Global
tokens from `tokens.css` are available inside every module via CSS custom
properties — modules reference `var(--color-accent)` not hard-coded values.

---

## 6. Prerequisites

| Requirement | Minimum version | How to check |
|-------------|----------------|-------------|
| Node.js | 20 LTS | `node --version` |
| npm | 10 | `npm --version` (ships with Node 20) |
| sbom-utility binary | any | `go build -o sbom-utility .` from repo root |

No other global tools are required.  `electron`, `vite`, and
`electron-builder` are all devDependencies and install automatically.

---

## 7. Quick start

### Step 1 — build the CLI binary

```bash
# From the repo root
go build -o sbom-utility .          # macOS / Linux
go build -o sbom-utility.exe .      # Windows
```

### Step 2 — install GUI dependencies

The installer scripts verify Node.js ≥ 20 and the binary before running
`npm ci`.

```bash
# macOS or Linux (from repo root)
./gui-ts/install.sh

# Windows (PowerShell, from repo root)
.\gui-ts\install.ps1
```

### Step 3 — launch in development mode

```bash
cd gui-ts
npm run dev
```

Electron opens automatically.  The Vite dev server provides hot-module
replacement (HMR) — React component changes appear instantly without
restarting Electron.

### One-liner (after first install)

```bash
cd gui-ts && npm run dev
```

---

## 8. Build & distribute

### Development / smoke-test build

```bash
cd gui-ts
npm run build
# TypeScript type-check → Vite bundle → electron-builder --dir (unpackaged)
# Output: gui-ts/dist-release/<platform>-unpacked/SBOM Utility
```

### Production distributable packages

```bash
cd gui-ts

npm run dist:mac    # .dmg (universal: x64 + arm64)
npm run dist:win    # NSIS installer .exe (x64 + arm64)
npm run dist:linux  # AppImage + .deb (x64 + arm64)
npm run dist        # all platforms (needs Docker or cross-compile toolchain)
```

All outputs land in `gui-ts/dist-release/`.

### Via Makefile (from repo root)

```bash
make build-gui-ts   # npm ci + vite build + electron-builder --dir
make dist-gui-ts    # npm ci + full npm run dist
make dev-gui-ts     # npm run dev (hot-reload; no binary produced)
```

### Version injection

```bash
cd gui-ts
npm version 0.17.0 --no-git-tag-version   # bumps package.json only
npm run dist:mac
```

`app.getVersion()` reads `package.json` automatically — no linker flags needed.

### Code-signing

| Platform | Environment variables | Notes |
|----------|-----------------------|-------|
| macOS | `CSC_LINK` (path to `.p12`), `CSC_KEY_PASSWORD` | `hardenedRuntime: true` and the entitlements file are already wired |
| Windows | `CSC_LINK` (path to `.p12`), `CSC_KEY_PASSWORD` | electron-builder calls `signtool.exe` automatically |
| Linux | n/a | AppImage and `.deb` do not require code-signing |

---

## 9. Makefile targets

| Target | Command | Output |
|--------|---------|--------|
| `make build-gui-ts` | `cd gui-ts && npm ci && npm run pack` | Unpackaged Electron app in `dist-release/` |
| `make dist-gui-ts` | `cd gui-ts && npm ci && npm run dist` | Platform installer(s) in `dist-release/` |
| `make dev-gui-ts` | `cd gui-ts && npm run dev` | Dev server + Electron window (hot-reload) |
| `make build-gui` | `go build -o sbom-utility-gui ./gui` | Fyne GUI binary (unchanged) |

---

## 10. License

The TypeScript GUI code (`gui-ts/`) is licensed under **Apache-2.0**, matching
the rest of sbom-utility.

### Dependency licences

All dependencies are permissively licensed.  No GPL, LGPL, AGPL, or SSPL
code is introduced.

| Package | Licence | Governance body |
|---------|---------|----------------|
| Electron | MIT | **OpenJS Foundation** (Linux Foundation) — IP held by foundation |
| React | MIT | Meta Open Source |
| Vite | MIT | Community / VoidZero |
| vite-plugin-electron | MIT | Community |
| electron-builder | MIT | Community |
| TypeScript | Apache-2.0 | Microsoft Open Source |
| @vitejs/plugin-react | MIT | Community / VoidZero |
| @typescript-eslint/* | MIT | typescript-eslint organisation |
| eslint | MIT | OpenJS Foundation |
