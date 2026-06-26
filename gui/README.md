# sbom-utility GUI

A native desktop GUI for [sbom-utility](../README.md), built with [Fyne](https://fyne.io) (BSD-3-Clause).  
No JavaScript. No Electron. No browser engine. No GPL or LGPL dependencies.

---

## File tree

```
gui/
├── README.md                    ← this file
├── main.go                      ← Fyne app entry point; mirrors main.go init() pattern
├── bridge/
│   ├── doc.go                   ← package documentation
│   ├── validate.go              ← wraps cmd.Validate()
│   ├── license.go               ← wraps cmd.ListLicenses()
│   ├── component.go             ← wraps cmd.ListComponents()
│   ├── resource.go              ← wraps cmd.ListResources()
│   └── vulnerability.go         ← wraps cmd.ListVulnerabilities()
├── screens/
│   ├── doc.go                   ← package documentation
│   ├── validate.go              ← Validate tab
│   ├── license.go               ← Licenses tab
│   ├── component.go             ← Components tab
│   ├── resource.go              ← Resources tab
│   └── vulnerability.go         ← Vulnerabilities tab
└── widgets/
    ├── doc.go                   ← package documentation
    ├── filepicker.go            ← reusable file-picker row (label + entry + Browse button)
    ├── results.go               ← scrollable monospace results view
    └── sidepanel.go             ← collapsible ▶/▼ toggle panel
```

---

## Architecture

### Key principles

**Separate binary — CLI is untouched.**  
The GUI is built from `./gui` and produces its own binary. The existing CLI binary
(`./`) is completely unaffected; its `main.go`, `cmd/`, and all existing tests are
unchanged.

**Bridge layer — no code duplication.**  
Each `bridge/*.go` file translates GUI inputs into the exact same function calls the
CLI cobra commands use. It does this by writing into `utils.GlobalFlags` (the same
global the CLI uses) and then calling the real exported `cmd.*` function directly —
no `exec.Command`, no re-implementation of any logic.

```
FilePicker + flag widgets
        │
        ▼
  bridge/validate.go          sets utils.GlobalFlags.PersistentFlags.InputFile
  bridge/license.go           sets utils.GlobalFlags.PersistentFlags.OutputFormat
  bridge/component.go         sets per-command flag structs (ValidateFlags, etc.)
  …                           calls cmd.Validate() / cmd.ListLicenses() / …
        │
        ▼
  cmd/validate.go             ← original, unmodified CLI implementation
  cmd/license_list.go
  cmd/component.go
  …
        │
        ▼
  bytes.Buffer  ──────────────▶  widgets/results.go  (scrollable text view)
```

**Automatic feature parity.**  
Because every screen calls the real `cmd.*` function, any bug fix or new flag added
to the CLI is automatically available in the GUI without any GUI-side changes.

**Async execution.**  
Every "Run" button fires work in a `go func(){}` goroutine so the Fyne UI remains
responsive during long scans or large BOM files.

### Screen layout pattern

Every tab follows the same structure:

```
┌─────────────────────────────────────────────────────────┐
│  BOM file: [_________________________]  [Browse]  [Run] │  ← top bar
├─────────────────────────────────────────────────────────┤
│ ▼ Command Options          │                            │
│   --variant  [_________]   │   (scrollable results)     │
│   --force    [_________]   │                            │
│   --format   [txt ▾]       │   bom-ref  type  name …    │
│   --where    [_________]   │   ────────────────────     │
│   Filter keys hint …       │   pkg:npm/…  lib  …        │
│                            │                            │
│ ▶ Command Options          │   (collapsed state)        │
└────────────────────────────┴────────────────────────────┘
  collapsible SidePanel (28%)   ResultsView (72%)
```

---

## Build prerequisites

| Platform | Requirement |
|----------|-------------|
| **macOS** | Xcode Command Line Tools (`xcode-select --install`) — provides clang |
| **Linux** | `gcc`, `libgl1-mesa-dev`, `xorg-dev` (headers only, not bundled in binary) |
| **Windows** | [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2/MinGW-w64 (MIT licensed) |

CGo must be enabled (`CGO_ENABLED=1`, which is the default on the host platform).

---

## Build

```bash
# Build GUI binary (output: sbom-utility-gui)
go build -o sbom-utility-gui ./gui

# Build CLI binary (unchanged)
go build -o sbom-utility .

# Run directly without producing a binary
go run ./gui
```

### macOS — packaged .app bundle

```bash
go install fyne.io/tools/cmd/fyne@latest
fyne package -os darwin -icon gui/Icon.png -name "SBOM Utility" ./gui
# Produces: SBOM Utility.app
```

### Windows — .exe with embedded icon

```bash
fyne package -os windows -icon gui/Icon.png -name "SBOM Utility" ./gui
# Produces: SBOM Utility.exe  (no runtime DLLs needed)
```

### Linux — .tar.xz with desktop entry

```bash
fyne package -os linux -icon gui/Icon.png -name "SBOM Utility" ./gui
```

### Cross-compilation (all platforms from one host)

[fyne-cross](https://github.com/fyne-io/fyne-cross) (MIT) uses Docker to cross-compile
for all targets without manual cross-toolchain setup:

```bash
go install github.com/fyne-io/fyne-cross@latest
fyne-cross darwin --arch=amd64,arm64 ./gui
fyne-cross windows --arch=amd64      ./gui
fyne-cross linux   --arch=amd64,arm64 ./gui
```

---

## License

The GUI code (`gui/`) is licensed under the **Apache-2.0** license, matching the rest
of sbom-utility.

The GUI depends on [Fyne](https://github.com/fyne-io/fyne) (BSD-3-Clause) and its
transitive dependencies, all of which are permissively licensed (MIT, BSD-3, zlib,
Apache-2.0). No GPL or LGPL code is introduced.
