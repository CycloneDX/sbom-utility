# sbom-utility GUI

A native desktop GUI for [sbom-utility](../README.md), built with [Fyne](https://fyne.io) (BSD-3-Clause).
No JavaScript. No Electron. No browser engine. No GPL or LGPL dependencies.

---

## File tree

```
gui/
├── README.md                    ← this file
├── main.go                      ← Fyne app entry point; mirrors main.go init() pattern
├── theme/
│   └── macos.go                 ← custom macOS-inspired Fyne theme
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

---

## Theme

The GUI uses a custom macOS-inspired Fyne theme defined in [`gui/theme/macos.go`](theme/macos.go). It targets **macOS Ventura / Sonoma light-mode** aesthetics and is active on all platforms.

### Color palette

| Role | Hex | macOS semantic |
|------|-----|----------------|
| Window background | `#F5F5F5` | Window chrome grey |
| Panel / input background | `#FFFFFF` | White content areas |
| Sidebar / header rows | `#EBEBEB` | Sidebar grey |
| Primary accent | `#007AFF` | System blue |
| Focus ring / selection | `#007AFF` 20 % | Translucent accent |
| Primary text | `#1D1D1F` | Label |
| Secondary / placeholder text | `#6E6E73` | Secondary label |
| Separator / input border | `#D2D2D7` | Separator |
| Error | `#FF3B30` | System red |
| Warning | `#FF9F0A` | System amber |
| Success | `#30D158` | System green |
| Shadow | `#000000` 15 % | Drop shadow |

### Typography & spacing

Sizes follow the [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines/typography):

| Token | Size (pt) |
|-------|-----------|
| Body text | 13 |
| Caption | 11 |
| Heading | 17 |
| Sub-heading | 15 |
| Padding | 6 |
| Inner padding | 4 |
| Input border | 1 |
| Input corner radius | 5 |
| Scroll bar width | 8 |
| Separator thickness | 1 |

> **Font note:**
The theme uses Fyne's built-in sans-serif faces (regular, bold,
> italic, monospace), which are visually close to Apple's SF Pro at these sizes.

### Customizing the theme

To override colors or sizes, edit [`gui/theme/macos.go`](theme/macos.go).
Each `Color()` and `Size()` case maps directly to a named Fyne constant
(e.g. `theme.ColorNamePrimary`, `theme.SizeNameText`).
Any color name not explicitly listed falls back to `theme.LightTheme()`.

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
# Build GUI binary via Make (output: sbom-utility-gui)
make build-gui

# Build GUI binary directly
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

The GUI code (`gui/`) is licensed under the **Apache-2.0** license, matching the rest of `sbom-utility`.

The GUI depends on [Fyne](https://github.com/fyne-io/fyne) (BSD-3-Clause) and its transitive dependencies, all of which are permissively licensed (MIT, BSD-3, zlib, Apache-2.0). No GPL or LGPL code is introduced.
