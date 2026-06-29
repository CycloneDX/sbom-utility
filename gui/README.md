# sbom-utility GUI

A native desktop GUI for [sbom-utility](../README.md), built with [Fyne](https://fyne.io) (BSD-3-Clause).
No JavaScript. No Electron. No browser engine. No GPL or LGPL dependencies.

---

## File tree

```
gui/
├── README.md                    ← this file
├── FyneApp.toml                 ← Fyne app metadata (name, ID, version, icon path)
├── main.go                      ← Fyne app entry point; mirrors main.go init() pattern
├── theme/
│   ├── macos.go                 ← custom macOS-inspired Fyne theme (global)
│   └── viewer.go                ← dark editor theme for the BOM source viewer
├── bridge/
│   ├── doc.go                   ← package documentation
│   ├── bom_info.go              ← parses BOM spec-version for the status bar
│   ├── validate.go              ← wraps cmd.Validate()
│   ├── license.go               ← wraps cmd.ListLicenses()
│   ├── component.go             ← wraps cmd.ListComponents()
│   ├── resource.go              ← wraps cmd.ListResources()
│   └── vulnerability.go         ← wraps cmd.ListVulnerabilities()
├── screens/
│   ├── doc.go                   ← package documentation
│   ├── state.go                 ← shared AppState (BOM file path, BOM info)
│   ├── load.go                  ← Load BOM file-open dialog + raw viewer
│   ├── view.go                  ← View tab (raw BOM source viewer)
│   ├── validate.go              ← Validate tab
│   ├── license.go               ← Licenses tab
│   ├── component.go             ← Components tab
│   ├── resource.go              ← Resources tab
│   └── vulnerability.go         ← Vulnerabilities tab
└── widgets/
    ├── doc.go                   ← package documentation
    ├── filepicker.go            ← reusable file-picker row (label + entry + Browse button)
    ├── results.go               ← scrollable monospace results view
    ├── sidepanel.go             ← collapsible ▶/▼ toggle panel
    └── statusbar.go             ← bottom status bar (spec version + file path)
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

The GUI uses two cooperating themes defined in `gui/theme/`:

| File | Scope |
|------|-------|
| [`macos.go`](theme/macos.go) | Global — applied to the whole application via `a.Settings().SetTheme()` |
| [`viewer.go`](theme/viewer.go) | Local — applied only to the BOM source viewer via `container.NewThemeOverride()` |

### Global theme (`macos.go`)

Targets **macOS Ventura / Sonoma light-mode** aesthetics and is active on all platforms.

#### Color palette

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

#### Typography & spacing

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

> **Font note:** The theme uses Fyne's built-in sans-serif faces (regular, bold,
> italic, monospace), which are visually close to Apple's SF Pro at these sizes.

### Viewer theme (`viewer.go`)

The BOM source viewer (the **View** pane and the raw viewer shown after **Load BOM**) uses a separate dark-editor colour scheme, applied via `container.NewThemeOverride`. Only the widget tree inside that container sees these overrides; the rest of the application is unaffected.

#### Color palette

| Role | Hex | Notes |
|------|-----|-------|
| Background / input background | `#1E1E1E` | VS Code-style dark charcoal |
| Foreground (text) | `#CECECE` | Light grey — easy on the eye against dark bg |
| Placeholder text | `#7A7A7A` | Dimmer grey |
| Disabled text | `#888888` | Slightly lighter than placeholder |
| Text selection | `#264F78` | Muted blue (VS Code selection) |
| Cursor / focus | `#CECECE` | Matches foreground |
| Input border | `#3C3C3C` | Subtle, same family as bg |
| Scroll bar | `#606060` / `#2A2A2A` | Track and thumb |

#### Font

The entry widget uses `fyne.TextStyle{Monospace: true}`. Fyne resolves monospace fonts from the host OS font stack at runtime using the following fallback order:

1. **Consolas** (Windows default monospace; also present on many macOS installs)
2. **Courier New** (bundled on all major platforms)
3. System monospace fallback (Menlo on macOS, Monospace on Linux)

No TTF files are bundled; the OS font stack is used directly.

### Customizing the themes

- **Global colours / sizes** → edit [`gui/theme/macos.go`](theme/macos.go). Each `Color()` and `Size()` case maps to a named Fyne constant (e.g. `theme.ColorNamePrimary`, `theme.SizeNameText`). Unlisted names fall back to `theme.LightTheme()`.
- **Viewer background / foreground** → edit the `Viewer*` colour variables at the top of [`gui/theme/viewer.go`](theme/viewer.go). Only the colour tokens listed in its `Color()` method are overridden; all others delegate to the active global theme.

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

There are two ways to build and run the GUI: **`go run` / `go build`** for development:

| Method | Output | macOS app-menu name | Windows taskbar name |
|--------|--------|---------------------|----------------------|
| `go run ./gui` | no binary | binary temp name | n/a |
| `go build -o sbom-utility-gui ./gui` | raw binary | `sbom-utility-gui` (file name) | `sbom-utility-gui` |

### Development (go run / go build)

```bash
# Run directly without producing a binary (app-menu shows temp binary name on macOS)
go run ./gui

# Build raw binary (app-menu shows "sbom-utility-gui" on macOS)
go build -o sbom-utility-gui ./gui

# Build CLI binary (unchanged)
go build -o sbom-utility .

# Build GUI binary via Make (output: sbom-utility-gui)
make build-gui
```

### Distribution (fyne package)

`fyne package` wraps the binary in a native bundle and injects [`gui/FyneApp.toml`](FyneApp.toml) metadata into the platform manifest (`Info.plist` on macOS, `AppxManifest.xml` on Windows). That manifest is what the OS reads to display the app name in the menu bar, Dock, and taskbar — a raw binary never has one, so the OS falls back to the file name.

Install the Fyne CLI once:

```bash
go install fyne.io/tools/cmd/fyne@latest
```

Then package for each platform. `fyne package` reads `gui/FyneApp.toml` automatically when run from the `gui/` directory or when `./gui` is passed as the target.

#### Adding Fyne to PATH

`go install` places binaries in `$GOPATH/bin` (default `~/go/bin`), which is not on `$PATH` by default on macOS. Add it to your shell profile and reload:

##### bash

```bash
# bash (~/.bash_profile or ~/.bashrc)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bash_profile && source ~/.bash_profile
```

##### zsh

```zsh
# zsh (~/.zshrc) — default shell on macOS Catalina and later
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc && source ~/.zshrc
```

##### verify

Verify with `which fyne` — it should print `~/go/bin/fyne`.

#### macOS — `.app` bundle

```bash
fyne package -os darwin -icon gui/images/icons/BOM-Utility-Icon.png ./gui
# Produces: SBOM Utility.app
# macOS reads Info.plist inside the bundle → menu bar shows "SBOM Utility"
```

#### Windows — `.exe` with embedded icon and manifest

```bash
fyne package -os windows -icon gui/images/icons/BOM-Utility-Icon.png ./gui
# Produces: SBOM Utility.exe  (no runtime DLLs needed)
```

#### Linux — `.tar.xz` with desktop entry

```bash
fyne package -os linux -icon gui/images/icons/BOM-Utility-Icon.png ./gui
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

## App metadata

Application identity is defined in [`gui/FyneApp.toml`](FyneApp.toml).
Fyne reads this file at build time and embeds it into the native bundle (`Info.plist`
on macOS, `AppxManifest.xml` on Windows), which is how the OS derives the name shown
in the app menu, Dock, and taskbar.

| Value | Where to edit |
|-------|---------------|
| Application display name | `[Details] Name` in `gui/FyneApp.toml` |
| Bundle / app ID | `[Details] ID` in `gui/FyneApp.toml` |
| Version string | `[Details] Version` in `gui/FyneApp.toml` — also overridable at link time (see below) |
| Copyright year / holder | `gui/main.go` — inside the `aboutItem` callback |
| Project URL | `gui/main.go` — inside the `aboutItem` callback |

> **Note:** When running as a plain binary (`go run ./gui` / `go build`) macOS still
> shows the binary file name in the menu bar. The `FyneApp.toml` name only takes
> effect inside a packaged `.app` bundle (see [Build → macOS](#macos--packaged-app-bundle) above).

### Injecting the version at build time

```bash
go build -ldflags "-X main.Version=$(git describe --tags --always)" -o sbom-utility-gui ./gui
```

---

## License

The GUI code (`gui/`) is licensed under the **Apache-2.0** license, matching the rest of `sbom-utility`.

The GUI depends on [Fyne](https://github.com/fyne-io/fyne) (BSD-3-Clause) and its transitive dependencies, all of which are permissively licensed (MIT, BSD-3, zlib, Apache-2.0). No GPL or LGPL code is introduced.
