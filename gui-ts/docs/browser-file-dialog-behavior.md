# Browser File Dialog Behavior — Load BOM Start Directory

> Records confirmed behavior of the "Load BOM" file picker dialog, specifically
> how the start directory is controlled and persisted.  Updated after hands-on
> debugging on the `tsgui-enhance` branch (2025).  Refer to this before making
> further changes in this area.

---

## Background

The GUI runs as a pure browser app backed by a local Go HTTP server (`sbom-utility serve`).
There is no Electron layer.  File-picking is done from JavaScript via one of two paths
depending on which browser is in use:

1. **File System Access API** (`showOpenFilePicker` / `showDirectoryPicker`) —
   Chrome/Edge and Safari 15.2+.  Gives JS control over `startIn`.
2. **`<input type="file">` fallback** — Firefox and any browser where
   `showOpenFilePicker` is absent.  No JS control over start directory.

The relevant source file is [`gui-ts/src/renderer/mockBridge.ts`](../src/renderer/mockBridge.ts).

---

## Key Lessons Learned (Debugging Session)

These were confirmed through hands-on testing and multiple failed attempts.

### 1. `startIn` does NOT accept path strings

`showOpenFilePicker({ startIn: "/Users/matt/Granite" })` — **silently ignored**.
`showOpenFilePicker({ startIn: "Granite" })` — **silently ignored** (not a well-known name).

`startIn` only accepts:
- A `FileSystemHandle` object (file or directory handle obtained from the browser API)
- One of the well-known virtual names: `"documents"`, `"downloads"`, `"desktop"`,
  `"music"`, `"pictures"`, `"videos"`

This is why `preferences.json` storing `defaultBomDirectory: "Granite"` never worked —
`"Granite"` is not a well-known name and is not a `FileSystemHandle`.

### 2. `FileSystemHandle` objects cannot be stored in `localStorage`

They are complex browser objects, not serialisable to JSON strings.
`localStorage` only holds strings — `FileSystemHandle` must be stored in **IndexedDB**.

### 3. `requestPermission()` kills the handle after a page reload

An earlier attempt called `handle.requestPermission({ mode: 'read' })` on the handle
restored from IndexedDB before using it as `startIn`.  This seemed sensible but was
the direct cause of failure:

- After a page reload, `requestPermission()` returns `'prompt'` — not `'granted'`
- The code treated anything other than `'granted'` as invalid and discarded the handle
- Result: `startIn` fell back to `'documents'` → dialog opened at `~/home`

**Fix:** `startIn` is only a *navigation hint* to the browser — it does not require
read permission to the handle.  The `requestPermission()` call was removed entirely.
Chrome uses the handle as a location hint regardless of permission state.

### 4. The user must grant permission once via `showDirectoryPicker`

Chrome shows a one-time prompt: *"Allow this site to view and copy files?"* when
`showDirectoryPicker()` is called.  This happens the first time the user clicks
**Browse…** in Preferences.  After clicking Allow:
- The `FileSystemDirectoryHandle` is stored in IndexedDB
- All subsequent Load BOM dialogs use it as `startIn` — including after page refreshes
- Chrome does not re-prompt on subsequent sessions

### 5. The text input in Preferences was actively misleading

An earlier design had a text `<input>` where users could type a path like
`/Users/matt/Granite`.  This never worked (see point 1 above) but looked like it
should.  It was removed.  **Browse…** is the only control.

---

## Per-Browser Summary

### Chrome / Edge (Chromium-based) ✅ Fully working

| Property | Detail |
|---|---|
| File picker API | `showOpenFilePicker()` |
| `startIn` support | ✅ accepts `FileSystemHandle` |
| Cross-session persistence | ✅ `FileSystemHandle` stored in IndexedDB |
| Setup required | One-time: click **Browse…** in Preferences, grant permission |

**How it works end-to-end:**
1. User clicks **Browse…** in Preferences → `showDirectoryPicker()` opens
2. User selects their BOM folder (e.g. `Granite`) → browser prompts "Allow…" once
3. `FileSystemDirectoryHandle` saved to IndexedDB (`sbom-gui` / `handles` / `lastBomDirectory`)
4. On any subsequent Load BOM click: `loadDirectoryHandle()` reads the handle from IDB,
   passes it as `startIn` to `showOpenFilePicker()` → dialog opens in `Granite`
5. After a successful file pick, the file's `FileSystemFileHandle` also updates the IDB
   entry → dialog stays in the last-used folder even if the user navigated elsewhere

---

### Firefox ✅ Works natively (no JS control needed)

| Property | Detail |
|---|---|
| File picker API | `<input type="file">` fallback (`showOpenFilePicker` not implemented) |
| `startIn` support | ❌ not available from JS |
| Cross-session persistence | ✅ Firefox / OS remembers the last directory natively |
| Setup required | None |

Firefox never enters the `showOpenFilePicker` path.  The OS file dialog remembers
where the user last navigated, entirely outside JS control.  The **Browse…** button
in Preferences calls `showDirectoryPicker` which is also absent in Firefox, so the
button is hidden (guarded by `window.sbomBridge?.pickDirectory`).

**The `defaultBomDirectory` preference has no effect on Firefox.**

---

### Safari (15.2+) ⚠️ In-session only

| Property | Detail |
|---|---|
| File picker API | `showOpenFilePicker()` |
| `startIn` support | ✅ accepts `FileSystemHandle` |
| Cross-session persistence | ❌ Safari cannot store `FileSystemHandle` in IndexedDB |
| Setup required | Per-session: click Browse… each time after a page reload |

Safari supports `showOpenFilePicker` and `startIn` works within a single tab session.
However, storing a `FileSystemHandle` in IndexedDB throws a `DataCloneError` on WebKit.
The `saveDirectoryHandle()` call silently catches this error, so nothing breaks — but
the handle is not persisted.  On every page reload the dialog falls back to `'documents'`.

This is a WebKit limitation, not a code bug.  No JS workaround is available.

**Possible future improvement:** A "re-authorize" prompt on load (like VS Code Web uses)
could ask the user to re-pick the folder each session.  Not currently implemented as
the extra friction outweighs the benefit.

---

## `startIn` Well-Known Names

When no `FileSystemHandle` is available, these strings are valid for `startIn`:

| Value | Maps to |
|---|---|
| `"documents"` | ~/Documents |
| `"downloads"` | ~/Downloads |
| `"desktop"` | ~/Desktop |
| `"music"` | ~/Music |
| `"pictures"` | ~/Pictures |
| `"videos"` | ~/Movies / Videos |

Any other string is silently ignored and the browser opens at its own default (typically `~`).

---

## IndexedDB Storage Details

| Property | Value |
|---|---|
| Database | `sbom-gui` |
| Object store | `handles` |
| Key | `lastBomDirectory` |
| Value | `FileSystemDirectoryHandle` (from Browse…) or `FileSystemFileHandle` (from last pick) |
| Written by | `pickDirectory()` (Browse… button) and every successful `openFile()` pick |
| Read by | `pickFile()` on first call of each browser session (lazy load) |
| Permission call | **None** — `requestPermission()` must NOT be called; `startIn` is a hint only |

---

## Code Location

All logic is in one file:

```
gui-ts/src/renderer/mockBridge.ts
  ├── openHandleDB()           opens the IndexedDB database
  ├── saveDirectoryHandle()    persists a handle to IDB (no-op on Safari)
  ├── loadDirectoryHandle()    restores handle from IDB — NO requestPermission() call
  ├── pickFile()               drives showOpenFilePicker or <input> fallback
  └── mockBridge.pickDirectory Settings Browse… button; saves directory handle to IDB
```

The Preferences UI is in:

```
gui-ts/src/renderer/components/screens/SettingsScreen.tsx
  └── "Default BOM Directory" section — Browse… button only, no text input
```
