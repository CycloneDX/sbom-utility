# GUI TypeScript Browser Packaging Plan

## Goal

Package [`gui-ts`](../gui-ts) for non-developer analysts as a local browser application backed by the existing [`serve`](../cmd/serve.go) command, without relying on Electron packaging.

## Current codebase baseline

- The local HTTP API already exists in [`Serve()`](../cmd/serve.go#L119) and binds to loopback `127.0.0.1`.
- The browser frontend already talks to that API through [`mockBridge.ts`](../gui-ts/src/renderer/mockBridge.ts).
- The current browser flow is still developer-oriented and depends on Vite plus a separate server launcher in [`dev-browser-with-serve.sh`](../gui-ts/scripts/dev-browser-with-serve.sh).
- Browser file open currently uploads the selected file into a temp directory via [`handleServeOpenFile()`](../cmd/serve.go#L151).
- Server-side path handling is currently restricted to temp files by [`resolveServePath()`](../cmd/serve.go#L607), which is appropriate for the current upload/session model but does not yet support a more productized save/export workflow.
- The main analyst editing flow already exists in [`ValidateScreen.tsx`](../gui-ts/src/renderer/components/screens/ValidateScreen.tsx).

## Target product shape

Deliver a non-Electron package that:

1. starts a loopback-only local server
2. serves both the static GUI assets and the existing API from one process
3. opens the default browser automatically
4. supports analyst-friendly open/save flows
5. can later be wrapped either as a native installer or as a container image

At the same time, preserve the current developer workflow based on [`make dev-gui-browser`](../Makefile#L48), [`dev:browser`](../gui-ts/package.json), [`dev:browser:full`](../gui-ts/package.json), and [`dev-browser-with-serve.sh`](../gui-ts/scripts/dev-browser-with-serve.sh). The packaged runtime path must be additive and must not replace the existing Vite-based development path.

## Recommended implementation phases

### Phase 1 — Production static web build

- Add a production build script to [`gui-ts/package.json`](../gui-ts/package.json).
- Produce static assets under a predictable build directory such as `gui-ts/dist`.
- Remove end-user dependence on the Vite dev server for packaged use.

### Phase 2 — Serve static assets from Go

- Extend [`Serve()`](../cmd/serve.go#L119) to optionally serve the built GUI assets in addition to `/api/*` routes.
- Prefer embedding the compiled frontend into the Go binary for simplest deployment; alternatively allow a filesystem asset directory for early iterations.
- Add a root route (`/`) and static asset routes so the browser UI is delivered by the same local process as the API.
- Keep loopback-only binding.

### Phase 3 — Productized launcher flow

- Add a packaged launch mode that starts the local server and opens the user’s default browser automatically.
- Keep the current `serve` mode for development and debugging.
- On startup, prefer a fixed default port and fall back only if it is unavailable.
- Detect an existing running instance and open the browser to it instead of failing when possible.

### Phase 4 — Analyst-friendly file workflow

- Preserve the current upload-to-session open behavior from [`handleServeOpenFile()`](../cmd/serve.go#L151) for simplicity and cross-platform reliability.
- Treat opened BOMs as working copies, not implicit in-place edits of the source document.
- Keep `Save As…` as the default edit persistence action in [`ValidateScreen.tsx`](../gui-ts/src/renderer/components/screens/ValidateScreen.tsx#L54).
- Add explicit support for writing saved files to a permitted non-temp destination chosen by the user, because current path enforcement in [`resolveServePath()`](../cmd/serve.go#L607) only allows temp paths.
- Make overwrite of the original BOM explicit and confirm it before writing.
- Hide temp/session implementation details from the UI; continue showing analyst-facing display names.

### Phase 5 — Packaging and adoption polish

- Provide a simple native wrapper per platform (installer, app bundle, or signed binary package) that launches the browser-hosted local app without exposing Node/npm.
- Provide a container edition that mounts a host workspace and launches the same browser UI for ephemeral review workflows.
- Add user-facing documentation focused on launch/open/save and local-only operation, not developer setup.

## UX rules

- Launch must feel like opening an application, not starting a server.
- The browser should open automatically; users should not type localhost URLs.
- The app must clearly show the loaded BOM name, spec version, and validation state.
- Unsaved edits must be visible and protected before loading another BOM.
- Default save action should create an explicit saved copy unless the user intentionally chooses overwrite.
- File contents and analysis should remain local to the workstation/container session.
- The packaged runtime path must not regress the developer workflow provided by [`make dev-gui-browser`](../Makefile#L48).

## Key technical gaps in the current codebase

1. No production frontend build/distribution path is defined in [`gui-ts/package.json`](../gui-ts/package.json).
2. [`Serve()`](../cmd/serve.go#L119) exposes only API routes and does not serve the GUI itself.
3. [`resolveServePath()`](../cmd/serve.go#L607) currently blocks saving outside temp space, which is too restrictive for packaged analyst workflows.
4. No browser auto-open or single-launch product mode exists in the Go binary.
5. The current bridge in [`mockBridge.ts`](../gui-ts/src/renderer/mockBridge.ts#L8) assumes a dev-style fixed API base and should be aligned with packaged local serving.

## Execution-ready checklist

### Phase 1 — Production frontend build

- [ ] Add a production build script to [`gui-ts/package.json`](../gui-ts/package.json).
- [ ] Confirm the build emits static assets to [`gui-ts/dist/`](../gui-ts/dist/).
- [ ] Ensure the built frontend does not depend on the Vite dev server.
- [ ] Validate the frontend build locally with package checks:
  - [ ] run `npm run typecheck` in [`gui-ts`](../gui-ts)
  - [ ] run `npm run lint` in [`gui-ts`](../gui-ts)
  - [ ] run the new production build command in [`gui-ts/package.json`](../gui-ts/package.json)

### Phase 2 — Serve the GUI from Go

- [ ] Add static asset serving to [`Serve()`](../cmd/serve.go#L119) alongside existing `/api/*` routes.
- [ ] Decide whether the first implementation embeds assets or serves them from [`gui-ts/dist/`](../gui-ts/dist/).
- [ ] Add handling for `/` and static asset paths so the browser UI loads from the Go process.
- [ ] Keep loopback-only binding in [`Serve()`](../cmd/serve.go#L119).
- [ ] Ensure this static-serving path is enabled only for packaged/runtime use and does not replace the current Vite development path.
- [ ] Validate that the frontend loads correctly when served by the Go process.
- [ ] Confirm [`make dev-gui-browser`](../Makefile#L48) still works unchanged after the server changes.
- [ ] Add or update Go tests for static asset serving behavior.

### Phase 3 — Productized launch mode

- [ ] Add a packaged launch mode in Go that starts the local server and opens the default browser.
- [ ] Keep [`serve`](../cmd/serve.go#L106) available for development/debugging.
- [ ] Keep [`dev:browser`](../gui-ts/package.json), [`dev:browser:full`](../gui-ts/package.json), and [`dev-browser-with-serve.sh`](../gui-ts/scripts/dev-browser-with-serve.sh) intact for developer use.
- [ ] Prefer the existing default port first; fall back only if needed.
- [ ] Detect an already running local instance and open the browser to it when practical.
- [ ] Validate startup behavior on macOS and at least one managed target environment.
- [ ] Validate shutdown/relaunch behavior so users are not left with confusing background processes.

### Phase 4 — Analyst-friendly open/save workflow

- [ ] Preserve upload-on-open behavior from [`handleServeOpenFile()`](../cmd/serve.go#L151).
- [ ] Keep analyst-visible display names separate from internal working-copy paths in [`AppContext.tsx`](../gui-ts/src/renderer/context/AppContext.tsx#L30).
- [ ] Keep `Save As…` as the default persistence action in [`ValidateScreen.tsx`](../gui-ts/src/renderer/components/screens/ValidateScreen.tsx#L54).
- [ ] Extend server-side save handling so analyst-chosen non-temp destinations are supported safely; current enforcement in [`resolveServePath()`](../cmd/serve.go#L607) is too restrictive.
- [ ] Preserve explicit overwrite confirmation in [`ValidateScreen.tsx`](../gui-ts/src/renderer/components/screens/ValidateScreen.tsx#L246).
- [ ] Verify file open/save behavior in the packaged browser-served flow:
  - [ ] open a BOM
  - [ ] edit JSON
  - [ ] save as a new file
  - [ ] overwrite only after explicit confirmation
  - [ ] reload the saved BOM successfully

### Phase 5 — Packaging and rollout polish

- [ ] Add packaging docs for non-developer users, separate from the dev workflow in [`gui-ts/README.md`](../gui-ts/README.md).
- [ ] Define the first supported analyst distribution format:
  - [ ] native signed binary/bundle wrapper
  - [ ] container edition
- [ ] For the container edition, define mounted workspace behavior for input/output persistence.
- [ ] Document local-only security posture and expected workstation behavior.
- [ ] Validate the full analyst flow on a managed corporate laptop profile.

## Suggested validation after implementation

- Go tests for new server/static-file and save-path logic
- Typecheck and lint for [`gui-ts`](../gui-ts)
- Developer workflow regression check:
  - [`make dev-gui-browser`](../Makefile#L48) still starts the Vite-based development flow
  - [`dev:browser`](../gui-ts/package.json) and [`dev:browser:full`](../gui-ts/package.json) still work
- Manual validation on a managed corporate laptop profile for:
  - launch flow
  - open BOM
  - auto-validation
  - save edited BOM as new file
  - overwrite confirmation
  - clean shutdown/relaunch

## Rough effort and token cost estimate

### Engineering effort estimate

- Phase 1–2: 1–2 engineer days
- Phase 3: 1 engineer day
- Phase 4: 1–2 engineer days
- Phase 5 polish/docs/container wrapper: 1–2 engineer days

Total rough estimate: **4–7 engineer days** for a solid first packaged version using the current codebase.

### AI token cost estimate

For implementation support against the current codebase, a reasonable estimate is:

- discovery/planning: **15k–30k tokens**
- implementation across Go + TypeScript packaging changes: **40k–90k tokens**
- validation/fixes/documentation follow-up: **15k–40k tokens**

Total likely range: **70k–160k tokens** across the full effort, depending on how many review/iteration cycles are needed.

If the work is done in one focused implementation pass with limited redesign, expect the practical total to land near the middle of that range.