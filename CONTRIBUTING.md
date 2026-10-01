# Contributing to sbom-utility

Contributions are welcome under the [Apache 2.0 license](LICENSE).

This document covers how to contribute to `sbom-utility` and what a
contribution needs to satisfy before it can be merged. It builds on the
[CycloneDX contribution guidelines](https://github.com/CycloneDX/.github/blob/master/CONTRIBUTING.md),
which apply to every CycloneDX repository, and adds what is specific to this
one. For what the utility does and how to use it, see the [README](README.md).

Everyone taking part is expected to follow the
[CycloneDX Code of Conduct](https://github.com/CycloneDX/.github/blob/master/CODE_OF_CONDUCT.md).

## Ways to contribute

- **Ask a question** — please ask on Stack Overflow rather than opening an
  issue. A well-worded question becomes a resource for others searching later.
- **Report a bug or request a feature** — open an
  [issue](https://github.com/CycloneDX/sbom-utility/issues). Search existing
  issues first; if yours already exists, add to it rather than opening a new
  one. File one bug or one feature request per issue.
- **Report a security vulnerability** — do **not** open an issue. Follow
  [SECURITY.md](SECURITY.md).
- **Pick up existing work** — the
  [Priority features](README.md#priority-features) list in the README describes
  the areas where help is most wanted.
- **Work through a `TODO`** — the codebase is tagged with `TODO` comments
  describing improvements conceived while authoring the base functionality.
  Most have no open issue. Search for them and open one:

  ```bash
  grep -rn "TODO" --include="*.go" .
  ```

## Before you start

For anything beyond a trivial fix, **open an issue first** (or comment on an
existing one) describing what you intend to change. This avoids duplicated
effort and lets maintainers flag design concerns before you write code.

A draft pull request is a good way to share work in progress and get early
feedback.

## Development setup

**Prerequisites**

- Go **1.26 or later** — the minimum declared in [`go.mod`](go.mod). See
  https://go.dev/doc/install.
- A `git` client — see https://git-scm.com/downloads.
- A C compiler — needed for the optional desktop GUI in `gui/`, which uses
  CGo. It is also needed for `make test`, since that target runs the tests
  for every package including `gui/`. On macOS, the Xcode command line tools
  provide one (`xcode-select --install`).

**Fork, clone and build**

```bash
gh repo fork CycloneDX/sbom-utility --clone
cd sbom-utility
make build
```

`make build` produces a `sbom-utility` binary for your local `GOOS`/`GOARCH`.
You can also run directly from source without building:

```bash
go run main.go validate -i test/cyclonedx/1.4/cdx-1-4-mature-example-1.json
```

See [Development](README.md#development) in the README for debugging setup and
guidance on adding new BOM formats, schema versions and variants.

## Making a change

1. Create a branch off `main` in your fork.
2. Make your change, adding or updating tests as described below.
3. Run the checks in the next section until they pass.
4. Commit with a sign-off (see [Commits](#commits)).
5. Open a pull request against `main`, describing what changed and why, and
   linking the issue it addresses.
6. Respond to review comments. A maintainer merges once CI is green and the
   change is approved.

Pull requests that do not merge cleanly with the tip of `main` will be
declined; you will be asked to rebase or merge `main` and update the pull
request.

## Requirements for acceptable contributions

A contribution is ready to merge when all of the following hold.

**Formatting.** Code is formatted with `gofmt`:

```bash
make format
```

**Style.** Follow standard Go conventions for whitespace, indentation and
naming. Where existing code differs from language convention, consistency with
the surrounding code is preferred.

**Linting.** `golangci-lint` reports no findings for the packages CI checks.
The project's configuration is in [`.golangci.yaml`](.golangci.yaml). To run
exactly what CI runs:

```bash
golangci-lint run -D errcheck . ./cmd/... ./common/... ./log/... ./resources/... ./schema/... ./utils/...
```

`make golangci_lint` runs the linter more broadly — every package, with
`errcheck` enabled — so it may report findings in existing code that CI does
not enforce. Please don't introduce new ones in the code you touch.

Install the linter first if you do not have it:
https://golangci-lint.run/welcome/install/

**Tests.** The suite passes:

```bash
make test
```

`make test` runs `go test ./...`, which includes the `gui/` package and so
needs a C compiler (see [Development setup](#development-setup)). Faster,
package-scoped alternatives, which also run without a C compiler:

```bash
make test_cmd      # cmd and schema packages — the same packages CI tests
make test_schema   # schema package only
```

See [Testing](README.md#testing) in the README for how test files are
organised, how the working directory is handled, and how to run an individual
test.

**Tests for new functionality.** New functionality should come with tests
added to the existing test suite. Bug fixes should come with a test that fails
without the fix. Test BOM fixtures live under `test/`, grouped by format and
schema version.

**Dependencies.** Avoid adding a dependency when the functionality is trivial
to implement directly or is available in the Go standard library.

**License headers.** New Go source files carry the same Apache 2.0 header as
existing files — copy the header from [`main.go`](main.go).

**Scope.** Keep a pull request to one logical change, and avoid unrelated
whitespace changes — they add noise and make review harder. Unrelated fixes are
easier to review, and to revert, as separate pull requests.

## Commits

**Every commit must be signed off** to certify agreement with the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/). A
sign-off is a line at the end of the commit message:

```text
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it automatically, using the name and email from your git
configuration.

Commit messages should follow these rules:

- Separate the subject from the body with a blank line.
- Limit the subject line to 50 characters.
- Capitalise the subject line, and do not end it with a period.
- Use the imperative mood in the subject line ("Add", not "Added").
- Wrap the body at 72 characters.
- Use the body to explain what changed and why, rather than how.

[How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/) is
a good guide.

## Continuous integration

Two workflows run on every pull request targeting `main`:

- **[Go](.github/workflows/go.yml)** — builds all non-GUI packages, then runs
  `go test` against the `schema` and `cmd` packages.
- **[golangci-lint](.github/workflows/golangci-lint.yml)** — lints the non-GUI
  packages with the `errcheck` linter disabled. The `gui/` package is excluded
  because it requires X11/OpenGL, which headless runners do not provide.

Three further checks run on every pull request across CycloneDX repositories:

- **DCO** — fails if any commit lacks a `Signed-off-by:` line. To fix it, add
  the sign-off and force-push: `git commit --amend --no-edit -s` for the latest
  commit, or `git rebase --signoff main` for several, then
  `git push --force-with-lease`.
- **Codacy Static Code Analysis** — code quality and static analysis.
- **GitGuardian Security Checks** — scans for committed secrets.

Pull requests from first-time contributors may need a maintainer to approve
the workflow runs before the Go and golangci-lint checks start.

CI runs a narrower set of tests than `make test` does locally, so a green CI
run is necessary but not sufficient — please run the suite before opening a
pull request.

## Reporting bugs

Open an [issue](https://github.com/CycloneDX/sbom-utility/issues), one bug per
issue, including:

- The version you are running (`sbom-utility version`), and your operating
  system and its version.
- The exact command you ran and its output, including any exit code.
- A BOM that reproduces the problem, reduced to the smallest example that still
  does, with anything confidential removed.
- What you expected to happen, versus what happened.
- Any relevant screenshots or other output.

All issues and responses are kept in the public issue tracker, so they remain
searchable for others who hit the same problem.
