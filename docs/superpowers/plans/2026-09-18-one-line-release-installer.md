# One-Line Release Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe, reproducible one-line installer that downloads the published Misaka release for the current macOS/Linux architecture, verifies its SHA-256, and installs only the binary.

**Architecture:** Keep the existing archive `install-user.sh` as the local atomic copier. Add a thin network bootstrap script at `scripts/install.sh` that resolves either the latest published release or an explicit `MISAKA_VERSION`, downloads the release manifest and matching archive, verifies the published checksum, then delegates to the archive installer. Network initialization, service installation, Gateway configuration, Relay configuration, and state creation remain separate.

**Tech Stack:** POSIX `sh`, `curl`, `tar`, `uname`, `mktemp`, `shasum`/`sha256sum`, GitHub Releases.

**Spec:** User request for a one-line `curl | sh` installation path before physical dogfooding.

## Global Constraints

- Support only the published macOS/Linux targets currently produced by the Release workflow.
- Do not modify Network, identity, membership, service, Gateway, Relay, or state-layout behavior.
- Do not use `sudo`, write shell startup files, or create `~/.misaka`.
- Verify the release archive with the release-published `.sha256` file before installation.
- Preserve reproducibility with `MISAKA_VERSION=YYYY.M.D`.
- Keep the existing stable destination default `$HOME/.local/bin/misaka` and `MISAKA_INSTALL_DIR` override.
- Do not implement automatic updates or background release checks.

---

### Task 1: Lock down release selection and safety behavior

**Files:**
- Create: `scripts/install.sh`
- Test: command-line shell checks and a pinned published-release installation in a temporary HOME/install directory

**Interfaces:**
- Inputs: `MISAKA_VERSION` (optional), `MISAKA_INSTALL_DIR` (optional), and internal `MISAKA_RELEASE_BASE_URL` override for deterministic local testing.
- Outputs: installed `$MISAKA_INSTALL_DIR/misaka`, version JSON, and next-step guidance; non-zero exit for unsupported OS/architecture, missing tools, malformed manifest, failed download, or checksum mismatch.

- [x] **Step 1: Write the failing executable contract check**

Run before creating the script:

```bash
test -x scripts/install.sh
```

Expected: FAIL because the one-line bootstrap script does not exist yet.

- [x] **Step 2: Implement the minimal POSIX bootstrap**

The script will:

1. Select `darwin/arm64 → aarch64-apple-darwin`, `darwin/x86_64 → x86_64-apple-darwin`, and `linux/x86_64 → x86_64-unknown-linux-gnu`.
2. Select `releases/latest/download` unless `MISAKA_VERSION` is set, in which case select `releases/download/v$MISAKA_VERSION`.
3. Download `release-manifest.json` and extract `version`, target archive name, and SHA-256 without requiring `jq` or Python.
4. Reject a manifest whose version is not a non-zero-padded `YYYY.M.D` value or whose target entry is absent.
5. Download the archive and its `.sha256`, verify with `shasum -a 256 -c` or `sha256sum -c`.
6. Extract into a temporary directory and invoke the existing archive-local `install-user.sh` with the caller’s `MISAKA_INSTALL_DIR`.
7. Run the installed binary’s `version --json`, print the installed path and the fact that configuration is a separate step, then clean temporary files.

- [x] **Step 3: Run the contract check and shell lint**

Run:

```bash
test -x scripts/install.sh
sh -n scripts/install.sh
shellcheck scripts/install.sh
```

Expected: PASS.

- [x] **Step 4: Verify the pinned published-release path**

Run with a temporary destination:

```bash
install_home=$(mktemp -d /tmp/misaka-install-home-XXXXXX)
MISAKA_VERSION=2026.9.18 \
MISAKA_INSTALL_DIR="$install_home/.local/bin" \
sh scripts/install.sh
"$install_home/.local/bin/misaka" version --json
test ! -e "$install_home/.misaka"
```

Expected: the installed binary reports `2026.9.18` and the release Git SHA, and no Misaka state directory exists.

### Task 2: Document the one-line and reproducible install forms

**Files:**
- Modify: `README.md`
- Modify: `docs/deployment-v1.md`
- Modify: `docs/dogfooding-v1.md`

**Interfaces:**
- Latest convenience install:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh | sh
```

- Reproducible pinned install:

```bash
curl -fsSL https://raw.githubusercontent.com/SHIINASAMA/misaka/main/scripts/install.sh \
  | MISAKA_VERSION=2026.9.18 sh
```

- Configuration remains explicit after installation:

```bash
misaka network init
misaka network gateway add "$GATEWAY_URL"
misaka --iroh-relay "$RELAY_URL" service install
```

- [x] **Step 1: Add the latest and pinned commands to the user-facing installation docs**
- [x] **Step 2: State clearly that the installer does not initialize state or services**
- [x] **Step 3: Replace the verbose archive-only first step in the dogfood runbook with the one-line option, while retaining checksum/extract instructions for operators who want manual artifact control**
- [x] **Step 4: Verify documentation references and shell snippets with `rg` and `git diff --check`**

### Task 3: Run the focused and regression validation

**Files:**
- Test: `scripts/install.sh`, release installation path, repository validation commands

- [x] **Step 1: Run focused installer validation**

```bash
sh -n scripts/install.sh
shellcheck scripts/install.sh
MISAKA_VERSION=2026.9.18 MISAKA_INSTALL_DIR="$(mktemp -d /tmp/misaka-install-test-XXXXXX)" sh scripts/install.sh
```

- [x] **Step 2: Run repository checks proportional to the script/docs change**

```bash
git diff --check
cargo fmt --all -- --check
cargo test --workspace
```

- [x] **Step 3: Confirm the working tree contains only the intended installer, docs, and plan changes**

```bash
git status --short
git diff --stat
```
