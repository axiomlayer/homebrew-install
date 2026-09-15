# AxiomLayer Homebrew installer integration

This directory is the fail-closed boundary between the upstream Homebrew
installer and AxiomLayer's Darwin GUI/application fallback layer. The authority
is `axiomlayer/dotfiles#49`: version `2026-09-14`, commit
`8949852f785a3bacaba2a979d0790337950b0a4a`.

The fork does not reinterpret that pin. It proves the exact `install.sh` and
`uninstall.sh` bytes, their Git objects, their source tree, Bash syntax, the
Apple-Silicon-only `/opt/homebrew` contract, and the
`HOMEBREW_BREW_GIT_REMOTE` adapter used to point installation at the separately
promoted `AxiomLayer/homebrew` fork.

## Safe acquisition

Never pipe a network response into a shell. Materialize from the already checked
out authority commit:

```bash
tmp_dir="$(mktemp -d)"
python3 integration/axiomlayer/verify.py materialize \
  --destination "${tmp_dir}/install.sh" \
  --receipt "${tmp_dir}/receipt.json"
```

Or acquire the exact raw URL into a file and verify its SHA-256 before it becomes
executable:

```bash
tmp_dir="$(mktemp -d)"
python3 integration/axiomlayer/verify.py acquire \
  --destination "${tmp_dir}/install.sh" \
  --receipt "${tmp_dir}/receipt.json"
```

Neither command executes the installer. Both refuse an existing destination,
and both emit a receipt that contains no environment values or credentials.
The fleet's Darwin adapter remains responsible for consent, setting
`HOMEBREW_BREW_GIT_REMOTE=https://github.com/axiomlayer/homebrew`, and invoking
the verified local file only after the separate Homebrew/brew promotion gate has
passed.

## Automation boundary

Every inherited upstream job has an exact `Homebrew/install` repository guard,
so it is inert in AxiomLayer. The AxiomLayer integration workflow has read-only
contents permission, no environments, no secrets, no publisher path, and only
full-SHA action references. Its scheduled canary fetches upstream Git history,
parses—but never executes—the candidate installer, and refuses workflow
inventory or contract drift.

Repository Actions are disabled when the fork is created. After this integration
workflow reaches protected `main`, repository administrators may enable only
`.github/workflows/axiomlayer-fleet-integration.yml`; the source guards remain
defense in depth.

## Local verification

```bash
python3 integration/axiomlayer/verify.py all
python3 -m unittest -v integration/axiomlayer/test_verify.py
```

The safe-entrypoint probe executes only authority-verified bytes and only paths
that terminate before host detection or mutation (`--help` and fail-fast input
guards). It snapshots `/opt/homebrew`, the paths.d entry, Command Line Tools,
and Apple's CLT placeholder before and after.

## Physical macOS acceptance still required

Hosted and local non-mutating checks cannot prove administrator consent, Command
Line Tools installation, a real `/opt/homebrew` convergence, GUI cask behavior,
reboot/resume behavior, or application launch on Margay. Those remain explicit
host acceptance gates after both installer and Homebrew/brew promotions merge.
