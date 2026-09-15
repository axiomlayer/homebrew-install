#!/usr/bin/env python3
"""Fail-closed verifier for AxiomLayer's Homebrew installer integration lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable


HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
DEFAULT_MANIFEST = HERE / "homebrew-install-2026-09-14.json"
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REMOTE_USE = re.compile(r"\buses:\s*([^\s#]+)")
REMOTE_SHELL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:/bin/)?(?:ba|z|k)?sh\b|"
    r"(?:/bin/)?(?:ba|z|k)?sh\s+-c\s+[\"']\$\()",
    re.IGNORECASE,
)


class VerificationError(RuntimeError):
    """A fail-closed integration contract violation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(
    *args: str,
    root: Path = REPOSITORY_ROOT,
    text: bool = True,
) -> str | bytes:
    process = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )
    if process.returncode != 0:
        stderr = process.stderr
        stdout = process.stdout
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        detail = str(stderr).strip() or str(stdout).strip()
        raise VerificationError(f"git {' '.join(args)} failed: {detail}")
    return process.stdout.strip() if text else process.stdout


def git_file(revision: str, path: str, root: Path = REPOSITORY_ROOT) -> bytes:
    value = run_git("show", f"{revision}:{path}", root=root, text=False)
    assert isinstance(value, bytes)
    return value


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read manifest {path}: {error}") from error
    require(isinstance(value, dict), "manifest root must be an object")
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    require(
        manifest.get("schema") == "axiomlayer-homebrew-install-integration-v1",
        "unexpected manifest schema",
    )
    authority = manifest.get("authority")
    require(isinstance(authority, dict), "authority must be an object")
    require(authority.get("policy") == "axiomlayer/dotfiles#49", "wrong authority")
    require(
        authority.get("upstreamRepository") == "Homebrew/install",
        "wrong upstream repository",
    )
    require(
        authority.get("forkRepository") == "axiomlayer/homebrew-install",
        "wrong fork repository",
    )
    require(authority.get("version") == "2026-09-14", "wrong version")
    require(
        authority.get("commit") == "8949852f785a3bacaba2a979d0790337950b0a4a",
        "authority commit diverges from dotfiles #49",
    )
    require(
        authority.get("tree") == "cdc43383032ea8b6868e8552cb22de4bcfa43ee6",
        "authority tree is unexpected",
    )

    files = authority.get("files")
    require(isinstance(files, dict), "authority files must be an object")
    require(set(files) == {"install.sh", "uninstall.sh"}, "file set is incomplete")
    for path, spec in files.items():
        require(isinstance(spec, dict), f"{path}: file authority must be an object")
        require(
            HEX_COMMIT.fullmatch(str(spec.get("gitBlob", ""))) is not None,
            f"{path}: git blob must be a full object ID",
        )
        require(
            HEX_SHA256.fullmatch(str(spec.get("sha256", ""))) is not None,
            f"{path}: digest must be SHA-256",
        )
        require(
            isinstance(spec.get("bytes"), int) and spec["bytes"] > 0,
            f"{path}: byte count must be positive",
        )
        expected_url = (
            "https://raw.githubusercontent.com/Homebrew/install/"
            f"{authority['commit']}/{path}"
        )
        require(spec.get("rawUrl") == expected_url, f"{path}: raw URL is not pinned")

    darwin = manifest.get("darwinFallback")
    require(isinstance(darwin, dict), "darwinFallback must be an object")
    require(darwin.get("architecture") == "arm64", "Darwin must be arm64-only")
    require(darwin.get("prefix") == "/opt/homebrew", "wrong Darwin prefix")
    require(darwin.get("minimumMacosVersion") == "15.0", "wrong macOS floor")
    require(
        darwin.get("brewForkRepository") == "AxiomLayer/homebrew",
        "wrong downstream brew fork",
    )
    require(
        darwin.get("brewForkRemote") == "https://github.com/axiomlayer/homebrew",
        "wrong downstream brew remote",
    )
    require(
        darwin.get("requiredOverride") == "HOMEBREW_BREW_GIT_REMOTE",
        "wrong installer override port",
    )
    boundaries = darwin.get("hostBoundaries")
    require(isinstance(boundaries, list) and boundaries, "host boundaries are missing")
    require(
        all(isinstance(path, str) and path.startswith("/") for path in boundaries),
        "host boundaries must be absolute paths",
    )

    policy = manifest.get("workflowPolicy")
    require(isinstance(policy, dict), "workflowPolicy must be an object")
    require(
        policy.get("integrationWorkflow")
        == ".github/workflows/axiomlayer-fleet-integration.yml",
        "wrong integration workflow",
    )
    expected_upstream = {
        ".github/workflows/actionlint.yml",
        ".github/workflows/stale-issues-and-prs.yml",
        ".github/workflows/tests.yml",
    }
    require(
        set(policy.get("upstreamWorkflows", [])) == expected_upstream,
        "upstream workflow inventory changed",
    )
    actions = policy.get("allowedActions")
    require(isinstance(actions, dict) and actions, "allowed actions are missing")
    for action, commit in actions.items():
        require(isinstance(action, str) and "/" in action, "invalid action name")
        require(
            HEX_COMMIT.fullmatch(str(commit)) is not None,
            f"{action}: action pin must be a full commit",
        )


def verify_file_bytes(path: str, data: bytes, spec: dict[str, Any]) -> None:
    require(len(data) == spec["bytes"], f"{path}: byte count mismatch")
    actual = sha256_bytes(data)
    require(actual == spec["sha256"], f"{path}: SHA-256 mismatch: {actual}")


def git_blob_id(revision: str, path: str, root: Path = REPOSITORY_ROOT) -> str:
    output = run_git("ls-tree", revision, "--", path, root=root)
    assert isinstance(output, str)
    fields = output.split()
    require(len(fields) >= 3 and fields[1] == "blob", f"{path}: not a Git blob")
    return fields[2]


def verify_source(
    manifest: dict[str, Any],
    root: Path = REPOSITORY_ROOT,
) -> None:
    validate_manifest(manifest)
    authority = manifest["authority"]
    commit = authority["commit"]
    run_git("cat-file", "-e", f"{commit}^{{commit}}", root=root)
    tree = run_git("show", "-s", "--format=%T", commit, root=root)
    require(tree == authority["tree"], f"authority tree mismatch: {tree}")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    require(
        ancestry.returncode == 0, "working branch is not based on the authority commit"
    )

    for path, spec in authority["files"].items():
        pinned = git_file(commit, path, root=root)
        verify_file_bytes(path, pinned, spec)
        require(
            git_blob_id(commit, path, root=root) == spec["gitBlob"],
            f"{path}: authority Git blob mismatch",
        )
        head = git_file("HEAD", path, root=root)
        require(head == pinned, f"{path}: fork branch changed pinned bootstrap bytes")


def assert_bash_syntax(data: bytes, label: str, *, extglob: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="axiomlayer-homebrew-syntax-") as directory:
        path = Path(directory) / "script.sh"
        path.write_bytes(data)
        command = ["/bin/bash", "-u"]
        if extglob:
            command.extend(["-O", "extglob"])
        command.extend(["-n", str(path)])
        process = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    require(process.returncode == 0, f"{label}: Bash syntax failed: {process.stderr}")


def verify_darwin_contract(
    data: bytes,
    manifest: dict[str, Any],
    label: str = "install.sh",
) -> None:
    validate_manifest(manifest)
    try:
        script = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label}: installer is not UTF-8") from error
    darwin = manifest["darwinFallback"]
    required_fragments = {
        "Bash entrypoint": "#!/bin/bash",
        "strict unset handling": "set -u",
        "Darwin dispatch": "Darwin) HOMEBREW_ON_MACOS=1",
        "native architecture query": 'UNAME_MACHINE="$(/usr/bin/uname -m)"',
        "Apple Silicon refusal": '[[ "${UNAME_MACHINE}" != "arm64" ]]',
        "Apple Silicon error": "Homebrew on macOS is only supported on Apple Silicon processors!",
        "Darwin prefix": f'HOMEBREW_PREFIX="{darwin["prefix"]}"',
        "repository follows prefix": 'HOMEBREW_REPOSITORY="${HOMEBREW_PREFIX}"',
        "macOS floor": f'MACOS_OLDEST_SUPPORTED="{darwin["minimumMacosVersion"]}"',
        "brew remote override": 'HOMEBREW_BREW_GIT_REMOTE="${HOMEBREW_BREW_GIT_REMOTE:-',
        "remote is applied": '"config" "remote.origin.url" "${HOMEBREW_BREW_GIT_REMOTE}"',
        "analytics suppression": "HOMEBREW_NO_ANALYTICS_THIS_RUN=1",
        "noninteractive port": "NONINTERACTIVE",
    }
    for description, fragment in required_fragments.items():
        require(fragment in script, f"{label}: missing {description}")
    require(
        'HOMEBREW_BREW_DEFAULT_GIT_REMOTE="https://github.com/Homebrew/brew"' in script,
        f"{label}: canonical default brew remote changed",
    )
    require(
        REMOTE_SHELL_PIPE.search(script) is None,
        f"{label}: remote content is piped into a shell",
    )
    assert_bash_syntax(data, label)


def workflow_paths_at(revision: str, root: Path = REPOSITORY_ROOT) -> list[str]:
    output = run_git(
        "ls-tree",
        "-r",
        "--name-only",
        revision,
        "--",
        ".github/workflows",
        root=root,
    )
    assert isinstance(output, str)
    return sorted(
        path for path in output.splitlines() if path.endswith((".yml", ".yaml"))
    )


def verify_action_references(
    workflows: Iterable[tuple[str, str]],
    allowed_actions: dict[str, str],
) -> set[str]:
    seen: set[str] = set()
    for path, text in workflows:
        require(
            "pull_request_target:" not in text,
            f"{path}: pull_request_target is forbidden",
        )
        for line_number, line in enumerate(text.splitlines(), 1):
            match = REMOTE_USE.search(line)
            if not match:
                continue
            use = match.group(1)
            if use.startswith("./") or use.startswith("docker://"):
                continue
            require("@" in use, f"{path}:{line_number}: action ref is missing")
            action, reference = use.rsplit("@", 1)
            require(
                HEX_COMMIT.fullmatch(reference) is not None,
                f"{path}:{line_number}: {use} is not pinned to a full commit",
            )
            require(
                action in allowed_actions,
                f"{path}:{line_number}: {action} is not allowed",
            )
            require(
                reference == allowed_actions[action],
                f"{path}:{line_number}: {action} uses an unexpected commit",
            )
            seen.add(action)
    return seen


def workflow_job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    jobs_start = next(
        (index for index, line in enumerate(lines) if line.rstrip() == "jobs:"), None
    )
    require(jobs_start is not None, "workflow has no jobs mapping")
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[jobs_start + 1 :]:
        if line.strip() and not line.startswith((" ", "\t")):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
        if match:
            current = match.group(1)
            blocks[current] = [line]
        elif current is not None:
            blocks[current].append(line)
    require(bool(blocks), "workflow has no jobs")
    return {name: "".join(block) for name, block in blocks.items()}


def verify_workflows(
    manifest: dict[str, Any],
    root: Path = REPOSITORY_ROOT,
) -> None:
    validate_manifest(manifest)
    policy = manifest["workflowPolicy"]
    workflow_dir = root / ".github" / "workflows"
    paths = sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml"))
    require(bool(paths), "repository has no workflows")
    workflows = [
        (str(path.relative_to(root)), path.read_text(encoding="utf-8"))
        for path in paths
    ]
    seen = verify_action_references(workflows, policy["allowedActions"])
    require(
        set(policy["allowedActions"]) <= seen,
        "not every declared action pin is exercised by the current workflows",
    )

    integration_path = policy["integrationWorkflow"]
    expected_paths = set(policy["upstreamWorkflows"]) | {integration_path}
    actual_paths = {path for path, _ in workflows}
    require(actual_paths == expected_paths, "workflow inventory changed without review")

    workflow_text = dict(workflows)
    for path in policy["upstreamWorkflows"]:
        for job, block in workflow_job_blocks(workflow_text[path]).items():
            require(
                "github.repository == 'Homebrew/install'" in block,
                f"{path}:{job}: inherited job is executable in the fork",
            )

    integration = workflow_text[integration_path]
    for job, block in workflow_job_blocks(integration).items():
        require(
            "github.repository == 'axiomlayer/homebrew-install'" in block,
            f"{integration_path}:{job}: integration job lacks an exact fork guard",
        )
    require("secrets." not in integration, "integration workflow references a secret")
    require("GH_TOKEN" not in integration, "integration workflow requests a token")
    require(
        re.search(r"^\s*environment:\s*", integration, re.MULTILINE) is None,
        "integration workflow declares an environment",
    )
    require(
        re.search(
            r"^permissions:\s*\n\s+contents:\s+read\s*$", integration, re.MULTILINE
        )
        is not None,
        "integration workflow must grant only contents:read",
    )
    require(
        re.search(r"\bwrite\b", integration, re.IGNORECASE) is None,
        "integration workflow requests write authority",
    )
    require(
        "curl " not in integration and "wget " not in integration,
        "workflow downloads scripts",
    )
    require(
        "schedule:" in integration and "workflow_dispatch:" in integration,
        "integration workflow is not proactive",
    )


def verify_candidate(
    manifest: dict[str, Any],
    revision: str,
    root: Path = REPOSITORY_ROOT,
) -> None:
    validate_manifest(manifest)
    commit = manifest["authority"]["commit"]
    run_git("cat-file", "-e", f"{revision}^{{commit}}", root=root)
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, revision],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    require(
        ancestry.returncode == 0, "candidate does not descend from the promoted commit"
    )
    install = git_file(revision, "install.sh", root=root)
    uninstall = git_file(revision, "uninstall.sh", root=root)
    verify_darwin_contract(install, manifest, label=f"{revision}:install.sh")
    assert_bash_syntax(uninstall, f"{revision}:uninstall.sh", extglob=True)

    paths = workflow_paths_at(revision, root=root)
    expected = sorted(manifest["workflowPolicy"]["upstreamWorkflows"])
    require(paths == expected, "candidate upstream workflow inventory changed")
    workflows = [
        (path, git_file(revision, path, root=root).decode("utf-8")) for path in paths
    ]
    verify_action_references(workflows, manifest["workflowPolicy"]["allowedActions"])


def host_snapshot(paths: Iterable[str]) -> dict[str, dict[str, Any] | None]:
    snapshot: dict[str, dict[str, Any] | None] = {}
    for value in paths:
        path = Path(value)
        try:
            info = path.lstat()
        except FileNotFoundError:
            snapshot[value] = None
            continue
        snapshot[value] = {
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
            "mtimeNs": info.st_mtime_ns,
            "symlink": os.readlink(path) if path.is_symlink() else None,
        }
    return snapshot


def verified_install_bytes(
    manifest: dict[str, Any],
    root: Path = REPOSITORY_ROOT,
) -> bytes:
    validate_manifest(manifest)
    authority = manifest["authority"]
    data = git_file(authority["commit"], "install.sh", root=root)
    verify_file_bytes("install.sh", data, authority["files"]["install.sh"])
    return data


def atomic_materialize(
    destination: Path,
    data: bytes,
    spec: dict[str, Any],
) -> None:
    verify_file_bytes("install.sh", data, spec)
    require(not destination.exists(), f"refusing to overwrite {destination}")
    require(
        destination.parent.is_dir(),
        f"destination parent does not exist: {destination.parent}",
    )
    temporary = destination.parent / f".{destination.name}.axiomlayer-{os.getpid()}"
    require(not temporary.exists(), f"temporary path already exists: {temporary}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o500)
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    except FileExistsError as error:
        temporary.unlink(missing_ok=True)
        raise VerificationError(f"refusing to overwrite {destination}") from error


def receipt_for(manifest: dict[str, Any], destination: Path) -> dict[str, Any]:
    authority = manifest["authority"]
    spec = authority["files"]["install.sh"]
    return {
        "schema": "axiomlayer-verified-bootstrap-receipt-v1",
        "repository": authority["forkRepository"],
        "upstream": authority["upstreamRepository"],
        "version": authority["version"],
        "commit": authority["commit"],
        "path": "install.sh",
        "sha256": spec["sha256"],
        "bytes": spec["bytes"],
        "destination": str(destination),
        "executed": False,
    }


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    require(not path.exists(), f"refusing to overwrite {path}")
    data = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    spec = {"bytes": len(data), "sha256": sha256_bytes(data)}
    atomic_materialize(path, data, spec)
    path.chmod(0o400)


def download_pinned_install(manifest: dict[str, Any]) -> bytes:
    validate_manifest(manifest)
    spec = manifest["authority"]["files"]["install.sh"]
    url = spec["rawUrl"]
    parsed = urllib.parse.urlparse(url)
    require(
        parsed.scheme == "https" and parsed.hostname == "raw.githubusercontent.com",
        "installer URL must use the pinned GitHub raw endpoint over HTTPS",
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "axiomlayer-integrity-gate/1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.geturl() == url, "installer download redirected")
            data = response.read(spec["bytes"] + 1)
    except OSError as error:
        raise VerificationError(f"installer download failed: {error}") from error
    verify_file_bytes("install.sh", data, spec)
    return data


def materialize(
    manifest: dict[str, Any],
    destination: Path,
    receipt: Path | None,
    download: bool,
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    data = (
        download_pinned_install(manifest)
        if download
        else verified_install_bytes(manifest, root=root)
    )
    atomic_materialize(destination, data, manifest["authority"]["files"]["install.sh"])
    value = receipt_for(manifest, destination)
    if receipt is not None:
        write_receipt(receipt, value)
    return value


def probe_safe_entrypoints(
    manifest: dict[str, Any],
    root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    data = verified_install_bytes(manifest, root=root)
    verify_darwin_contract(data, manifest)
    boundaries = manifest["darwinFallback"]["hostBoundaries"]
    before = host_snapshot(boundaries)
    probes = [
        (["--help"], {}, 0, "Homebrew Installer"),
        (
            [],
            {"CI": "fabricated-ci", "INTERACTIVE": "1"},
            1,
            "Cannot run force-interactive mode in CI.",
        ),
        (
            [],
            {"INTERACTIVE": "1", "NONINTERACTIVE": "1"},
            1,
            "Both `$INTERACTIVE` and `$NONINTERACTIVE` are set",
        ),
        ([], {"POSIXLY_CORRECT": "1"}, 1, "Bash must not run in POSIX mode."),
        (["--axiomlayer-invalid-option"], {}, 1, "Unrecognized option"),
    ]
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="axiomlayer-homebrew-probe-") as directory:
        root_dir = Path(directory)
        installer = root_dir / "install.sh"
        atomic_materialize(
            installer, data, manifest["authority"]["files"]["install.sh"]
        )
        base_env = {
            "HOME": str(root_dir / "home"),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(root_dir),
            "USER": "axiomlayer-fabricated-user",
        }
        (root_dir / "home").mkdir()
        for arguments, additions, expected_code, expected_text in probes:
            environment = {**base_env, **additions}
            process = subprocess.run(
                ["/bin/bash", str(installer), *arguments],
                cwd=root_dir,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            combined = process.stdout + process.stderr
            require(
                process.returncode == expected_code,
                f"safe probe {arguments or additions} returned {process.returncode}",
            )
            require(
                expected_text in combined,
                f"safe probe omitted expected refusal: {expected_text}",
            )
            results.append({"arguments": arguments, "exitCode": process.returncode})
    after = host_snapshot(boundaries)
    require(before == after, "safe entrypoint probes changed a declared host boundary")
    return {"hostBoundariesUnchanged": True, "probes": results}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in (
        "validate",
        "verify-source",
        "verify-workflows",
        "verify-darwin",
        "probe-help",
        "all",
    ):
        subparsers.add_parser(name)
    candidate = subparsers.add_parser("verify-candidate")
    candidate.add_argument("revision")
    for name in ("materialize", "acquire"):
        command = subparsers.add_parser(name)
        command.add_argument("--destination", type=Path, required=True)
        command.add_argument("--receipt", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "validate":
            validate_manifest(manifest)
        elif args.command == "verify-source":
            verify_source(manifest)
        elif args.command == "verify-workflows":
            verify_workflows(manifest)
        elif args.command == "verify-darwin":
            verify_darwin_contract(verified_install_bytes(manifest), manifest)
        elif args.command == "verify-candidate":
            verify_candidate(manifest, args.revision)
        elif args.command == "probe-help":
            print(
                json.dumps(probe_safe_entrypoints(manifest), indent=2, sort_keys=True)
            )
        elif args.command in {"materialize", "acquire"}:
            value = materialize(
                manifest,
                args.destination,
                args.receipt,
                download=args.command == "acquire",
            )
            print(json.dumps(value, indent=2, sort_keys=True))
        elif args.command == "all":
            validate_manifest(manifest)
            verify_source(manifest)
            verify_workflows(manifest)
            verify_darwin_contract(verified_install_bytes(manifest), manifest)
            probe_safe_entrypoints(manifest)
        print(f"ok: {args.command}")
        return 0
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
