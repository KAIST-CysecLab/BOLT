"""Exercise the detector-to-CycloneDX handoff without a source DB or Ghidra."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

import cyclonedx_sbom_gen
import detector


class ComponentProvenanceTest(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.workdir = Path(temporary_directory.name)
        self.meta_dir = self.workdir / "repo_meta"
        self.meta_dir.mkdir()
        patches = mock.patch.multiple(
            detector,
            REPO_META_DIR=str(self.meta_dir),
            OUTPUT_DIR=str(self.workdir / "output"),
        )
        patches.start()
        self.addCleanup(patches.stop)

    def build_bom(self, components_path):
        binary = self.workdir / "sample"
        binary.write_bytes(b"synthetic binary fixture")
        with contextlib.redirect_stdout(io.StringIO()):
            return cyclonedx_sbom_gen.build_bom(
                binary=binary,
                root_name=None,
                root_version=None,
                supplier=None,
                user_components_path=Path(components_path),
                use_autodiscover=False,
            )

    def test_reference_version_provenance_survives_sbom_generation(self):
        (self.meta_dir / "madler@@zlib.txt").write_text(
            "v1.3.1, pkg:generic/zlib@1.3.1, Zlib, library\n"
            "v1.2.8, pkg:generic/zlib@1.2.8, Zlib, library\n",
            encoding="utf-8",
        )
        components_path = detector.write_binary_components_json(
            "sample", [{"name": "madler@@zlib", "matched_pairs": {"f": "f"}}]
        )

        bom = self.build_bom(components_path)

        self.assertEqual(len(bom["components"]), 1)
        component = bom["components"][0]
        self.assertEqual(component["name"], "zlib")
        self.assertEqual(component["version"], "1.3.1")
        self.assertEqual(component["purl"], "pkg:generic/zlib@1.3.1")
        self.assertEqual(component["licenses"], [{"license": {"id": "Zlib"}}])
        self.assertEqual(
            {prop["name"]: prop["value"] for prop in component["properties"]},
            {
                "bolt:binary:version-source": "reference-metadata",
                "bolt:binary:component-id": "madler@@zlib",
                "bolt:binary:reference-ref": "v1.3.1",
            },
        )

    def test_only_numeric_version_prefixes_are_removed(self):
        cases = [
            ("v1.3.1", "1.3.1"),
            ("V.1.3.1", "1.3.1"),
            ("version-1.900.1", "version-1.900.1"),
            ("release-2.0.12", "release-2.0.12"),
            ("master", "master"),
            ("git+abc123", "git+abc123"),
        ]
        for reference_ref, expected in cases:
            with self.subTest(reference_ref=reference_ref):
                purl = f"pkg:generic/example@{expected}"
                (self.meta_dir / "owner@@example.txt").write_text(
                    f"{reference_ref}, {purl}, MIT, library\n", encoding="utf-8"
                )

                metadata = detector.load_component_release_meta("owner@@example")

                self.assertEqual(metadata["version"], expected)
                self.assertEqual(metadata["reference_ref"], reference_ref)
                self.assertEqual(metadata["purl"], purl)

    def test_supplied_identity_and_evidence_survive_sbom_generation(self):
        cpe = "cpe:2.3:a:zlib:zlib:1.2.8:*:*:*:*:*:*:*"
        evidence = {
            "identity": {
                "field": "version",
                "confidence": 1.0,
                "methods": [{"technique": "binary-analysis", "confidence": 1.0}],
            }
        }
        components_path = self.workdir / "supplied.components.json"
        components_path.write_text(
            json.dumps([{"name": "zlib", "version": "1.2.8", "cpe": cpe, "evidence": evidence}]),
            encoding="utf-8",
        )

        component = self.build_bom(components_path)["components"][0]

        self.assertEqual(component["cpe"], cpe)
        self.assertEqual(component["evidence"], evidence)
        # The builder must not assign detector provenance to an independent input.
        self.assertNotIn("properties", component)


if __name__ == "__main__":
    unittest.main()
