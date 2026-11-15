"""The Scan cannot swap an official Artifact after its authority is issued."""
from types import SimpleNamespace
import unittest

from vulnerabilityanalysis.scan import _official_pin_matches_qualification


class OfficialScanBindingTest(unittest.TestCase):
    def test_v2_artifact_contract_and_both_revisions_must_match_token(self):
        token = SimpleNamespace(contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
            contract_sha256="a" * 64, harness_sha256="b" * 64,
            oss_fuzz_revision="c" * 40, upstream_revision="d" * 40,
            upstream_harness_path="test/fuzz.c")
        pin = {"contract_kind": token.contract_kind,
               "contract_sha256": token.contract_sha256,
               "local_harness_sha256": token.harness_sha256,
               "oss_fuzz": {"revision": token.oss_fuzz_revision},
               "upstream_harness": {"revision": token.upstream_revision,
                                    "path": token.upstream_harness_path}}
        self.assertTrue(_official_pin_matches_qualification(pin, token))
        for key, value in (("contract_sha256", "e" * 64),
                           ("local_harness_sha256", "e" * 64)):
            self.assertFalse(_official_pin_matches_qualification({**pin, key: value}, token))
        changed = {**pin, "upstream_harness": {**pin["upstream_harness"],
                                                "revision": "e" * 40}}
        self.assertFalse(_official_pin_matches_qualification(changed, token))

    def test_v1_pin_remains_distinct_from_v2(self):
        token = SimpleNamespace(contract_kind="OFFICIAL_OSS_FUZZ_HARNESS_V1",
            upstream_revision="a" * 40, upstream_harness_path="projects/demo/fuzz.c",
            harness_sha256="b" * 64)
        pin = {"revision": token.upstream_revision, "path": token.upstream_harness_path,
               "harness_sha256": token.harness_sha256}
        self.assertTrue(_official_pin_matches_qualification(pin, token))
        changed = SimpleNamespace(**{**vars(token), "contract_kind":
            "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2", "contract_sha256": "c" * 64,
            "oss_fuzz_revision": "d" * 40})
        self.assertFalse(_official_pin_matches_qualification(pin, changed))


if __name__ == "__main__":
    unittest.main()
