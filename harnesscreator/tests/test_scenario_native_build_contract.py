from pathlib import Path
import unittest

from harnesscreator.agents.scenario_harness import ScenarioHarnessGeneratorAgent
from harnesscreator.llm import ScriptedLLM
from harnesscreator.input_transport import (
    classify_external_transport, permits_explicit_socket_trial,
)
from harnesscreator.models import ProjectSpec


class ScenarioNativeBuildContractTest(unittest.TestCase):
    def _configuration(self, *, native: bool) -> dict:
        project = ProjectSpec(
            source_root=Path("/tmp/source"),
            output_root=Path("/tmp/output"),
            build_command=["python", "-m", "harnesscreator.runtime.native_build"]
            if native else ["custom-builder"],
            native_default_build=native,
        )
        agent = ScenarioHarnessGeneratorAgent(
            ScriptedLLM([]), None, project, max_context_turns=1
        )
        return agent._trusted_build_configuration()

    def test_bundled_builder_exposes_provisional_main_alias(self):
        config = self._configuration(native=True)
        contract = config["native_builder_main_contract"]
        self.assertIn("hc_native_original_main", contract)
        self.assertIn("rejects multiple", contract)
        self.assertIn("not proof", contract)

    def test_custom_builder_does_not_claim_main_alias(self):
        self.assertNotIn(
            "native_builder_main_contract", self._configuration(native=False)
        )

    def test_stale_native_flag_does_not_claim_alias_for_custom_builder(self):
        project = ProjectSpec(
            source_root=Path("/tmp/source"),
            output_root=Path("/tmp/output"),
            build_command=["custom-builder"],
            native_default_build=True,
        )
        agent = ScenarioHarnessGeneratorAgent(
            ScriptedLLM([]), None, project, max_context_turns=1
        )
        self.assertNotIn(
            "native_builder_main_contract", agent._trusted_build_configuration()
        )

    def test_mixed_socket_families_allow_only_explicit_runtime_trial(self):
        channel = "AF_INET SOCK_STREAM or AF_UNIX SOCK_STREAM peer payload"
        self.assertEqual(classify_external_transport(channel, "recv"), "unknown")
        self.assertTrue(permits_explicit_socket_trial(channel, "recv", "tcp"))
        self.assertTrue(permits_explicit_socket_trial(channel, "recv", "unix_stream"))
        self.assertFalse(permits_explicit_socket_trial(channel, "recv", "udp"))
        self.assertFalse(permits_explicit_socket_trial(channel, "SSL_read", "tcp"))

    def test_internet_socket_family_and_type_support_source_backed_trials(self):
        self.assertEqual(
            classify_external_transport("AF_INET SOCK_STREAM peer payload", "recv"),
            "unknown",
        )
        self.assertTrue(permits_explicit_socket_trial(
            "AF_INET SOCK_STREAM peer payload", "recv", "tcp"
        ))
        self.assertTrue(permits_explicit_socket_trial(
            "AF_INET SOCK_DGRAM peer payload", "recvfrom", "udp"
        ))
        self.assertFalse(permits_explicit_socket_trial(
            "AF_INET6 SOCK_STREAM peer payload", "recv", "tcp"
        ))


if __name__ == "__main__":
    unittest.main()
