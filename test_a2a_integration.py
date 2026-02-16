import os
import unittest


class A2AIntegrationTests(unittest.TestCase):
    def test_call_master_agent_with_real_remote_agent(self):
        run_flag = os.environ.get("RUN_A2A_INTEGRATION_TEST", "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if not run_flag:
            self.skipTest("Set RUN_A2A_INTEGRATION_TEST=1 to run integration test.")

        try:
            from agent.tools.a2a_tools import register_master_agent, call_master_agent
        except Exception as exc:
            self.skipTest(f"a2a_tools import failed: {exc}")

        resource_name = (os.environ.get("REMOTE_AGENT_TEST") or os.environ.get("REMOTE_AGENT_MASTER") or "").strip()
        if not resource_name:
            self.skipTest("Set REMOTE_AGENT_TEST or REMOTE_AGENT_MASTER for integration test.")

        register_result = register_master_agent(resource_name=resource_name, description="A2A integration test agent")
        self.assertEqual(register_result.get("status"), "registered", str(register_result))

        call_result = call_master_agent(
            task_type="A2A接続確認",
            objective="このメッセージが届くか確認したい",
            facts=["送信元は vuln-agent の統合テストです"],
            requested_actions=["受信確認メッセージを返してください"],
            urgency="低",
            user_id="a2a-integration-test",
        )
        self.assertEqual(call_result.get("status"), "success", str(call_result))
        response_text = str(call_result.get("response_text", "")).strip()
        self.assertTrue(
            response_text or call_result.get("response"),
            "Remote agent returned neither response_text nor response payload.",
        )


if __name__ == "__main__":
    unittest.main()

