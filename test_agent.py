import os
import unittest


class AgentIntegrationTests(unittest.TestCase):
    def test_agent_stream_query_smoke(self):
        run_flag = os.environ.get("RUN_AGENT_INTEGRATION_TEST", "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if not run_flag:
            self.skipTest("Set RUN_AGENT_INTEGRATION_TEST=1 to run integration test.")

        try:
            import vertexai
            from vertexai import agent_engines
        except Exception as exc:
            self.skipTest(f"vertexai is not available: {exc}")

        project_id = (os.environ.get("GCP_PROJECT_ID") or "").strip()
        location = (os.environ.get("GCP_LOCATION") or "asia-northeast1").strip()
        agent_engine_id = (os.environ.get("AGENT_ENGINE_ID") or "").strip()
        if not project_id or not agent_engine_id:
            self.skipTest("GCP_PROJECT_ID and AGENT_ENGINE_ID are required for integration test.")

        vertexai.init(project=project_id, location=location)
        agent = agent_engines.get(
            f"projects/{project_id}/locations/{location}/reasoningEngines/{agent_engine_id}"
        )

        chunks = []
        for event in agent.stream_query(user_id="test-user", message="log4jを検索して"):
            content = event.get("content") if isinstance(event, dict) else None
            parts = (content or {}).get("parts", []) if isinstance(content, dict) else []
            for part in parts:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    chunks.append(part["text"])

        self.assertTrue(chunks, "No text chunks were returned from stream_query.")


if __name__ == "__main__":
    unittest.main()
