from pathlib import Path
import unittest


CLOUDBUILD_PATH = Path("cloudbuild.yaml")


class CloudBuildOptimizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = CLOUDBUILD_PATH.read_text(encoding="utf-8")

    def test_has_new_substitutions(self):
        self.assertIn("_ADK_BUILDER_IMAGE:", self.content)
        self.assertIn("_FORCE_FULL_DEPLOY:", self.content)
        self.assertIn("_CHANGED_FILES:", self.content)

    def test_has_detect_changes_step(self):
        self.assertIn("id: detect-changes", self.content)
        self.assertIn("DEPLOY_AGENT=", self.content)
        self.assertIn("DEPLOY_GATEWAY=", self.content)
        self.assertIn("DEPLOY_SCHEDULER=", self.content)
        self.assertIn("DEPLOY_WEB=", self.content)
        self.assertIn("agent/*)", self.content)
        self.assertIn("live_gateway/*)", self.content)
        self.assertIn("scheduler/*)", self.content)
        self.assertIn("web/*)", self.content)

    def test_agent_step_uses_adk_builder_and_skip_guard(self):
        self.assertIn('- name: "${_ADK_BUILDER_IMAGE}"', self.content)
        self.assertIn('if [ "${DEPLOY_AGENT:-true}" != "true" ]; then', self.content)
        self.assertIn("command -v adk", self.content)

    def test_component_steps_have_skip_guards(self):
        self.assertIn('if [ "${DEPLOY_GATEWAY:-true}" != "true" ]; then', self.content)
        self.assertIn('if [ "${DEPLOY_SCHEDULER:-true}" != "true" ]; then', self.content)
        self.assertIn('if [ "${DEPLOY_WEB:-true}" != "true" ]; then', self.content)


if __name__ == "__main__":
    unittest.main()
