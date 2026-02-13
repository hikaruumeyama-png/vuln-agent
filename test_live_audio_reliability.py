from pathlib import Path
import unittest


LIVE_GATEWAY_APP = Path("live_gateway/app.py")
LIVE_GATEWAY_API = Path("live_gateway/live_api.py")
WEB_APP = Path("web/app.js")


class LiveAudioReliabilityTests(unittest.TestCase):
    def test_gateway_emits_greeting_failure_status(self):
        source = LIVE_GATEWAY_APP.read_text(encoding="utf-8")
        self.assertIn('"status": "greeting_no_audio"', source)
        self.assertIn('"status": "greeting_error"', source)
        self.assertIn("Greeting TTS failed", source)

    def test_frontend_handles_greeting_fallback_speech(self):
        source = WEB_APP.read_text(encoding="utf-8")
        self.assertIn("function playGreetingFallbackSpeech", source)
        self.assertIn("window.speechSynthesis.speak", source)
        self.assertIn('payload.status === "greeting_no_audio"', source)
        self.assertIn('payload.status === "greeting_error"', source)

    def test_live_api_uses_current_native_audio_model(self):
        source = LIVE_GATEWAY_API.read_text(encoding="utf-8")
        self.assertIn("gemini-2.5-flash-native-audio-preview-12-2025", source)
        self.assertNotIn("gemini-2.0-flash-live-001", source)
        self.assertIn("session.send_client_content(", source)
        self.assertIn("session.send_realtime_input(", source)


if __name__ == "__main__":
    unittest.main()
