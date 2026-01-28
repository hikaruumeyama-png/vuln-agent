import vertexai
from vertexai import agent_engines

PROJECT_ID = "agenticai-485616"
LOCATION = "asia-northeast1"
AGENT_ENGINE_ID = "2793436833713750016"

vertexai.init(project=PROJECT_ID, location=LOCATION)
agent = agent_engines.get(f"projects/{PROJECT_ID}/locations/{LOCATION}/reasoningEngines/{AGENT_ENGINE_ID}")

for event in agent.stream_query(
    user_id="test-user",
    message="log4jを検索して"
):
    if 'content' in event:
        for part in event['content'].get('parts', []):
            if 'text' in part:
                print(part['text'])
