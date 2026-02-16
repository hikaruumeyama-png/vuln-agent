# Test Dialog Agent (A2A確認用)

`test_dialog_agent` は、A2A接続確認のための最小エージェントです。

## できること
- `ping`: 稼働確認
- `echo_message`: 受信メッセージのエコー
- `parse_handoff_sections`: `【...】` 形式ハンドオフ文の簡易パース

## デプロイ例
```bash
cd test_dialog_agent
adk deploy agent_engine \
  --project=YOUR_PROJECT_ID \
  --region=asia-northeast1 \
  --display_name=test-dialog-agent .
```

デプロイ後に表示されるリソース名を `REMOTE_AGENT_TEST` または `REMOTE_AGENT_MASTER` に設定してください。

## A2A統合テスト実行
```bash
export RUN_A2A_INTEGRATION_TEST=1
export REMOTE_AGENT_TEST="projects/<PROJECT>/locations/<LOCATION>/reasoningEngines/<AGENT_ID>"
python -m unittest -v test_a2a_integration.py
```

