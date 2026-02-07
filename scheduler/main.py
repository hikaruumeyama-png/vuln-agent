"""
定期実行用スクリプト

Cloud Scheduler → Cloud Functions → Agent Engine
の構成で定期的に脆弱性スキャンを実行する場合に使用

Cloud Functionsのエントリーポイントとしてデプロイ
"""

import os
import json
import functions_framework
import vertexai


# 環境変数から設定を取得
PROJECT_ID = os.environ.get("GCP_PROJECT_ID")
LOCATION = os.environ.get("GCP_LOCATION", "asia-northeast1")
AGENT_RESOURCE_NAME = os.environ.get("AGENT_RESOURCE_NAME")  # デプロイ後に設定


@functions_framework.http
def run_vulnerability_scan(request):
    """
    Cloud Schedulerから呼び出される脆弱性スキャン実行関数
    
    HTTP トリガー:
        POST /run_vulnerability_scan
    
    Cloud Scheduler設定例:
        - 頻度: */5 * * * * (5分毎)
        - ターゲット: HTTP
        - URL: Cloud FunctionのURL
        - メソッド: POST
    """
    print(f"Starting vulnerability scan...")
    print(f"Project: {PROJECT_ID}, Location: {LOCATION}")
    print(f"Agent: {AGENT_RESOURCE_NAME}")
    
    if not all([PROJECT_ID, LOCATION, AGENT_RESOURCE_NAME]):
        return json.dumps({
            "status": "error",
            "message": "Missing required environment variables"
        }), 500
    
    try:
        # Vertex AI初期化
        vertexai.init(project=PROJECT_ID, location=LOCATION)
        
        # デプロイ済みエージェントを取得
        client = vertexai.Client(project=PROJECT_ID, location=LOCATION)
        app = client.agent_engines.get(name=AGENT_RESOURCE_NAME)
        
        # スキャン実行プロンプト
        scan_prompt = """
        新しいSIDfmの脆弱性通知メールを確認してください。
        未処理の脆弱性があれば、以下の手順で処理してください：
        1. SBOMと照合して影響を受けるシステムを特定
        2. 優先度を判定
        3. 担当者に通知
        4. メールを既読にマーク
        
        処理結果をサマリーとして報告してください。
        """
        
        # エージェント実行
        results = []

        import asyncio

        async def execute_scan():
            async for event in app.async_stream_query(
                user_id="scheduler",
                message=scan_prompt,
            ):
                if hasattr(event, 'content'):
                    for part in event.content.get('parts', []):
                        if 'text' in part:
                            results.append(part['text'])

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pool.submit(asyncio.run, execute_scan()).result()
        else:
            asyncio.run(execute_scan())
        
        summary = "\n".join(results)
        print(f"Scan completed. Summary: {summary[:500]}")
        
        return json.dumps({
            "status": "success",
            "summary": summary
        }), 200
        
    except Exception as e:
        print(f"Error during scan: {e}")
        return json.dumps({
            "status": "error",
            "message": str(e)
        }), 500


@functions_framework.http
def health_check(request):
    """ヘルスチェック用エンドポイント"""
    return json.dumps({"status": "healthy"}), 200
