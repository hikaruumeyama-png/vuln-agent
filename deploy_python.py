"""
Vertex AI Agent Engine デプロイスクリプト

ADK CLI (adk deploy) の代替として、Pythonから直接デプロイする場合に使用
より詳細な制御が必要な場合や、CI/CDパイプラインからの実行に適しています
"""

import os
import sys
import argparse
from pathlib import Path

import vertexai
from vertexai.agent_engines import AdkApp


def deploy_agent(
    project_id: str,
    location: str,
    staging_bucket: str,
    display_name: str,
    env_vars: dict[str, str] = None,
):
    """
    エージェントをVertex AI Agent Engineにデプロイ
    
    Args:
        project_id: GCPプロジェクトID
        location: リージョン (例: asia-northeast1)
        staging_bucket: ステージングバケット (例: gs://bucket-name)
        display_name: エージェントの表示名
        env_vars: 環境変数の辞書
    """
    print(f"Initializing Vertex AI...")
    print(f"  Project: {project_id}")
    print(f"  Location: {location}")
    
    vertexai.init(project=project_id, location=location)
    
    # エージェントをインポート
    print(f"\nLoading agent...")
    sys.path.insert(0, str(Path(__file__).parent))
    from agent.agent import root_agent
    
    # AdkAppでラップ
    print(f"Creating AdkApp...")
    app = AdkApp(agent=root_agent)
    
    # 環境変数の設定
    env_vars = env_vars or {}
    
    # デプロイ
    print(f"\nDeploying to Agent Engine...")
    print(f"  Display Name: {display_name}")
    print(f"  Staging Bucket: {staging_bucket}")
    
    # requirements
    requirements = [
        "google-cloud-aiplatform[agent_engines,adk]>=1.112.0",
        "google-api-python-client>=2.100.0",
        "packaging>=23.0",
    ]
    
    deployed_app = AdkApp.create(
        adk_app=app,
        display_name=display_name,
        staging_bucket=staging_bucket,
        requirements=requirements,
        env_vars=env_vars if env_vars else None,
    )
    
    print(f"\n✅ Deployment successful!")
    print(f"  Resource Name: {deployed_app.resource_name}")
    
    return deployed_app


def test_deployed_agent(resource_name: str, project_id: str, location: str):
    """デプロイされたエージェントをテスト"""
    print(f"\nTesting deployed agent...")
    
    vertexai.init(project=project_id, location=location)
    
    # デプロイされたエージェントを取得
    client = vertexai.Client(project=project_id, location=location)
    app = client.agent_engines.get(name=resource_name)
    
    # テストクエリ
    test_queries = [
        "こんにちは、あなたの機能を教えてください",
        "CVE-2024-0001の影響を調べてください",
    ]
    
    for query in test_queries:
        print(f"\n📝 Query: {query}")
        print("-" * 50)
        
        async def run_query():
            async for event in app.async_stream_query(
                user_id="test-user",
                message=query,
            ):
                if hasattr(event, 'content'):
                    for part in event.content.get('parts', []):
                        if 'text' in part:
                            print(part['text'])
        
        import asyncio
        asyncio.run(run_query())


def main():
    parser = argparse.ArgumentParser(
        description="Deploy Vulnerability Management Agent to Vertex AI Agent Engine"
    )
    
    parser.add_argument(
        "--project", "-p",
        required=True,
        help="GCP Project ID"
    )
    parser.add_argument(
        "--location", "-l",
        default="asia-northeast1",
        help="GCP Region (default: asia-northeast1)"
    )
    parser.add_argument(
        "--staging-bucket", "-b",
        required=True,
        help="GCS staging bucket (e.g., gs://my-bucket)"
    )
    parser.add_argument(
        "--display-name", "-n",
        default="vulnerability-management-agent",
        help="Display name for the agent"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test the deployed agent after deployment"
    )
    
    # 環境変数
    parser.add_argument("--gmail-user", help="Gmail user email for domain delegation")
    parser.add_argument("--sidfm-sender", default="noreply@sidfm.com", help="SIDfm sender email")
    parser.add_argument("--sbom-spreadsheet-id", help="SBOM spreadsheet ID")
    parser.add_argument("--sbom-sheet-name", default="SBOM", help="SBOM sheet name")
    parser.add_argument("--chat-space-id", help="Default Google Chat space ID")
    
    args = parser.parse_args()
    
    # 環境変数を構築
    env_vars = {}
    if args.gmail_user:
        env_vars["GMAIL_USER_EMAIL"] = args.gmail_user
    if args.sidfm_sender:
        env_vars["SIDFM_SENDER_EMAIL"] = args.sidfm_sender
    if args.sbom_spreadsheet_id:
        env_vars["SBOM_SPREADSHEET_ID"] = args.sbom_spreadsheet_id
    if args.sbom_sheet_name:
        env_vars["SBOM_SHEET_NAME"] = args.sbom_sheet_name
    if args.chat_space_id:
        env_vars["DEFAULT_CHAT_SPACE_ID"] = args.chat_space_id
    
    # デプロイ
    deployed_app = deploy_agent(
        project_id=args.project,
        location=args.location,
        staging_bucket=args.staging_bucket,
        display_name=args.display_name,
        env_vars=env_vars,
    )
    
    # テスト
    if args.test:
        test_deployed_agent(
            resource_name=deployed_app.resource_name,
            project_id=args.project,
            location=args.location,
        )


if __name__ == "__main__":
    main()
