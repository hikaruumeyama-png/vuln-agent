# マルチエージェントアーキテクチャ V2 設計書

> 作成日: 2026-03-03
> ステータス: レビュー済み・承認待ち
> 対象: 脆弱性対応エージェント → 課統合マスターエージェント → 全社展開

---

## 1. エグゼクティブサマリー

### 現行アーキテクチャからの主要変更点

| 項目 | 現行 (V1) | 新設計 (V2) |
|------|-----------|-------------|
| **実行基盤** | Vertex AI Agent Engine (マネージド) | **Cloud Run + ADK (セルフホスト)** |
| **エージェント数** | 1 (+ 5つの未稼働リモート定義) | **3 (Master / Vuln / Builder)** |
| **モデル** | Gemini 2.5 Pro/Flash (スコアベースルーティング) | **Gemini Flash + Claude Sonnet/Opus (エージェント単位固定)** |
| **A2A** | カスタム REST (886行の独自実装) | **A2A v0.3 正式プロトコル (段階移行)** |
| **ツール接続** | 直接API呼び出し | **MCP Protocol 標準化** |
| **リポジトリ** | モノレポ | **モノレポ維持 (構造変更)** |

### 変更の根拠

1. **Agent Engine の制約**: インスタンス上限10、MCP write不安定、セッション課金、ブラックボックス
2. **品質優先**: Claude Sonnet/Opus の日本語品質・コード生成精度を活用
3. **スケール**: エージェント動的生成にはAgent Engineのプロビジョニングが制約になる
4. **標準化**: A2A/ACP がLinux Foundation下で統合。業界標準に乗る

---

## 2. 業務要件（事実のみ）

### 確定している業務フロー

```
SIDfm 脆弱性通知メール
    → SBOM 突合 (BigQuery / Sheets)
    → 影響分析 (CVSS / exploit 状況)
    → 担当者特定 (owner mapping)
    → Google Chat 通知 (カード形式)
```

### 確定しているエージェント要件

| # | エージェント | 根拠 |
|---|---|---|
| 1 | **Vuln Agent** | 上記業務フローを実行する唯一の確定業務 |
| 2 | **Master Agent** | 将来構想: 人間とのフロント、課統合 |
| 3 | **Agent Builder** | 他業務は都度作る戦略の実現手段 |

### 明示的に作らないもの

- Jira Agent (不要と確認済み)
- Approval Agent (未稼働、必要になればBuilder/Claude Codeで作成)
- Patch Agent (同上)
- Report Agent (同上)

---

## 3. アーキテクチャ設計

### 3.1 全体構成図

```
                    ┌──────────────────────────────┐
                    │      Human Interface         │
                    │                              │
                    │  Google Chat  Web UI  Voice   │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │       Master Agent           │
                    │       Cloud Run              │
                    │       Gemini 2.5 Flash       │
                    │                              │
                    │  ・インテント分類             │
                    │  ・AgentCard参照→A2Aルーティング│
                    │  ・セッション管理 (Firestore) │
                    │  ・グレースフルデグラデーション │
                    └───────┬──────────┬───────────┘
                            │          │
                    A2A Protocol    A2A Protocol
                            │          │
              ┌─────────────▼──┐  ┌────▼──────────────┐
              │  Vuln Agent    │  │  Agent Builder     │
              │  Cloud Run     │  │  Cloud Run         │
              │  Claude        │  │  Claude            │
              │  Sonnet 4.6    │  │  Opus 4.5          │
              │  (via Vertex)  │  │  (via Vertex)      │
              │                │  │                    │
              │  通知→突合→    │  │  ヒアリング→       │
              │  分析→Chat通知 │  │  Agent生成→        │
              │                │  │  デプロイ→A2A登録  │
              └──────┬─────────┘  └──────┬─────────────┘
                     │                   │
                     │  MCP Protocol     │ 動的生成
                     │                   │
              ┌──────▼─────────┐  ┌──────▼─────────────┐
              │  MCP Servers   │  │  Generated Agents   │
              │  BigQuery      │  │  (JSON/YAML定義)    │
              │  Sheets        │  │  Cloud Run動的起動   │
              │  NVD/OSV       │  │  Master自動登録      │
              │  Chat          │  └────────────────────┘
              └────────────────┘
```

### 3.2 モデル配置

| エージェント | モデル | 選定理由 | 月額概算 |
|---|---|---|---|
| Master Agent | **Gemini 2.5 Flash** | ルーティングのみ。$0.15/1M入力。レイテンシ最優先 | ~$1 |
| Vuln Agent | **Claude Sonnet 4.6** (Vertex AI) | 脆弱性分析の推論精度・日本語自然さ。Nejumiベンチ上位 | ~$24 |
| Agent Builder | **Claude Opus 4.5** (Vertex AI) | コード生成精度 (SWE-bench 80.9%)。ADK agent.py自動生成に最高品質が必要 | ~$8 |
| 構造化JSON抽出 (shared/) | **Gemini 2.5 Flash** | 現行維持。コスト最適 | ~$1 |
| 音声 (Live Gateway) | **Gemini 2.5 Flash Native Audio** | 現行維持 | ~$1 |
| **LLM合計** | | | **~$35/月** |
| Cloud Run (3サービス) | | min-instances=0, 従量課金 | ~$20-40/月 |
| **総合計** | | | **~$55-75/月** |

**スコアベースモデルルーティングは廃止**。各エージェントが責務に最適なモデルを固定利用。

### 3.3 ADK コード構造

**Master Agent:**

```python
# agents/master_agent/agent.py
from google.adk import Agent
from google.adk.models import Gemini

master_agent = Agent(
    name="master_agent",
    model=Gemini(model="gemini-2.5-flash"),
    instruction=MASTER_INSTRUCTION,
    tools=[route_to_agent, list_available_agents, get_session_context],
)
```

**Vuln Agent:**

```python
# agents/vuln_agent/agent.py
from google.adk import Agent
from google.adk.models import LiteLlm

vuln_agent = Agent(
    name="vulnerability_management_agent",
    model=LiteLlm(model="vertex_ai/claude-sonnet-4-6"),
    instruction=VULN_INSTRUCTION,
    tools=[search_sbom, send_alert, search_history, ...],
    before_tool_callback=[validate_a2a_request, ...],
)
```

**Agent Builder:**

```python
# agents/builder_agent/agent.py
from google.adk import Agent
from google.adk.models import LiteLlm

builder_agent = Agent(
    name="agent_builder",
    model=LiteLlm(model="vertex_ai/claude-opus-4-5"),
    instruction=BUILDER_INSTRUCTION,
    tools=[generate_agent_code, deploy_to_cloud_run, register_agent_card],
)
```

### 3.4 プロトコル設計

```
プロトコル使い分け:

  A2A Protocol ─── エージェント ↔ エージェント (水平通信)
  MCP Protocol ─── エージェント → ツール/データ   (垂直接続)

  Master ──A2A──→ Vuln Agent
  Master ──A2A──→ Agent Builder
  Master ──A2A──→ Generated Agents (動的)

  Vuln Agent ──MCP──→ BigQuery MCP Server
  Vuln Agent ──MCP──→ Sheets MCP Server
  Vuln Agent ──MCP──→ NVD/OSV MCP Server
  Vuln Agent ──MCP──→ Chat MCP Server
```

**A2A移行戦略**: 現行カスタムRESTをアダプターパターンで抽象化し、A2A v0.3バックエンドを差し替え可能にする。

```python
# shared/a2a_adapter.py
class A2AAdapter(Protocol):
    async def call(self, agent_id: str, message: str) -> str: ...
    async def discover(self) -> list[AgentCard]: ...

class LegacyRestAdapter(A2AAdapter):
    """現行の ReasoningEngine REST 呼び出し"""
    ...

class A2AProtocolAdapter(A2AAdapter):
    """Google A2A v0.3 正式プロトコル"""
    ...
```

### 3.5 AI vs コード境界設計

**原則**: 「入力が同じなら出力が毎回同じか？」 — Yesならコード、NoならAI。

#### Vuln Agent の境界

**確定的パイプライン（コード）— LLM呼び出し0回:**

```
SIDfm通知テキスト受信
  → 1. テキスト解析          正規表現 (shared/ticket_parsers.py)
       CVE-ID、CVSS、製品名抽出
  → 2. SBOM突合              BigQueryクエリ (shared/sbom_lookup.py)
       影響システム特定
  → 3. 担当者マッピング      テーブルルックアップ
       owner_email, owner_name
  → 4. 期限計算              DEADLINE_RULES (コード)
       CVSS × resource_type × exploit → 営業日数
  → 5. Chat通知送信          テンプレート埋め込み
       カード形式、固定フォーマット
  → 6. 履歴記録              BigQuery INSERT

  目標: 5秒以内、毎回同じ結果、完全に監査可能
```

**AI処理（LLM）— 人間の対話が入る場合のみ:**

```
「CVE-2024-1234の影響範囲を詳しく教えて」
「この脆弱性は放置しても大丈夫？」
「先月対応した類似の脆弱性は？」

  → 曖昧な質問の意図解釈
  → 複数ソースの情報を統合した分析
  → 自然言語での説明・推奨
  → 過去履歴を踏まえた文脈理解
```

#### Master Agent の境界

**確定的処理（コード）— ルーティングの90%:**

```
1. インテント分類
   ├─ SIDfm通知パターン検出    正規表現 (CVE-XXXX, CVSS等)
   │   → Vuln Agent に A2A 直接委任
   ├─ "エージェントを作って"    キーワードマッチ
   │   → Builder Agent に A2A 直接委任
   └─ 既知コマンド ("/status")  完全一致
       → 定型レスポンス返却

2. AgentCard参照               レジストリ検索
3. A2Aメッセージ送信           プロトコル処理
4. セッション管理              Firestore CRUD
```

**AI処理（LLM）— 上記で判定できない場合のみ:**

```
「最近セキュリティで気になることある？」
「来月の監査に向けて準備しておくことは？」
  → どのエージェントに委任すべきか判断できない
  → AI がインテントを解釈して適切な委任先を決定
  → 該当エージェントがなければ自分で回答
```

#### Agent Builder の境界

**AI処理（前半）:**

```
1. 業務要件ヒアリング          対話で要件を引き出す
2. エージェント設計            ツール構成を決定
3. コード生成                  agent.py, tools/
4. テスト生成                  テストコード
```

**確定的処理（後半）:**

```
5. Sandbox実行                 コンテナで動作確認
6. Cloud Runデプロイ           adk deploy cloud_run
7. AgentCard登録               レジストリINSERT
8. 管理者承認ゲート            承認フロー
```

#### AI比率サマリー

| エージェント × モード | AI | コード | LLM呼び出し |
|---|---|---|---|
| Vuln 定型フロー (SIDfm通知) | 0% | 100% | **0回** |
| Vuln 対話フロー (人の質問) | 70% | 30% | 1-3回 |
| Master ルーティング (既知パターン) | 0% | 100% | **0回** |
| Master ルーティング (曖昧質問) | 50% | 50% | 1回 |
| Builder | 80% | 20% | 3-10回 |

---

### 3.6 エラーハンドリング戦略

**原則**: LLM障害時に品質を落として回答するより、**正直に止まる**方が安全。

#### フォールバックチェーン

```
Vuln Agent 障害:
  Master → 「脆弱性分析サービスが一時的に利用できません。
             10分後に再度お試しください。
             緊急の場合は https://nvd.nist.gov で直接検索できます。」

Builder Agent 障害:
  Master → 「エージェント作成サービスが現在利用できません。
             後ほど再度お試しください。」

Master Agent 障害:
  Chat Webhook → Vuln Agent 直接呼び出し (現行パスを維持)
  ※ Master導入後も、Chat Webhook → Vuln直接パスをフォールバックとして残す

A2A通信障害:
  A2AProtocolAdapter → LegacyRestAdapter (HTTP直接呼び出し)
  ※ アダプターパターンにより自動切替

LLM API障害 (Claude / Gemini):
  → モデルフォールバックはしない
  → エラーを正直に返す
  → 確定的パイプライン (定型フロー) は LLM非依存のため影響なし
```

#### エラーメッセージの基準

すべてのエラーメッセージに以下を含める:
1. **何が起きたか** (「分析サービスが利用できません」)
2. **次のアクション** (「10分後に再試行」「直接検索リンク」)
3. **緊急時の代替手段** (外部リンクまたは担当者連絡先)

---

### 3.7 A2A通信契約

#### メッセージフォーマット

```
Master → 子エージェント (Request):
{
  "intent": "analyze_vulnerability",
  "payload": "CVE-2024-1234 の影響を分析してください",
  "session_id": "sess_abc123",
  "trace_id": "trace_xyz789",
  "context_summary": "直前の会話で AlmaLinux 8 について議論"
}

子エージェント → Master (Response):
{
  "status": "success" | "partial" | "error",
  "result": "分析結果テキスト...",
  "source": "vuln_agent",
  "latency_ms": 4200,
  "token_count": { "input": 1200, "output": 800 }
}
```

#### タイムアウト・リトライ

| 項目 | 値 | 理由 |
|---|---|---|
| A2Aタイムアウト | **60秒** | NVD/OSV API呼び出し含む分析は30秒超の可能性 |
| リトライ | **1回** (2秒後) | A2A障害はインフラ起因が多く即リトライで回復しやすい |
| Chat Webhook | **非同期モード** | 即座に「処理中...」返信、完了後にスレッド返信。30秒制約を回避 |

---

### 3.8 セッション管理

| 項目 | 値 | 理由 |
|---|---|---|
| ストア | Firestore (`sessions/{session_id}`) | ADK公式サンプルあり。無料枠大 |
| TTL | **7日間** (最終アクティビティから) | 翌日に「昨日のあれ」と聞くケースに対応 |
| コンテキスト保持 | 直近 **4ターン** | 現行RECENT_TURNSと同じ。トークン消費を制限 |
| 引き継ぎ | session_id + context_summary を子エージェントに渡す | 子エージェントが文脈を理解するために必要 |

---

## 4. リポジトリ構成

### 4.1 判断: モノレポ維持

**理由**:

1. **ADK公式パターン**: `google/adk-samples` が `python/agents/` 配下に25以上のエージェントを並列配置するモノレポ構成
2. **既存CI/CDの再利用**: `cloudbuild.yaml` の差分ビルド (`_CHANGED_FILES` パターンマッチ) がそのまま拡張可能
3. **shared/ の扱い**: モノレポなら `cp -r shared/` で済む。マルチレポならPyPIパッケージ化が必要
4. **開発体制**: 1人 + Claude Code。モノレポなら単一セッションで全コードを横断理解・修正可能
5. **Agent Builder**: 動的生成コードはJSON/YAML設定として `generated_agents/` に保存。コードリポジトリの動的作成は複雑すぎる

### 4.2 新ディレクトリ構造

```
vuln-agent/
├── agents/                          # 全エージェント (ADK)
│   ├── master_agent/                #   マスターエージェント
│   │   ├── __init__.py
│   │   ├── agent.py
│   │   ├── prompt.py                #   システムプロンプト分離
│   │   ├── requirements.txt
│   │   └── tools/
│   │       ├── routing_tools.py     #     A2Aルーティング
│   │       └── session_tools.py     #     セッション管理
│   │
│   ├── vuln_agent/                  #   脆弱性管理エージェント (現 agent/ を移動)
│   │   ├── __init__.py
│   │   ├── agent.py
│   │   ├── prompt.py
│   │   ├── requirements.txt
│   │   └── tools/
│   │       ├── sbom_tools.py        #     現 sheets_tools.py を改名
│   │       ├── alert_tools.py       #     現 chat_tools.py の通知部分
│   │       ├── intel_tools.py       #     現 vuln_intel_tools.py
│   │       ├── history_tools.py     #     現行維持
│   │       └── web_tools.py         #     現行維持
│   │
│   └── builder_agent/               #   エージェントビルダー
│       ├── __init__.py
│       ├── agent.py
│       ├── prompt.py
│       ├── requirements.txt
│       └── tools/
│           ├── codegen_tools.py     #     ADKコード生成
│           ├── deploy_tools.py      #     Cloud Runデプロイ
│           └── registry_tools.py    #     AgentCard登録
│
├── shared/                          # 共通ライブラリ (既存拡張)
│   ├── __init__.py
│   ├── a2a_adapter.py               #   A2Aアダプター (新規)
│   ├── agent_query.py               #   既存維持
│   ├── constants.py                 #   既存維持
│   ├── gemini_direct.py             #   既存維持
│   ├── guardrails.py                #   現 guardrail_callbacks.py を移動
│   ├── infra.py                     #   既存維持
│   ├── secret_config.py             #   現 tools/secret_config.py を移動
│   ├── session_store.py             #   Firestoreセッション (新規)
│   ├── sbom_lookup.py               #   既存維持
│   ├── ticket_*.py                  #   既存維持 (5ファイル)
│   └── mcp/                         #   MCP Server実装 (将来)
│       └── __init__.py
│
├── generated_agents/                # Builder生成エージェント定義
│   └── .gitkeep                     #   JSON/YAML。コードではなく設定として管理
│
├── live_gateway/                    # 既存維持 (Cloud Run WebSocket)
├── chat_webhook/                    # 既存維持 → Master Agent経由に段階移行
├── workspace_events_webhook/        # 既存維持
├── web/                             # 既存維持
│
├── tests/                           # テスト集約 (現ルート散在を整理)
│   ├── unit/
│   │   ├── test_vuln_agent/
│   │   ├── test_master_agent/
│   │   ├── test_shared/             #   現在カバーなし → 新規追加
│   │   └── ...
│   └── integration/
│       ├── test_a2a_flow.py
│       └── test_e2e_vuln_flow.py
│
├── cloudbuild.yaml                  # 差分ビルド拡張
├── CLAUDE.md
└── README.md
```

### 4.3 現行からの移動マッピング

```
現行                              → 移動先
──────────────────────────────────────────────────────
agent/agent.py                    → agents/vuln_agent/agent.py + prompt.py
agent/tools/sheets_tools.py       → agents/vuln_agent/tools/sbom_tools.py
agent/tools/chat_tools.py         → agents/vuln_agent/tools/alert_tools.py
agent/tools/vuln_intel_tools.py   → agents/vuln_agent/tools/intel_tools.py
agent/tools/history_tools.py      → agents/vuln_agent/tools/history_tools.py
agent/tools/web_tools.py          → agents/vuln_agent/tools/web_tools.py
agent/tools/guardrail_callbacks.py→ shared/guardrails.py
agent/tools/secret_config.py      → shared/secret_config.py
agent/tools/a2a_tools.py          → shared/a2a_adapter.py (全面書き直し)
agent/tools/orchestration_tools.py→ 廃止 (Master Agentが担う)
agent/tools/capability_tools.py   → 廃止 (Cloud Runでは不要)
agent/tools/config_tools.py       → 廃止 (Cloud Runでは不要)
agent/tools/granular_tools.py     → agents/vuln_agent/tools/ に必要分のみ吸収
test_*.py (ルート19ファイル)       → tests/unit/ に整理
```

### 4.4 CI/CD (cloudbuild.yaml 拡張)

```yaml
# 差分検知の拡張
# agents/master_agent/* → DEPLOY_MASTER=true
# agents/vuln_agent/*   → DEPLOY_VULN=true
# agents/builder_agent/* → DEPLOY_BUILDER=true
# shared/*               → DEPLOY_MASTER=true, DEPLOY_VULN=true, DEPLOY_BUILDER=true
# live_gateway/*         → DEPLOY_GATEWAY=true
```

デプロイコマンド:

```bash
# 各エージェントを個別Cloud Runサービスとしてデプロイ
adk deploy cloud_run \
  --project=$PROJECT_ID \
  --region=asia-northeast1 \
  --service_name=master-agent \
  agents/master_agent/

adk deploy cloud_run \
  --project=$PROJECT_ID \
  --region=asia-northeast1 \
  --service_name=vuln-agent \
  agents/vuln_agent/

adk deploy cloud_run \
  --project=$PROJECT_ID \
  --region=asia-northeast1 \
  --service_name=builder-agent \
  agents/builder_agent/
```

**shared/ のビルド時配布**: 各エージェントのデプロイ前に `cp -r shared/ agents/{agent}/_shared/` を実行。ADKの `adk deploy cloud_run` はディレクトリ内のファイルのみをDockerコンテキストに含めるため。

---

## 5. 構造化レビュー結果

### 5.1 Skeptic (懐疑者) レビュー

**S-1: Cloud Run移行でAgent Engineの組み込みセッション管理を失う**

Agent Engineはセッション管理を内蔵しているが、Cloud Runでは自前構築が必要。Firestoreセッションストアの実装・テスト工数がボトルネックになるリスク。

→ **対策**: ADK v1.14.0以降は `InMemorySessionService` / `DatabaseSessionService` をフレームワーク内で提供。Firestoreアダプターも公式サンプルが存在。実装工数は1-2日。

**S-2: Claude Sonnet via Vertex AI のレイテンシが未検証**

Gemini Proと比較して、Claude Sonnet (Vertex AI経由) のレイテンシが本番ワークロードで許容範囲内かは実測されていない。

→ **対策**: Phase Aで品質比較テスト（同一クエリ50件）を実施し、レイテンシ・品質を実測してから移行判断。許容外ならGemini Proにフォールバック。

**S-3: adk deploy cloud_run の shared/ コンテキスト問題**

`adk deploy cloud_run` はエージェントディレクトリのみをDockerコンテキストに含める。`shared/` は親ディレクトリにあるため、直接importできない。

→ **対策**: cloudbuild.yamlでデプロイ前に `cp -r shared/ agents/{agent}/_shared/` を実行（現行の workspace_events_webhook と同パターン）。ADK v1.13.0のrequirements.txtバグはv1.14.1で修正済み。

**S-4: Agent Builderの動的エージェント生成はセキュリティリスク**

生成されたエージェントがA2Aネットワークに参加すると、品質管理・権限管理が困難。

→ **対策**: 生成エージェントはJSON/YAML設定として保存（任意コード実行ではない）。共通ADKランタイムがロード。AgentCard登録時に管理者承認ゲート必須。月額コスト上限をCloud Billing Budgetで設定。

### 5.2 Constraint Guardian (制約監視) レビュー

**C-1: コスト**

LLM月額~$35 + Cloud Run月額~$20-40 = **月額$55-75**。現行Agent Engine (ランタイム$50-100 + LLM$21) = $71-121と比較して**同等以下**。

**C-2: レイテンシ (Google Chat 応答)**

```
現行: Chat → Webhook → Agent Engine → 応答 (3-8秒)

V2:   Chat → Webhook → Master (Flash, ~1秒)
                         → A2A → Vuln Agent (Sonnet, ~3-5秒)
                         → A2A → Master → 応答
      合計: 5-10秒 (非同期スレッド返信なら許容範囲)
```

A2Aラウンドトリップ追加で+2-3秒。現行の非同期モード（CHAT_ASYNC_RESPONSE_ENABLED=true）で吸収可能。

**C-3: 可観測性**

現行はログのみ。3サービス×Cloud Runになるとトレース追跡が困難。

→ **対策**: OpenTelemetry + Cloud Trace導入。A2A通信にcorrelation_idを付与。各エージェントのBigQuery履歴に統一trace_idを記録。

**C-4: shared/ 変更時のデプロイ範囲**

現行の cloudbuild.yaml は `shared/*` 変更時に `DEPLOY_WORKSPACE_EVENTS` のみフラグが立つバグがある（`DEPLOY_AGENT` が立たない）。V2では3エージェント全てに波及する。

→ **対策**: cloudbuild.yaml拡張時に `shared/*` → 全エージェント再デプロイのフラグを正しく設定。

### 5.3 User Advocate (ユーザー代弁者) レビュー

**U-1: Master Agent導入でユーザー体験が変わる**

現行はGoogle ChatでVuln Agentに直接話しかける。Master経由になっても体験が悪化しないか。

→ **対策**: Masterは透過的に動作。ユーザーは「課のAIアシスタント」に話す認識でOK。レスポンスのフッターに「この回答は脆弱性管理エージェントが担当しました」を表示し、内部動作を可視化。

**U-2: Agent Builderは非技術者に使えるか**

「エージェントを作って」は抽象的すぎて非技術者には難しい。

→ **対策**: テンプレート型UI。「経費精算」「議事録要約」「週報作成」等のプリセットを3-5個用意。ゼロからの自由構築はパワーユーザー向け上級モード。

**U-3: エラー時の体験**

子エージェント障害時にユーザーに何が伝わるか。

→ **対策**: Master Agentにグレースフルデグラデーションを実装。「現在脆弱性分析サービスが一時的に利用できません。XX分後に再試行してください」等の自然言語案内。

### 5.4 Integrator (統合判定)

| ID | 指摘 | 判定 | 対応 |
|----|------|------|------|
| S-1 | セッション管理喪失 | **解決済** | ADK組込み + Firestoreアダプター |
| S-2 | Claude レイテンシ未検証 | **Phase Aで実測** | 50件比較テスト。フォールバック用意 |
| S-3 | shared/ コンテキスト | **解決済** | cp -r パターン (既存手法) |
| S-4 | Builder セキュリティ | **対策済** | JSON設定 + 承認ゲート + コスト上限 |
| C-1 | コスト | **問題なし** | 現行同等以下 |
| C-2 | レイテンシ | **許容範囲** | 非同期モードで吸収 |
| C-3 | 可観測性 | **Phase Bで対応** | OpenTelemetry + Cloud Trace |
| C-4 | shared/ デプロイ | **Phase A で修正** | cloudbuild.yaml フラグ修正 |
| U-1 | UX 変化 | **対策済** | 透過動作 + フッター表示 |
| U-2 | Builder UX | **Phase Cで対応** | テンプレート型UI |
| U-3 | エラー体験 | **Phase Bで対応** | グレースフルデグラデーション |

**最終判定: APPROVED** — 全指摘事項に対する対策が明文化済み。未解決項目はPhase A の実測テストで判断。

---

## 6. テスト戦略

### 原則

「AIが関わらない処理」と「AIが関わる処理」でテスト手法を完全に分ける。

### 確定的処理のテスト（assert で検証可能）

| 対象 | テスト方法 | カバレッジ基準 |
|---|---|---|
| SIDfm通知解析 (ticket_parsers.py) | 入力テキスト → 抽出結果のassert | パターン網羅: CVE桁数バリエーション、GHSA形式、CVSS有無 |
| SBOM突合 (sbom_lookup.py) | モックBQ → 影響システムリストのassert | 該当あり/なし/複数該当/データソース障害 |
| 期限計算 (DEADLINE_RULES) | CVSS × resource_type × exploit → 営業日数のassert | 全ルール組合せ (R1-R5 × 各パラメータ) |
| 担当者マッピング | purl → owner のassert | マッチ/不一致/デフォルトフォールバック |
| Masterインテント分類 | メッセージ → ルーティング先のassert | SIDfm通知/Builder依頼/既知コマンド/曖昧(AIに委任) |
| A2Aアダプター | モックHTTP → レスポンス処理のassert | 正常/タイムアウト/リトライ/フォールバック |

**基準: 確定的パイプラインのカバレッジ100%。** これらは全て純粋関数であり、テストが書けないコードはない。

### AI処理のテスト（Golden Test方式）

LLMの出力を「正解」と比較することは不可能。代わりに**必須要素の存在確認**で検証する。

```python
# 例: Vuln Agent 対話モードのGolden Test
GOLDEN_TESTS = [
    {
        "input": "CVE-2024-1234 の AlmaLinux 8 への影響を教えて",
        "required_elements": [
            "CVE-2024-1234",       # CVE-IDへの言及
            "AlmaLinux",           # 対象OSへの言及
            "CVSS",                # スコアへの言及
        ],
        "forbidden_elements": [
            "わかりません",          # 回答拒否
            "エラー",               # 処理失敗
        ],
    },
    # ... 最低20件: 通知パターン(CVSS High/Med/Low × exploit有無 × SBOM該当/非該当)
    #              + 対話パターン(影響分析/履歴参照/比較質問/曖昧質問)
]
```

**基準: 全Golden Testのrequired_elementsが出力に含まれること。** AIの「採点」は使わない。文字列マッチのみ。

### 統合テスト

| テストケース | 検証内容 |
|---|---|
| Chat → Master → Vuln (定型) | SIDfm通知が確定的パイプラインで処理され、Chat返信が来ること |
| Chat → Master → Vuln (対話) | 人の質問がAIパスで処理され、Chat返信が来ること |
| Chat → Master → Builder | 「エージェントを作って」がBuilder に委任されること |
| Master障害時フォールバック | Chat → Vuln直接パスが動作すること |
| A2Aタイムアウト | 60秒超で適切なエラーメッセージが返ること |

---

## 7. 可観測性

### ログ基準

| 種別 | 記録内容 | 記録先 |
|---|---|---|
| **A2A通信** (必須) | trace_id, source_agent, target_agent, status, latency_ms, token_count | Cloud Logging |
| **A2A payload** (ERROR時のみ) | request/response本文 | Cloud Logging (通常時は記録しない。容量削減) |
| **ツール実行** (必須) | tool_name, agent_id, status, latency_ms | Cloud Logging |
| **LLM呼び出し** (必須) | model, input_tokens, output_tokens, latency_ms | Cloud Logging |
| **脆弱性処理履歴** | 全フィールド | BigQuery (既存) |

### トレーシング

```
trace_id の伝播:
  Chat Webhook → (trace_id生成) → Master → (trace_id引継) → Vuln Agent
                                                              → BigQuery履歴

全ログにtrace_idを付与し、1つのリクエストの全経路を追跡可能にする。
実装: OpenTelemetry + Cloud Trace。
```

### アラート

| 条件 | 閾値 | 通知先 |
|---|---|---|
| エラー率 | > 10% / 5分間 | Google Chat (運用チャンネル) |
| レイテンシ p95 | > 15秒 | Google Chat |
| Cloud Run インスタンス異常終了 | > 3回 / 10分間 | Google Chat |
| LLM API 429 (レート制限) | > 5回 / 1分間 | Google Chat |

---

## 8. データオーナーシップ

| データストア | Source of Truth | 書き込み権限 | 読み取り権限 |
|---|---|---|---|
| SBOM (BigQuery / Sheets) | 外部プロセス (SBOM管理者) | 外部のみ | Vuln Agent |
| 脆弱性処理履歴 (BigQuery) | Vuln Agent | Vuln Agent | Vuln Agent, Master (参照) |
| セッション (Firestore) | Master Agent | Master Agent | Master Agent |
| AgentCard レジストリ | Builder Agent | Builder Agent | Master Agent |
| 生成Agent定義 (generated_agents/) | Builder Agent | Builder Agent | 共通ランタイム |
| Secret / 設定 (Secret Manager) | 運用管理者 | 運用管理者のみ | 全エージェント (読取) |

**原則: 1つのデータストアに対して書き込み権限を持つのは1つのエージェント（または外部プロセス）のみ。** 複数エージェントが同一データを書き込む設計は禁止。衝突の元。

---

## 9. セキュリティモデル

### Phase A-B（課内運用）

```
全エージェント共通:
  サービスアカウント: 1つ (vuln-agent-sa@project.iam.gserviceaccount.com)
  IAMロール: BigQuery Data Viewer/Editor, Firestore User,
             Secret Manager Accessor, Chat API

  理由: 1人+Claude Code体制で、サービスアカウント分離の管理コストが見合わない。
```

### Phase C（マルチテナント・部署展開時）

```
サービスアカウント分離:
  master-agent-sa   → Firestore, Secret Manager (読取), A2A呼び出し
  vuln-agent-sa     → BigQuery, Sheets, Chat API, NVD/OSV外部API
  builder-agent-sa  → Cloud Run Admin, Artifact Registry, AgentCardレジストリ
  generated-agent-sa → テンプレートから生成。管理者が承認時に権限を個別付与

  分離タイミング: マルチテナント化が必要になった時点。それまでは過剰。
```

### Agent Builder セキュリティガードレール

```
生成エージェントの制約:
  1. 実行コードなし    → JSON/YAML設定のみ。任意コード実行不可
  2. ツール許可リスト   → 生成時にBuilderが利用APIを提示、管理者が個別承認
  3. コスト上限        → Cloud Billing Budget alert (生成エージェント単位)
  4. A2A参加承認       → AgentCard登録時に管理者承認ゲート必須
  5. 自動停止          → 30日間未使用のエージェントはCloud Runサービス停止
```

---

## 10. 実装ロードマップ

### Phase A: 基盤移行 + 品質検証（2-3週間）

```
Week 1:
  □ Firestoreセッションストア実装 (shared/session_store.py)
  □ agents/vuln_agent/ ディレクトリ作成、現行 agent/ からコード移動
  □ LiteLlm(model="vertex_ai/claude-sonnet-4-6") でモデル差し替え
  □ Cloud Run デプロイ確認 (adk deploy cloud_run)

Week 2:
  □ 品質比較テスト: Gemini Pro vs Claude Sonnet (同一クエリ50件)
    - 測定項目: レイテンシ、日本語自然さ、分析精度、コスト
    - 結果に基づきモデル最終決定
  □ shared/ の cp -r ビルドパイプライン確認
  □ cloudbuild.yaml フラグ修正 (shared/* → 全エージェント再デプロイ)

Week 3:
  □ Chat Webhook → Cloud Run Vuln Agent に向き先変更
  □ Agent Engine → Cloud Run 並行稼働 → 動作確認 → 切替
  □ tests/ ディレクトリ整理、shared/ テスト追加
  □ Agent Engine インスタンス停止
```

### Phase B: Master Agent + A2A（3-4週間）

```
Week 4-5:
  □ agents/master_agent/ 新規作成 (Gemini Flash)
  □ shared/a2a_adapter.py 実装 (アダプターパターン)
  □ A2A AgentCard 定義 (vuln_agent, master_agent)
  □ Master → Vuln Agent の A2A 通信テスト

Week 6-7:
  □ Chat Webhook → Master Agent 経由に切替
  □ Live Gateway → Master Agent 経由に切替
  □ OpenTelemetry + Cloud Trace 導入
  □ グレースフルデグラデーション実装
  □ 統合テスト (E2E: Chat → Master → Vuln → Chat返信)
```

### Phase C: Agent Builder + 拡張（1-2ヶ月）

```
Week 8-10:
  □ agents/builder_agent/ 新規作成 (Claude Opus)
  □ ADKテンプレートコード生成ツール
  □ Cloud Runデプロイツール
  □ AgentCard自動登録ツール
  □ テンプレート型UI (3-5業務プリセット)

Week 11-12:
  □ generated_agents/ JSON/YAML管理フロー
  □ 承認ゲート (管理者承認後にA2Aネットワーク参加)
  □ Cloud Billing Budget alert (動的エージェントコスト上限)
  □ 監査ログ (BigQuery統一ストリーム)

Week 12+:
  □ MCP Server 標準化 (shared/mcp/)
  □ マルチテナント対応 (部署展開に向けて)
```

---

## 11. 判断記録 (Decision Log)

| # | 判断 | 採択案 | 棄却案 | 理由 |
|---|------|--------|--------|------|
| D1 | 実行基盤 | Cloud Run + ADK | Agent Engine維持 | 上限10撤廃、MCP安定性、コスト削減、制御力 |
| D2 | リポジトリ | モノレポ維持 | マルチレポ / ハイブリッド | ADK公式パターン準拠、shared/共有が最もシンプル、1人+Claude Code体制に最適 |
| D3 | Vulnモデル | Claude Sonnet 4.6 | Gemini 2.5 Pro | 日本語品質・推論精度 (Phase A実測で最終確認) |
| D4 | Builderモデル | Claude Opus 4.5 | Gemini 2.5 Pro | コード生成精度 (SWE-bench 80.9%) |
| D5 | Masterモデル | Gemini 2.5 Flash | Claude Haiku | $0.15/1M。ルーティングのみでFlashの品質で十分。コスト1/7 |
| D6 | ルーティング | エージェント単位固定 | スコアベース動的切替 | 複雑性排除。責務明確化 |
| D7 | A2A | 段階的に正式v0.3移行 | カスタムREST維持 | Linux Foundation統合仕様。150+組織エコシステム |
| D8 | ツール接続 | MCP標準化 (段階的) | 現行直接API維持 | 再利用性。エージェント間ツール共有 |
| D9 | エージェント数 | 3 (Master/Vuln/Builder) | 6-7 (未稼働含む全展開) | 確定業務のみ。存在しない業務のエージェントは作らない |
| D10 | クラウド | GCP維持 | AWS/Azure移行 | Google Chat/Sheets/BigQuery統合。スイッチングコスト大 |
| D11 | 生成エージェント | JSON/YAML設定 | コードリポジトリ動的生成 | セキュリティ・管理容易性。共通ランタイムでロード |
| D12 | AI vs コード境界 | 確定処理はLLM呼び出し0回 | 全処理をLLM経由 | 速度・再現性・監査可能性。CODEX_TASK.mdの設計方針を継承 |
| D13 | LLM障害時 | エラーを正直に返す | 別モデルにフォールバック | 品質を落として回答するより停止が安全 |
| D14 | テスト手法 | 確定処理=assert / AI=Golden Test | LLMによるAI採点 | 採点AIの信頼性が不明。文字列マッチのみで検証 |
| D15 | SA分離タイミング | Phase C (マルチテナント化時) | 初期から分離 | 1人体制でIAM管理コストが見合わない |
| D16 | A2Aログ方針 | メタデータ必須 / payload本文はERROR時のみ | 全payload記録 | 容量削減。LLM長文応答でログ膨張を防ぐ |
| D17 | データ書き込み原則 | 1データストア=1書き込み者 | 複数エージェント書き込み可 | 衝突防止。Source of Truth の明確化 |

---

## 12. リスクマトリクス

| リスク | 発生確率 | 影響度 | 対策 | 検証タイミング |
|--------|----------|--------|------|----------------|
| Claude Vertex AI レイテンシ許容外 | 中 | 高 | Gemini Pro フォールバック | Phase A Week 2 |
| A2A v0.3 破壊的変更 | 低〜中 | 中 | アダプターパターン | Phase B |
| adk deploy cloud_run のバグ | 低 | 中 | gcloud run deploy 直接に切替 | Phase A Week 1 |
| Agent Builder 品質管理困難 | 中 | 高 | JSON設定限定 + 承認ゲート | Phase C |
| shared/ 変更の影響範囲見落とし | 中 | 中 | cloudbuild.yaml フラグ修正 + CI テスト | Phase A Week 2 |

---

## 13. 参照リンク

- [ADK Cloud Run Deploy](https://google.github.io/adk-docs/deploy/cloud-run/)
- [ADK A2A Integration](https://google.github.io/adk-docs/a2a/)
- [ADK Multi-Model (LiteLLM)](https://docs.litellm.ai/docs/tutorials/google_adk)
- [Claude on Vertex AI](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/partner-models/claude)
- [A2A + ACP Linux Foundation統合](https://lfaidata.foundation/communityblog/2025/08/29/acp-joins-forces-with-a2a-under-the-linux-foundations-lf-ai-data/)
- [Vertex AI Agent Engine Overview](https://docs.cloud.google.com/agent-builder/agent-engine/overview)
- [google/adk-samples (モノレポ参考)](https://github.com/google/adk-samples)
