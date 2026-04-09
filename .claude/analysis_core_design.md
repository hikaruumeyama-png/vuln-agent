# AIエージェントコア設計の詳細分析と改善案

**分析対象**: Vertex AI Agent Engine版 脆弱性管理AIエージェント
**分析日**: 2026-02-21
**分析担当**: agent-analyst チーム

---

## 1. システムプロンプト設計の評価

### 1.1 現状の構造と特徴

システムプロンプト（`AGENT_INSTRUCTION`）は **226行の詳細な指示体系** で構成されています。

#### 強み
- **責務の明確化**: 5つの主要責務（検知→分析→特定→判定→通知）が明示的に定義されている
- **データ構造の説明**: SBOMシートと担当者マッピングシートの構造が具体的に記載
- **フロー定義**: 処理フロー（分析実行時）が段階的に示されている
- **質問対応**: ユーザー問い合わせパターンと回答ポリシーが列挙されている
- **権限内実行ポリシー**: `get_runtime_capabilities` による権限確認の流れが指示されている
- **出力フォーマット統一**: 4セクション形式（結論→根拠→不確実性→次アクション）の統一化

#### 課題

1. **指示の粒度不均等**
   - L71-100: 主要責務（5行）vs L101-226: 詳細ポリシー（125行）で **24倍の粒度差**
   - 権限判定ロジック（L159-166）が細粒度化していて「判定を自動化」しすぎている

2. **曖昧な優先度付け**
   - L196-207: "細粒度優先ポリシー" と L208-218: "実行方式選択ポリシー" が **重複・競合**
   - 「まず細粒度ツール」vs「まず decide_execution_mode」のどちらが優先か不明確
   - L190-194: 実行スコープ制御とツール合成ポリシーの対立構造

3. **暗黙的な前提条件**
   - L104: 期限計算が `send_vulnerability_alert()` 内部で行われることへの依存
   - L120: SBOM検索で "検索結果に担当者情報が自動付加される" という実装依存の指示

4. **出力フォーマットの強制度が不適切**
   - L177-188: "すべての通常回答は4セクション必須"は、簡潔な回答を阻害する可能性
   - 単一行の回答（例: "リソース見つかりません"）で4セクション必須は過度

### 1.2 改善提案

#### 優先度1: 指示の整理統合

```markdown
# 改善案1: ポリシー統合（実行方式の一本化）

現在:
- L196-207: 細粒度優先ポリシー
- L208-218: 実行方式選択ポリシー

改善案:
┌─────────────────────────────────────────────┐
│ 統一実行フロー                              │
├─────────────────────────────────────────────┤
│ 1. decide_execution_mode() で粗判定         │
│ 2. direct_tool の場合:                      │
│    - list_predefined_operations で操作確認  │
│    - 細粒度ツール優先で段階実行             │
│ 3. codegen_with_tools の場合:              │
│    - generate_tool_workflow_code で計画     │
│    - execute_tool_workflow_plan で実行      │
│ 4. 権限不足なら get_authorized_operations_ │
│    overview で代替を検索                    │
└─────────────────────────────────────────────┘
```

#### 優先度2: 出力フォーマットの柔軟化

```markdown
# 改善案2: 応答形式の適応的ルール

現在: "すべての通常回答は4セクション必須"

改善案:
┌─────────────────────────────────────────┐
│ 応答型パターン別フォーマット            │
├─────────────────────────────────────────┤
│ A. データ取得型                         │
│    → 結論のみ + 根拠URL              │
│    (例: SBOM検索、メンバー一覧)       │
│                                        │
│ B. 判定型                             │
│    → 結論 + 根拠 + 不確実性           │
│    (例: CVE分類、期限判定)            │
│                                        │
│ C. 行動型                             │
│    → 結論 + 根拠 + 不確実性 + 次ア    │
│    (例: 通知送信、引継ぎ)             │
│                                        │
│ D. エラー型                           │
│    → エラー理由のみ + 次ア             │
│    (例: 権限不足、データ見つからず)    │
└─────────────────────────────────────────┘
```

---

## 2. ツール群の責務分離と設計品質

### 2.1 ツール分類と現状

| グループ | ツール数 | 特徴 | 評価 |
|---------|--------|------|------|
| **Sheets/SBOM** | 10 | SBOM検索・詳細抽出 | ⭐⭐⭐⭐ 細粒度化が良い |
| **Chat** | 4 | 通知・メッセージ送信 | ⭐⭐⭐ 強い＆機能豊か |
| **History** | 1 | 履歴保存 | ⭐⭐ 単機能だが必須 |
| **A2A** | 9 | エージェント連携 | ⭐⭐⭐ 拡張可能だが複雑 |
| **Capability** | 4 | 権限確認 | ⭐⭐⭐⭐ 自律性向上に貢献 |
| **Granular** | 13 | 既存ツールの細粒度ラッパー | ⭐⭐ 有用だが責務不明確 |
| **Orchestration** | 8 | 実行方式判定・コード生成 | ⭐⭐⭐ 構想は良いが実装品質に課題 |
| **Config** | 2 | 設定参照 | ⭐⭐⭐ 最小化が適切 |
| **Web/Intel** | 5 | 外部API参照 | ⭐⭐⭐⭐ 外部情報源として堅牢 |

**合計: 56ツール** が登録されている。

### 2.2 責務の重複と境界

#### 問題1: Granular Tools の位置付け曖昧性

```python
# 現状: Granular Tools の実態

def list_chat_member_emails(space_id):
    """チャットメンバーのメール一覧のみ返す"""
    result = list_space_members(space_id=space_id)  # ← ラッパーの単なるフィルタ
    members = result.get("members") or []
    emails = sorted({m.get("email", "") for m in members if m.get("email")})
    return {"status": "success", "count": len(emails), "emails": emails}
```

**課題**: ラッパーツールが13個あり、 `agent.py` の import list を肥大化させている。
- Granularツール自体が「細粒度化」を標榜しているが、実際には既存ツールへの**フィルタリングラッパー**
- エージェント側から見ると「別のツール」に見えるため、認知的負荷増加

**改善案**:
```markdown
# 案1: Granular を内部化
- granular_tools を agent.py にインポートせず
- 必要に応じてエージェントが "複数ツール合成" で実現
- 登録ツール数削減: 56 → 43

# 案2: Granular を戦略的に選別
- 頻繁に使う細粒度化 (5個程度) のみ残す:
  - list_chat_member_emails (Chat系)
  - check_bigquery_readability_summary (BQ系)
  - get_nvd_cvss_summary (Intel系)
  - list_osv_vulnerability_ids (Intel系)
  - list_web_search_urls (Web系)
- 残り8個は "エージェントが合成" で実現
```

#### 問題2: A2A Tools の粒度問題

```python
# A2Aツール群 (9個)

1. register_remote_agent              # 基本的な登録
2. register_master_agent              # master_agent 特化登録
3. call_remote_agent                  # 単発呼び出し
4. call_remote_agent_conversation_loop # 継続対話
5. call_master_agent                  # master_agent 特化呼び出し
6. create_jira_ticket_request         # リクエスト文作成
7. create_approval_request            # 承認文作成
8. create_master_agent_handoff_request # 引継ぎ文作成
9. list_registered_agents             # 登録一覧確認
```

**課題**:
- `register_remote_agent` と `register_master_agent` は **責務不明確** (master_agent専化の根拠は?)
- `call_remote_agent` と `call_master_agent` も **実質同じ** (引数のmessageだけ異なる)
- `create_*_request` が3種類あるが、フォーマットは `create_master_agent_handoff_request` 一択 (L591-657)

**改善案**:
```python
# 統合案: A2A ツール5個に整理

1. register_agent(agent_id, resource_name, role="remote")
   # role="master" で master_agent 特化処理

2. call_agent(agent_id, message, conversation_mode=False, max_turns=5)
   # conversation_mode=True で自動継続対話

3. create_agent_request(request_type, fields)
   # request_type in ["jira", "approval", "handoff"]
   # 統一フォーマットで構築

4. list_agents()

5. get_agent_info(agent_id)
```

### 2.3 命名規則の一貫性

**良い例**:
- `search_sbom_by_purl` vs `search_sbom_by_product` (動詞-対象-条件)
- `get_sbom_contents` vs `get_owner_mapping` (get-リソース)

**悪い例**:
- `list_sbom_package_types` (list-対象)
- `count_sbom_packages_by_type` (count-対象)
- 同じ行為（列挙）を `list_` と `count_` で区別 → エージェントが区別困難

**改善案**:
```
統一案: 動詞を以下に絞る
- search_*: 複雑な検索（複数条件、複数結果）
- get_*: 単一リソース取得または リスト形式でまとめた取得
- list_*: 列挙（カウント込み）
- count_*: 廃止（list_* で count 含める）

適用例:
- count_sbom_packages_by_type() → get_sbom_package_type_summary()
  返値: {types: ["npm", "maven"], counts: {"npm": 50, "maven": 30}, total: 80}
```

---

## 3. A2A（Agent-to-Agent）連携設計の評価

### 3.1 現状の設計

#### プロトコル
- **Vertex AI ReasoningEngine REST API** を使用（streamQuery / query endpoint）
- Token取得、リソース名解析、リトライロジックが実装されている

#### レジストリ機構
```python
_agent_registry: dict[str, Any] = {}
# リモート状態でメモリ蓄積 → Agent Engine再起動で消える
```

#### エージェントタイプ
- `master_agent`: 課のマスターエージェント（統合判断用）
- `jira_agent`, `approval_agent` 等: 役割別エージェント

### 3.2 課題分析

#### 課題1: レジストリの永続性喪失

```python
# 現状問題:
_load_preconfigured_agents()  # モジュール読込時に環境変数から読み込み

# 環境変数に設定: REMOTE_AGENT_JIRA=projects/.../reasoningEngines/xxx

# Agent Engine 再起動 → メモリ消去 → 再度 _load_preconfigured_agents() 呼び出し
```

**影響**:
- 同じ脆弱性を複数通知した場合、毎回レジストリ再読み込みで無駄
- 動的登録の永続化ができない（一時的な連携が消える）

**改善案**:
```markdown
# 案: Simple KVS or Local File Cache

1. 環境変数から読み込み → `_agent_registry` に キャッシュ
2. 동적登録 (`register_remote_agent`) → メモリ + `agent_registry.json` に記録
3. 再起動時: JSON から復元 → 環境変数でアップデート
4. CloudRun 再起動時は環境変数から再初期化
```

#### 課題2: エラーハンドリングの薄さ

```python
# 現状: call_remote_agent のエラー処理

if result.get("status") != "success":
    stop_reason = "remote_error"
    return {
        "status": "error",
        "agent_id": normalized_agent_id,
        "stop_reason": stop_reason,
        "turns_executed": turn,
        "final_response_text": response_text,
        "transcript": transcript,
        "message": str(result.get("message") or "remote agent call failed"),
    }
```

**課題**:
- エラーの **分類** がない（認証エラー vs リソース不在 vs タイムアウト）
- エラー時の **フォールバック戦略** がない

**改善案**:
```python
# エラー分類スキーム
class A2AError(Enum):
    AGENT_NOT_REGISTERED = "agent_not_found"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    SERVICE_UNAVAILABLE = "service_unavailable"

# エージェント側の対応戦略
if error_type == AGENT_NOT_REGISTERED:
    # → register_master_agent で自動登録を試みる
    # → それでも駄目なら代替フロー提案
elif error_type == TIMEOUT:
    # → max_turns 削減で再試行
elif error_type == SERVICE_UNAVAILABLE:
    # → 次のターンに遅延実行を提案
```

#### 課題3: 継続対話の停止条件が脆弱

```python
# 現状: call_remote_agent_conversation_loop の停止判定

final_markers = ("最終回答:", "final answer:", "完了です", "以上です")
if any(marker in response_text.lower() for marker in final_markers):
    stop_reason = "final_marker_detected"
    break
```

**課題**:
- マーカーが応答に含まれない場合、`max_turns` まで無駄に実行
- LLM応答は **文脈に依存** → 同じ内容でもマーカー有無がばらつく
- **同一応答の重複検知** も不安定（正規化だけでは不十分）

**改善案**:
```markdown
# 停止判定ロジックの高度化

1. マーカー検知 (重要度: 高)
2. セマンティック重複検知 (embedding距離)
3. 到達可能性判定 (ツール呼び出しなし → 応答が進展していない)
4. 信頼度スコア算出 (継続の価値判定)

例:
- Turn 3 で "答えが出ました" → STOP
- Turn 3-4 の応答が語義的に同じ → STOP
- Turn 3-4 で新規ツール呼び出しなし → WARNING (STOP検討)
```

### 3.3 拡張性の評価

#### 良い点
- `call_remote_agent_conversation_loop` で **継続対話パターン** の実装がある
- `create_master_agent_handoff_request` で **標準フォーマット化** されている

#### 不足点
- エージェント間での **状態共有** 機構がない
  - 例: master_agentが jira_agentを呼ぶ際、チケットID を次の処理に渡す方法がない
- **優先度制御** がない（すべて同一優先度で実行）
- **条件付き分岐** がない（AIが判定してから複数の異なるエージェントを選択・呼び出す流れはサポートされていない）

---

## 4. オーケストレーション・細粒度ツールの設計品質

### 4.1 Orchestration Tools の実装評価

#### ツール群
1. `list_predefined_operations`: 事前ツール化された操作一覧
2. `list_operation_catalog_health`: カタログと実装の同期チェック
3. `get_authorized_operations_overview`: 権限内で何ができるか総覧
4. `decide_execution_mode`: 実行方式を `direct_tool` or `codegen_with_tools` で判定
5. `generate_tool_workflow_code`: ツール呼び出しコードを生成（実行なし）
6. `execute_tool_workflow_plan`: 計画を安全に段階実行

#### 強み
- **自律性向上**: エージェントが「今何ができるのか」を自己診断可能
- **実行安全性**: 生成コードを検証後に段階実行する設計
- **カタログの自己修復**: `list_operation_catalog_health` で漏れを検知できる

#### 課題

##### 課題1: `decide_execution_mode` の判定ロジックが粗い

```python
# 現状
complexity_score = 0
if len(request_text) >= 120:
    complexity_score += 1
if len(requested_ops) >= 4:
    complexity_score += 2
elif len(requested_ops) >= 2:
    complexity_score += 1

complexity_hits = [hint for hint in _COMPLEXITY_HINTS if hint in normalized]
complexity_score += min(len(complexity_hits), 3)

mode = "codegen_with_tools" if complexity_score >= 3 else "direct_tool"
```

**問題**:
- **テキスト長ベース** (≥120文字) で判定 → 長い但し単純な依頼も `codegen` へ
- **キーワードベース** → 「複数」という単語があると自動 `codegen` (偽正例)
- **運用実績がない** → scoring パラメータが恣意的

**改善案**:
```python
# 複雑度判定の多次元化

def decide_execution_mode_v2(user_request, context=None):
    dimensions = {
        "arity": _score_tool_arity(requested_ops),        # ツール数
        "interdependency": _score_dependencies(flow),     # ツール間の依存
        "state_threading": _score_state_sharing(flow),    # 状態共有必要度
        "error_recovery": _score_error_paths(flow),       # エラー分岐
        "temporal": _score_sequential_constraints(flow),  # 時間的制約
    }

    # スコア集約
    complexity = weighted_sum(dimensions, weights={
        "arity": 0.2,
        "interdependency": 0.35,
        "state_threading": 0.2,
        "error_recovery": 0.15,
        "temporal": 0.1,
    })

    return "codegen_with_tools" if complexity > 0.5 else "direct_tool"
```

##### 課題2: `generate_tool_workflow_code` が生成するコードが実行不可

```python
# 生成コード例
def run_workflow(tools):
    request = "CVE-2024-12345の影響システムを調べて"
    results = []
    # Step: search_sbom_by_purl
    results.append({'tool': 'search_sbom_by_purl', 'result': tools['search_sbom_by_purl']()})
    # Step: get_owner_mapping
    results.append({'tool': 'get_owner_mapping', 'result': tools['get_owner_mapping']()})
    return {...}
```

**問題**:
- ツール呼び出しに **引数がない** → 実際は動作しない
- ツール間に **データ依存** (前ステップの結果を使う) が全く表現されない
- `search_sbom_by_purl(cve_id)` のように **必須引数が不足**

**改善案**:
```python
# 改善案: ワークフロー仕様言語化

def generate_tool_workflow_code_v2(user_request, tool_sequence=None):
    """ワークフローを YAML/JSON で出力 → execute_tool_workflow_plan で実行"""

    # 生成フォーマット (JSON)
    workflow = {
        "version": "1.0",
        "steps": [
            {
                "id": "step_1",
                "tool": "search_sbom_by_purl",
                "description": "CVEに該当するパッケージをSBOMで検索",
                "inputs": {
                    "purl_pattern": "{{ extract_purl_from_request }}",
                },
                "outputs": {
                    "affected_systems": "$.matched_entries[].system_name",
                },
            },
            {
                "id": "step_2",
                "tool": "send_vulnerability_alert",
                "description": "影響システムの担当者に通知",
                "inputs": {
                    "affected_systems": "{{ step_1.affected_systems }}",
                    "vulnerability_id": "{{ extract_cve_id }}",
                },
                "depends_on": ["step_1"],
            },
        ],
    }

    return {
        "status": "success",
        "workflow": workflow,
        "note": "execute_tool_workflow_plan に workflow を渡して実行",
    }
```

##### 課題3: `execute_tool_workflow_plan` のエラー対応

```python
# 現状
for index, step in enumerate(steps, start=1):
    try:
        fn = _resolve_tool(tool_name)
        tool_result = fn(**kwargs)
        results.append({...})
    except Exception as exc:
        results.append({
            "step": index,
            "tool": tool_name,
            "status": "error",
            "message": str(exc),
        })
        if fail_fast:
            return {"status": "error", "step_results": results}
```

**問題**:
- **ステップスキップ** 機構がない → エラーで停止 or すべて実行（両極端）
- **条件分岐** がない → 前ステップの結果に基づいて次ステップを選択できない
- **リトライ戦略** がない → 一度失敗したら終わり

**改善案**:
```yaml
# ステップ制御の拡張

steps:
  - id: step_1
    tool: search_sbom_by_purl
    error_handling:
      on_not_found: skip          # 結果なし → 次ステップスキップ
      on_error: fallback_to_search_by_product  # エラー時の代替
      max_retries: 2

  - id: step_2
    tool: send_vulnerability_alert
    condition: "step_1.total_count > 0"  # 条件付き実行
    depends_on: [step_1]

  - id: step_2b
    tool: send_simple_message
    condition: "step_1.total_count == 0"  # 結果なしの別フロー
```

### 4.2 Granular Tools と Capability Tools の連携

#### 現状の一体化度
```python
# Capability Tools で権限を確認
get_runtime_capabilities()  # ツール一覧、接続状態

# その結果をエージェント側で解釈して、Granular で詳細取得
list_chat_member_emails()  # Chatメンバーメール取得

# さらに意思決定
if chat_connected and bigquery_readable:
    # ツール実行
```

#### 課題
- **エージェント側で判定** → ツール選択が自動化されない
- **Granular と Capability の責務混在** → どちらを使うか不明確

#### 改善案
```markdown
# 階層化: Capability → Granular → 特定ツール

階層1: Capability (可・不可のみ)
  └ get_runtime_capabilities()
    └ {chat: True, bigquery: False, ...}

階層2: Granular (粗い詳細)
  └ get_chat_space_info(), check_bigquery_readability_summary()
    └ {space_id: "...", member_count: 5, ...}

階層3: 特定ツール (詳細操作)
  └ list_chat_member_emails(), list_bigquery_tables()
    └ {emails: [...], tables: [...]}

エージェント判定フロー:
1. get_runtime_capabilities() → 対応サービス判定
2. (オプション) Granular で簡単な詳細確認
3. 詳細が必要ならば特定ツール実行

→ ツール選択の自動化の余地あり
```

---

## 5. 自律性向上に向けた改善点

### 5.1 現状の自律度評価

#### 高い自律性
- ✅ SBOM検索から担当者特定まで自動化（検索結果に自動付加）
- ✅ CVSS/リソース種別ベースの期限判定（ルール化）
- ✅ 権限確認してからツール実行（`get_runtime_capabilities` → フォールバック）
- ✅ 脆弱性スキャン後の自動通知

#### 低い自律性
- ❌ A2A連携の **条件付き選択** がない（どのエージェントを呼ぶか固定）
- ❌ 複数ステップの依存関係を **自動認識できない**（ユーザーが指示）
- ❌ エラーから自動リカバリ戦略がない（通知で終わり）
- ❌ 外部情報（Web検索、NVD）を **主体的に併用しない**（質問されるまで見ない）

### 5.2 フィードバックループの構築

#### 現状: フィードバックの欠落

```
流れ:
脆弱性入力 → SBOM検索 → 通知送信 → (終わり)

問題:
- 通知送信後、実際に「対応されたか」を知らない
- 修正依頼が来ても「前回とのつながり」を保持しない (incident_id はあるが履歴参照が手動)
```

#### 改善案

```markdown
# フィードバックループの実装

## A. 履歴ベースの状態追跡

通知送信時:
1. incident_id を生成
2. BigQuery に通知レコード保存
3. チャットスレッドに incident_id 埋め込み

修正依頼時:
1. スレッドから incident_id 抽出
2. BigQuery で過去のレコード検索
3. 前回との差分を認識 (「担当者変わった？」「期限が...」)

## B. 定期的な状況確認

（高度な自律性が必要）
- 毎日昼12時に「期限が明日な案件」をリマインド
- 「前回から10日、未解決案件」をエスカレーション
- web_search で CVE の最新情報を自動追跡

## C. エラーからの自動リカバリ

例: 通知送信失敗
→ エージェント自身で send_simple_message にフォールバック
→ 別の担当者に「通知失敗」を報告

例: SBOM検索結果が空
→ web_search で該当製品を検索
→ 「SBOMには未登録」を明示して通知
```

### 5.3 外部情報の主動的活用

#### 現状
```python
# システムプロンプト L168-174
# 「最新性が重要な問い（価格、脆弱性動向、リリース、ニュース）は web_search で根拠を取得」

# しかし実装:
# - CVE 詳細: NVD/OSV は呼ぶが、Web検索は「必要なら」
# - Web検索自体は エージェントが判断している（推奨ではない）
```

#### 改善案

```markdown
# 自動 Web 併用戦略

脆弱性通知フロー時:
1. search_osv_vulnerabilities で最新の脆弱性情報取得
2. CVSSが「確定でない」なら get_nvd_cve_details
3. NVD結果が「古い」（published < 7日前）なら web_search で最新情報確認
4. 「悪用実績」の有無が不明なら Google News で検索

利点:
- 回答の根拠が強い
- 「3日前の情報」ではなく「今の状況」を捉える
- エージェント自身が情報の鮮度を判定
```

### 5.4 エラーリカバリ戦略の構築

#### 現状
```python
# chat_tools.py L438-444
except HttpError as http_err:
    msg = _format_http_error(http_err, space_id)
    logger.error(...)
    return {"status": "error", "message": msg}
```

**問題**: 通知失敗 → ユーザーに負担（手動で別チャネルで通知）

#### 改善案

```python
def send_vulnerability_alert_with_fallback(...):
    """通知送信（フォールバック対応）"""

    # Attempt 1: Chat カード形式で送信
    result = _send_chat_card(...)
    if result.get("status") == "sent":
        return result

    # Fallback 1: シンプルメッセージで送信
    if result.get("error_type") == "PERMISSION_DENIED":
        simple_result = send_simple_message(
            f"【緊急通知】{vulnerability_id}: {title}\n"
            f"担当者: {', '.join(owners or [])}\n"
            f"詳細は別途メールでお知らせします"
        )
        if simple_result.get("status") == "sent":
            # メールや Slack への二次通知を試みる
            return {
                "status": "partial_success",
                "primary": "failed",
                "fallback": "sent_via_simple_message",
                "message": "カード形式は失敗、シンプルメッセージで送信完了",
            }

    # Fallback 2: メール送信（設定済み場合）
    # ...

    # Fallback 3: 管理者への手動対応依頼
    return {
        "status": "failed_all_fallbacks",
        "message": "通知送信が全てのチャネルで失敗。管理者に連絡してください。",
        "manual_action_required": True,
    }
```

---

## 6. 優先度付き改善提案（3-5個）

### 優先度1: ツール群の統合と命名規則統一 ⭐⭐⭐

**対象**: A2A Tools（9個→5個化）、Granular（13個→6個化）、命名規則統一

**期待効果**:
- エージェント import list 削減: 56 → 40 ツール
- エージェント側の判定複雑度低減
- ツール学習コスト削減

**実装規模**: 中程度（2-3日）

**実装順序**:
1. A2A の登録・呼び出し統合
2. Granular の戦略的選別（頻用5個以外は削除）
3. 命名規則統一 (count_* → get_*_summary 等)

---

### 優先度2: システムプロンプトのポリシー統一と分離 ⭐⭐⭐

**対象**: 実行方式決定フロー（L196-218）、出力フォーマット（L177-188）

**期待効果**:
- エージェントの判定ロジック明確化
- 簡潔な回答を許容（過度な4セクション強制をやめる）
- 実行フローが一本化→自律性向上

**実装規模**: 小（プロンプト修正のみ）

**実装内容**:
```
# 修正案

L196-218 を以下で置き換え:
「実行方式判定: すべての依頼で decide_execution_mode() を呼ぶ
→ direct_tool: 既存ツールを細粒度で段階実行
→ codegen_with_tools: 複雑なワークフローを生成・実行」

L177-188 を以下で置き換え:
「応答形式は依頼の種類に応じて選択
- データ取得: 結論 + 根拠
- 判定: 結論 + 根拠 + 不確実性
- 行動: 結論 + 根拠 + 不確実性 + 次ア」
```

---

### 優先度3: Orchestration Tools の実装強化 ⭐⭐

**対象**: `decide_execution_mode` (粗い判定)、`generate_tool_workflow_code` (引数なしで実行不可)、`execute_tool_workflow_plan` (エラー対応が薄い)

**期待効果**:
- 複雑な処理の自動化率向上
- エラー時の自動リカバリ
- ワークフロー再利用性向上

**実装規模**: 大（実装 1-2週間）

**実装内容**:
1. `decide_execution_mode` に多次元複雑度判定
2. `generate_tool_workflow_code` で YAML/JSON ワークフロー出力
3. `execute_tool_workflow_plan` で条件分岐・リトライ対応

---

### 優先度4: A2A 連携のエラー分類と自動リカバリ ⭐⭐

**対象**: `call_remote_agent` のエラーハンドリング、継続対話停止判定

**期待効果**:
- 連携失敗時の対応が体系的に
- リソース見つからない場合の自動登録
- タイムアウト時の自動リトライ

**実装規模**: 中（1週間）

**実装内容**:
1. エラー分類スキーム (AGENT_NOT_REGISTERED / AUTH_FAILED / TIMEOUT etc)
2. エラー種別別の自動対応ロジック
3. 継続対話の停止判定を強化（セマンティック重複検知）

---

### 優先度5: フィードバックループと履歴ベースの自動追跡 ⭐

**対象**: 履歴ツール、スレッド管理、定期リマインド

**期待効果**:
- 対応状況の自動追跡
- エスカレーション対象の自動抽出
- ユーザーの手動操作削減

**実装規模**: 大（2-3週間）

**実装内容**:
1. incident_id の BigQuery 全件スキャン
2. 「期限切れ間近」「未解決 N日超過」の自動リマインド
3. 定期脆弱性トレンド分析と alert 生成

---

## まとめテーブル

| 改善項目 | 優先度 | 手間 | 効果 | 実装期間 |
|---------|--------|------|------|---------|
| ツール統合・命名統一 | P1 | 中 | ⭐⭐⭐ 高 | 2-3日 |
| プロンプト統一 | P1 | 小 | ⭐⭐⭐ 高 | 1日 |
| Orchestration 強化 | P3 | 大 | ⭐⭐ 中 | 1-2週 |
| A2A エラー対応 | P4 | 中 | ⭐⭐ 中 | 1週 |
| フィードバック追跡 | P5 | 大 | ⭐ 低 | 2-3週 |

---

## 付録: 具体的な実装ファイルマッピング

### 優先度1 実装対象

```
agent/agent.py
  - L13-67: import 削減 (Granular → 6個化、A2A → 5個化)

agent/tools/a2a_tools.py
  - register_master_agent() を register_agent(role="master") に統合
  - create_jira/approval/handoff_request → create_agent_request(type=...) に統合
  - call_master_agent() を call_agent(agent_id="master_agent", ...) に統合

agent/tools/granular_tools.py
  - 不要な13個中8個を削除
  - list_sbom_package_types, count_sbom_packages_by_type を get_sbom_package_type_summary に統合

agent/tools/sheets_tools.py
  - count_sbom_packages_by_type() を削除 → list_sbom_packages_by_type で count フィールド返却
```

### 優先度2 実装対象

```
agent/agent.py
  - L196-218: 実行方式決定フロー統一
  - L177-188: 応答フォーマット柔軟化
```

### 優先度3 実装対象

```
agent/tools/orchestration_tools.py
  - decide_execution_mode() → 多次元複雑度判定に変更
  - generate_tool_workflow_code() → YAML/JSON ワークフロー生成に変更
  - execute_tool_workflow_plan() → 条件分岐・リトライ対応に拡張
```

---

**分析完了 | 2026-02-21**
