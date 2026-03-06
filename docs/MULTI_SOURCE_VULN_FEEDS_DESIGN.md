# マルチソース脆弱性インテリジェンス設計書

> 作成日: 2026-03-06
> ステータス: 承認済み・実装開始
> 目的: SIDfm 解約に伴い、複数のオープン/ベンダー脆弱性ソースへ移行

---

## 1. 背景と目的

### 現行の課題

- SIDfm は有償サービスであり、解約を予定
- 現行トリガーは「SIDfm通知メール → Gmail App → Google Chat → Workspace Events Webhook」
- 単一ソース依存のため、SIDfm がカバーしない製品・脆弱性を検知できない

### 新設計の目標

1. **オープンソースの脆弱性データベース** (CISA KEV / NVD / JVN / OSV) を主要ソースとする
2. **ベンダー固有ソース** (Cisco / Microsoft / Fortinet / AlmaLinux / Zabbix / MOTEX / SKYSEA) を補完ソースとする
3. **新規脆弱性が追加されたとき**をトリガーとし、Cloud Scheduler でポーリング
4. **ソース間の重複を CVE-ID ベースで排除**し、初回のみ処理する
5. 既存の SBOM 照合 → 担当者特定 → Chat 通知パイプラインは変更しない

---

## 2. 現行と新設計の比較

| 項目 | 現行 (SIDfm) | 新設計 (マルチソース) |
|------|-------------|---------------------|
| トリガー | SIDfm通知メール → Gmail App → Workspace Events | Cloud Scheduler → Poller → 各API定期ポーリング |
| ソース数 | 1 (SIDfm) | 4 共通 + 7 ベンダー = 11 ソース |
| 重複排除 | イベントレベルのみ (インメモリ) | CVE-ID + aliases ベースの永続排除 (BigQuery) |
| パース | SIDfmメール専用正規表現 | ソースごとアダプター → 共通スキーマ正規化 |
| SBOM照合 | 既存維持 | 既存維持 (変更なし) |
| 通知 | 既存維持 | 既存維持 (変更なし) |
| SBOM未該当 | 通知あり | ログのみ (通知しない) |

---

## 3. 全体アーキテクチャ

```
+-------------------------------------------------------------+
|                Cloud Scheduler (30分間隔)                      |
|                                                               |
|  +------+  +------+  +------+  +------+  +--------------+   |
|  |KEV   |  |NVD   |  |JVN   |  |OSV   |  |Vendor Feeds  |   |
|  |30min  |  |30min |  |1hour |  |30min |  |1-6hour       |   |
|  +--+---+  +--+---+  +--+---+  +--+---+  +------+-------+   |
+----+---------+---------+---------+---------------+-----------+
     |         |         |         |               |
     v         v         v         v               v
+-------------------------------------------------------------+
|          vuln_feed_poller (Cloud Function Gen2)               |
|                                                               |
|  +------------+  +----------------+  +-------------------+   |
|  | Source      |  | Normalizer     |  | Dedup Filter      |   |
|  | Adapters    |->| -> VulnEntry   |->| (BigQuery lookup) |   |
|  | (11)        |  |   共通スキーマ   |  |                   |   |
|  +------------+  +----------------+  +--------+----------+   |
+----------------------------------------------------+----------+
                                                     | 新規のみ
                                                     v
+-------------------------------------------------------------+
|                    Pub/Sub Topic                               |
|              (vuln-agent-new-vulnerabilities)                  |
+---------------------------+---------------------------------+
                            |
               +------------+------------+
               v                         v
+-----------------------+  +----------------------------------+
| vuln_intake_worker    |  | (将来) 他の消費者                  |
| (Cloud Function)      |  | - Slack通知 / Jira自動起票 等     |
|                       |  +----------------------------------+
| 1. SBOM照合           |
| 2. 該当あり -> 通知    |
|    該当なし -> ログのみ |
| 3. 履歴記録 (BQ)      |
+-----------------------+
```

---

## 4. 共通スキーマ

### 4.1 VulnEntry

全ソースから正規化された脆弱性エントリの共通データ構造。

```python
@dataclasses.dataclass
class AffectedProduct:
    vendor: str           # "Cisco", "Fortinet", "AlmaLinux" 等
    product: str          # "ASA", "FortiOS", "almalinux" 等
    versions: str         # 影響バージョン範囲 ("< 9.16.4" 等)
    cpe: str              # CPE 2.3 形式 (あれば)
    purl: str             # Package URL (あれば)

@dataclasses.dataclass
class VulnEntry:
    # --- 識別 ---
    vuln_id: str              # 主キー: CVE-2024-1234 / GHSA-xxxx / JVNDB-2024-xxxx
    aliases: list[str]        # 別名 (CVE <-> GHSA <-> JVN 間の相互参照)

    # --- メタデータ ---
    title: str
    description: str
    published: str            # ISO8601
    last_modified: str        # ISO8601
    source: str               # "cisa_kev" | "nvd" | "jvn" | "osv" | ...
    source_url: str           # 元情報のURL

    # --- スコアリング ---
    cvss_score: float | None
    cvss_vector: str | None
    severity: str             # "緊急" | "高" | "中" | "低"

    # --- 悪用情報 ---
    exploit_confirmed: bool   # KEVに掲載 or 明示的な悪用報告
    exploit_code_public: bool # PoCコード公開済み
    kev_due_date: str | None  # CISA KEVの対応期限 (あれば)

    # --- 影響製品 ---
    affected_products: list[AffectedProduct]

    # --- ベンダー固有 ---
    vendor_advisory_id: str | None  # FG-IR-2024-xxxx, cisco-sa-xxxx 等
    vendor_severity: str | None     # ベンダー独自重大度
    vendor_fixed_versions: list[str]
```

### 4.2 重大度マッピング

既存の chat_tools.py のルールと同一:

| CVSS | severity |
|------|----------|
| >= 9.0 | 緊急 |
| >= 7.0 | 高 |
| >= 4.0 | 中 |
| < 4.0 or 不明 | 低 |

---

## 5. ソースアダプター設計

### 5.1 アダプターインターフェース

```python
class BaseSourceAdapter(Protocol):
    source_id: str
    default_poll_interval_minutes: int

    def fetch_recent(self, since: datetime) -> list[VulnEntry]:
        """指定時刻以降の新規・更新エントリを取得"""
        ...
```

### 5.2 ソース一覧

| # | ソース | adapter | 間隔 | API/形式 | APIキー | フィルタ |
|---|--------|---------|------|---------|---------|---------|
| 1 | CISA KEV | `CisaKevAdapter` | 30分 | JSON catalog | 不要 | 全件 (悪用確認済み) |
| 2 | NIST NVD | `NvdAdapter` | 30分 | REST v2.0 | あり (取得する) | `lastModStartDate` 差分 |
| 3 | JVN iPedia | `JvnAdapter` | 1時間 | MyJVN API (XML) | 不要 | `datePublicStartY` 差分 |
| 4 | OSV.dev | `OsvAdapter` | 30分 | REST POST | 不要 | SBOM ecosystem で絞込 |
| 5 | Cisco CSAF | `CiscoCsafAdapter` | 1時間 | openVuln API | OAuth2 Client Credentials | ASA 関連のみ |
| 6 | MSRC CSAF | `MsrcAdapter` | 1時間 | MSRC API / CSAF | API Key | Windows/Exchange 等 |
| 7 | Fortinet PSIRT | `FortinetAdapter` | 1時間 | RSS XML | 不要 | FortiOS/FortiGate |
| 8 | AlmaLinux Errata | `AlmaLinuxAdapter` | 1時間 | errata.full.json | 不要 | 全件 (SBOM照合で絞込) |
| 9 | Zabbix | `ZabbixAdapter` | 6時間 | Playwright監視 | 不要 | 固定URL |
| 10 | MOTEX | `MotexAdapter` | 6時間 | Playwright監視 | 不要 | キーワードフィルタ |
| 11 | SKYSEA | `SkySEAAdapter` | 6時間 | Playwright監視 | 不要 | 固定URL |

### 5.3 スクレイピング系 (Zabbix / MOTEX / SKYSEA) の設計

HTMLスクレイピングは構造変更に脆弱なため、**Playwright + AI 解析**方式を採用する。

```
Cloud Scheduler (6時間ごと)
  -> vuln_feed_poller (source=zabbix,motex,skysea)
     -> Playwright (ヘッドレスChromium) でページ取得
     -> ページHTML/テキストを Gemini Flash に投入
     -> 「脆弱性アドバイザリ情報を抽出して」とプロンプト
     -> 構造化 JSON (VulnEntry相当) として返却
     -> 通常の dedup -> Pub/Sub フローへ
```

利点:
- HTML構造変更に対してロバスト (AI が意味を理解して抽出)
- CSS セレクタのメンテナンスが不要
- ページ構造変更時も自動で適応する可能性が高い

実装: Cloud Function に Playwright を含めると重いため、**専用の Cloud Run サービス** (`vuln-scraper`) として分離する。

```
vuln_feed_poller (Cloud Function)
  -> HTTP呼び出し -> vuln-scraper (Cloud Run + Playwright)
                     -> ヘッドレスブラウザでページ取得
                     -> Gemini Flash で構造化抽出
                     <- VulnEntry[] を返却
```

### 5.4 APIキー管理

| ソース | シークレット名 | 取得方法 |
|--------|-------------|---------|
| NVD | `vuln-agent-nvd-api-key` | https://nvd.nist.gov/developers/request-an-api-key |
| Cisco | `vuln-agent-cisco-client-id` / `vuln-agent-cisco-client-secret` | Cisco DevNet API Console |
| MSRC | `vuln-agent-msrc-api-key` | Microsoft Security Response Center |

全て Secret Manager に保存。vuln_feed_poller がランタイムで読み取る。

---

## 6. 重複排除設計

### 6.1 BigQuery テーブル: vuln_dedup

```sql
CREATE TABLE IF NOT EXISTS `{project}.{dataset}.vuln_dedup` (
  vuln_id         STRING NOT NULL,
  aliases         ARRAY<STRING>,
  first_source    STRING NOT NULL,
  first_seen_at   TIMESTAMP NOT NULL,
  sources_seen    ARRAY<STRING>,
  last_updated_at TIMESTAMP NOT NULL,
  processed       BOOL DEFAULT FALSE,
  sbom_matched    BOOL DEFAULT FALSE,
  skip_reason     STRING
)
PARTITION BY DATE(first_seen_at)
CLUSTER BY vuln_id;
```

### 6.2 重複排除ロジック

```
入力: VulnEntry

1. vuln_id を正規化 (大文字化: CVE-2024-1234)
2. vuln_dedup を検索: vuln_id OR ANY alias IN aliases
   -> ヒットあり:
      - sources_seen に現ソースを追加
      - last_updated_at を更新
      - ログ: "重複検知: {vuln_id} (既知ソース: {first_source})"
      - return SKIP
   -> ヒットなし:
      - INSERT (vuln_id, aliases, first_source, ...)
      - Pub/Sub に publish
      - return NEW
3. alias の相互解決:
   NVD から CVE-2024-1234 (aliases: [GHSA-xxxx])
   -> vuln_dedup に CVE-2024-1234 を登録
   OSV から GHSA-xxxx (aliases: [CVE-2024-1234])
   -> vuln_dedup 検索: CVE-2024-1234 がヒット -> SKIP
```

### 6.3 BigQuery テーブル: vuln_poll_state

```sql
CREATE TABLE IF NOT EXISTS `{project}.{dataset}.vuln_poll_state` (
  source_id       STRING NOT NULL,
  last_poll_at    TIMESTAMP NOT NULL,
  last_success_at TIMESTAMP,
  last_cursor     STRING,
  items_fetched   INT64 DEFAULT 0,
  items_new       INT64 DEFAULT 0,
  error_message   STRING
);
```

各アダプターはポーリング時に `last_cursor` を参照して差分取得し、完了後に更新する。

---

## 7. vuln_intake_worker 処理フロー

```
Pub/Sub メッセージ受信 (VulnEntry JSON)
  |
  +- 1. VulnEntry をデシリアライズ
  |
  +- 2. affected_products から SBOM 照合
  |     - AffectedProduct.purl があれば search_sbom_by_purl()
  |     - なければ product + version で search_sbom_by_product()
  |     - 該当なし -> vuln_dedup.sbom_matched=false, ログ記録, 終了
  |
  +- 3. 該当あり -> 既存パイプライン呼出
  |     - 担当者マッピング (_find_owner_for_purl)
  |     - 期限計算 (DEADLINE_RULES)
  |     - Chat通知送信 (send_vulnerability_alert)
  |
  +- 4. 履歴記録 (log_vulnerability_history)
  |     - source フィールドに "vuln_feed:{source_id}" を記録
  |
  +- 5. vuln_dedup 更新
        - processed=true, sbom_matched=true
```

SBOM未該当の場合は通知せず、ログのみ残す。

---

## 8. ディレクトリ構成 (追加分)

```
vuln-agent/
+-- vuln_feeds/                         # 脆弱性フィードポーラー (Cloud Function)
|   +-- main.py                         #   エントリーポイント
|   +-- requirements.txt
|   +-- adapters/                       #   ソースアダプター群
|   |   +-- __init__.py
|   |   +-- base.py                     #     BaseSourceAdapter + 共通ユーティリティ
|   |   +-- cisa_kev.py
|   |   +-- nvd.py
|   |   +-- jvn.py
|   |   +-- osv.py
|   |   +-- cisco_csaf.py
|   |   +-- msrc.py
|   |   +-- fortinet.py
|   |   +-- almalinux.py
|   |   +-- zabbix.py
|   |   +-- motex.py
|   |   +-- skysea.py
|   |   +-- scraper_client.py           #     vuln-scraper Cloud Run 呼出クライアント
|   +-- dedup.py                        #   BigQuery 重複排除
|   +-- poll_state.py                   #   ポーリング状態管理
|   +-- publisher.py                    #   Pub/Sub publish
|
+-- vuln_intake/                        # 脆弱性取り込みワーカー (Cloud Function)
|   +-- main.py                         #   エントリーポイント (Pub/Sub trigger)
|   +-- requirements.txt
|   +-- processor.py                    #   SBOM照合 -> Agent呼出 -> 通知
|
+-- vuln_scraper/                       # Playwright + AI スクレイパー (Cloud Run)
|   +-- app.py                          #   FastAPI エントリーポイント
|   +-- Dockerfile
|   +-- requirements.txt
|   +-- scraper.py                      #   Playwright ページ取得 + AI 抽出
|
+-- shared/
|   +-- vuln_schema.py                  #   VulnEntry / AffectedProduct 共通定義
|   +-- ...                             #   既存ファイル維持
```

---

## 9. Cloud Scheduler 構成

```yaml
# 共通ソース (30分間隔)
- name: poll-cisa-kev
  schedule: "*/30 * * * *"
  httpTarget:
    uri: https://{region}-{project}.cloudfunctions.net/vuln-feed-poller
    body: '{"sources": ["cisa_kev"]}'
    oidcToken:
      serviceAccountEmail: vuln-agent-sa@{project}.iam.gserviceaccount.com

- name: poll-nvd
  schedule: "*/30 * * * *"
  httpTarget:
    uri: https://{region}-{project}.cloudfunctions.net/vuln-feed-poller
    body: '{"sources": ["nvd"]}'

- name: poll-osv
  schedule: "*/30 * * * *"
  httpTarget:
    uri: https://{region}-{project}.cloudfunctions.net/vuln-feed-poller
    body: '{"sources": ["osv"]}'

# JVN + ベンダーAPI (1時間間隔)
- name: poll-jvn-vendor-api
  schedule: "0 * * * *"
  httpTarget:
    uri: https://{region}-{project}.cloudfunctions.net/vuln-feed-poller
    body: '{"sources": ["jvn", "cisco_csaf", "msrc", "fortinet", "almalinux"]}'

# スクレイピング系 (6時間間隔)
- name: poll-vendor-scrape
  schedule: "0 */6 * * *"
  httpTarget:
    uri: https://{region}-{project}.cloudfunctions.net/vuln-feed-poller
    body: '{"sources": ["zabbix", "motex", "skysea"]}'
```

---

## 10. 既存コードへの影響

| コンポーネント | 変更内容 |
|--------------|---------|
| `agent/tools/vuln_intel_tools.py` | 変更なし (オンデマンド参照用として維持) |
| `agent/tools/sheets_tools.py` | 変更なし (SBOM照合は vuln_intake から shared 経由で利用) |
| `agent/tools/chat_tools.py` | 変更なし (通知送信は vuln_intake から利用) |
| `agent/tools/history_tools.py` | 変更なし (履歴記録は vuln_intake から利用) |
| `workspace_events_webhook/` | Gmail監視トリガーを段階的に廃止。リアクション(?)トリガーは維持 |
| `shared/ticket_parsers.py` | SIDfm 固有パース関数は非推奨化 (互換性のため残す) |
| `shared/ticket_pipeline.py` | vuln_intake から呼び出すための薄いラッパー追加 |
| `cloudbuild.yaml` | vuln_feeds / vuln_intake / vuln_scraper のデプロイステップ追加 |

---

## 11. CI/CD (cloudbuild.yaml 拡張)

```yaml
# 差分検知の追加
vuln_feeds/*              -> DEPLOY_VULN_FEEDS=true
vuln_intake/*             -> DEPLOY_VULN_INTAKE=true
vuln_scraper/*            -> DEPLOY_VULN_SCRAPER=true
shared/vuln_schema.py     -> DEPLOY_VULN_FEEDS=true, DEPLOY_VULN_INTAKE=true

# デプロイステップ
- vuln_feed_poller: gcloud functions deploy (Cloud Function Gen2)
- vuln_intake_worker: gcloud functions deploy (Cloud Function Gen2, Pub/Sub trigger)
- vuln_scraper: gcloud run deploy (Cloud Run, Playwright + Chromium)
```

---

## 12. 実装ロードマップ

### Phase 1: 基盤構築 (1-2週間)

```
[x] 設計書作成 (本ドキュメント)
[ ] shared/vuln_schema.py (VulnEntry / AffectedProduct 定義)
[ ] BigQuery テーブル作成スクリプト (vuln_dedup, vuln_poll_state)
[ ] vuln_feeds/ 骨格
    - main.py (Cloud Function エントリーポイント)
    - adapters/base.py (BaseSourceAdapter)
    - dedup.py (重複排除)
    - poll_state.py (ポーリング状態管理)
    - publisher.py (Pub/Sub publish)
[ ] CISA KEV アダプター (最もシンプル: JSON直接取得)
[ ] NVD アダプター (既存 vuln_intel_tools.py のコード再利用)
[ ] vuln_intake/ 骨格
    - main.py (Pub/Sub trigger)
    - processor.py (SBOM照合 -> 通知)
```

### Phase 2: 主要ソース追加 (1-2週間)

```
[ ] JVN iPedia アダプター
[ ] OSV.dev アダプター (既存コード再利用)
[ ] Cloud Scheduler 設定
[ ] Pub/Sub トピック作成
[ ] 結合テスト (ポーラー -> dedup -> Pub/Sub -> intake -> 通知)
```

### Phase 3: ベンダーソース追加 (1-2週間)

```
[ ] Cisco CSAF アダプター
[ ] MSRC アダプター
[ ] Fortinet PSIRT アダプター
[ ] AlmaLinux Errata アダプター
```

### Phase 4: スクレイピング系 + 切替 (1週間)

```
[ ] vuln_scraper/ Cloud Run サービス (Playwright + Gemini Flash)
[ ] Zabbix / MOTEX / SKYSEA アダプター
[ ] SIDfm Gmail監視の停止 (workspace_events_webhook の Gmail トリガー無効化)
[ ] 運用ドキュメント更新
```

---

## 13. 判断記録 (Decision Log)

| # | 判断 | 採択案 | 棄却案 | 理由 |
|---|------|--------|--------|------|
| D1 | ポーリング間隔 | 全ソース30分 (スクレイピング系6時間) | ソースごとに個別設定 | 運用のシンプルさ優先 |
| D2 | 重複排除 | BigQuery永続テーブル | インメモリキャッシュ | 再起動耐性、監査可能性 |
| D3 | スクレイピング | Playwright + AI (Gemini Flash) | CSSセレクタ固定 | HTML構造変更へのロバスト性 |
| D4 | SBOM未該当 | ログのみ (通知しない) | 重要度高は通知 | ノイズ削減。必要なら後から変更可能 |
| D5 | APIキー | 取得して使う (NVD/Cisco/MSRC) | キーなし運用 | レート制限緩和、安定性向上 |
| D6 | スクレイパー実行基盤 | 専用 Cloud Run | Cloud Function内蔵 | Playwright + Chromiumが重いため分離 |
| D7 | メッセージング | Pub/Sub | 直接呼び出し | 疎結合、将来の消費者追加に対応 |

---

## 14. リスクマトリクス

| リスク | 発生確率 | 影響度 | 対策 |
|--------|----------|--------|------|
| NVD API レート制限 | 低 (APIキーあり) | 中 | APIキー取得、指数バックオフ |
| ベンダーAPI仕様変更 | 中 | 中 | アダプターパターンで変更を局所化 |
| スクレイピング対象サイト構造変更 | 中 | 低 | AI解析で吸収。失敗時はアラート |
| 大量の新規CVE同時公開 | 低 | 中 | Pub/Subバッファリング、バッチ処理 |
| 重複排除の alias 不整合 | 低 | 低 | 定期的な alias 再マッチジョブ |
