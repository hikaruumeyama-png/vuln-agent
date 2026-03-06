-- =============================================================
-- マルチソース脆弱性フィード用 BigQuery テーブル作成
-- =============================================================
-- 使い方:
--   bq query --use_legacy_sql=false < scripts/create_vuln_feed_tables.sql
--
-- 前提:
--   データセットは事前に作成済みであること。
--   環境に合わせて PROJECT_ID.DATASET を置換すること。
-- =============================================================

-- ----- 1. 重複排除テーブル (vuln_dedup) -----
CREATE TABLE IF NOT EXISTS `PROJECT_ID.DATASET.vuln_dedup` (
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
CLUSTER BY vuln_id
OPTIONS (
  description = '脆弱性フィード重複排除テーブル。CVE-ID + aliases で一意性を管理。'
);


-- ----- 2. ポーリング状態テーブル (vuln_poll_state) -----
CREATE TABLE IF NOT EXISTS `PROJECT_ID.DATASET.vuln_poll_state` (
  source_id       STRING NOT NULL,
  last_poll_at    TIMESTAMP NOT NULL,
  last_success_at TIMESTAMP,
  last_cursor     STRING,
  items_fetched   INT64 DEFAULT 0,
  items_new       INT64 DEFAULT 0,
  error_message   STRING
)
OPTIONS (
  description = '各脆弱性ソースのポーリング状態管理テーブル。'
);
