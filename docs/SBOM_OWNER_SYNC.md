# SBOM / OwnerMapping 同期（Excel -> BigQuery）

## 目的
- `sbom_packages` の `release` 表記ゆれを正規化
- `owner_mapping` を Excel から同期
- 取り込み後の検証（件数/重複/欠損）を自動実行

## スクリプト
- `scripts/sync_sbom_owner_from_excel.py`

## 実行例
```bash
python scripts/sync_sbom_owner_from_excel.py \
  --xlsx-path "C:\Users\hikaruumeyama\Downloads\脆弱性管理対象一覧 .xlsx" \
  --project info-sec-ai-platform \
  --dataset vuln_agent \
  --load
```

`owner_mapping` を Excel ベースで置き換える場合:
```bash
python scripts/sync_sbom_owner_from_excel.py \
  --xlsx-path "C:\Users\hikaruumeyama\Downloads\脆弱性管理対象一覧 .xlsx" \
  --project info-sec-ai-platform \
  --dataset vuln_agent \
  --load \
  --owner-replace
```

## 現在の取り込み対象シート
- SBOM: `参考：Almalinux8(aws-zabbix)パッケージ一`
- OwnerMapping: `脆弱性管理 Windows PC`, `脆弱性管理 Windows PC 以外`

## 生成ファイル（ローカル）
- `tmp_local/sbom_packages_ref_alma8.jsonl`
- `tmp_local/owner_mapping_from_excel.jsonl`
- `tmp_local/bq_validation_report.txt`

## 検証項目
- `sbom_total`
- `sbom_al8_prefix_rows`
- `sbom_al8_release_bad_format`
- `sbom_missing_key_fields`
- `sbom_duplicate_rows`
- `owner_total`
- `owner_missing_pattern`
- `owner_duplicate_pattern`

