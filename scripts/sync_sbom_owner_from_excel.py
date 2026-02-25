#!/usr/bin/env python3
"""
Excel -> BigQuery sync utility for vuln-agent.

Implements:
1) release normalization for almalinux8 rows in sbom_packages
2) owner_mapping enrichment from Excel sheets
3) post-load validation checks

No external Python dependencies are required.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def _resolve_bq_bin(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for cand in ("bq", "bq.cmd"):
        found = shutil.which(cand)
        if found:
            return found
    fallback = Path(r"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\bq.cmd")
    if fallback.exists():
        return str(fallback)
    raise FileNotFoundError("bq executable not found. Set --bq-bin explicitly.")


def _bq(bq_bin: str, query: str) -> str:
    proc = subprocess.run(
        [bq_bin, "query", "--use_legacy_sql=false"],
        input=query,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"bq query failed (exit={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}\nQUERY:\n{query}"
        )
    return proc.stdout


def _col_to_idx(col: str) -> int:
    n = 0
    for ch in col:
        if ch.isalpha():
            n = n * 26 + ord(ch.upper()) - 64
    return n - 1


def _load_workbook(xlsx_path: Path) -> Tuple[zipfile.ZipFile, List[str], Dict[str, str]]:
    zf = zipfile.ZipFile(xlsx_path)
    shared: List[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        sst = ET.fromstring(zf.read("xl/sharedStrings.xml"))
        for si in sst.findall(f"{{{NS_MAIN}}}si"):
            text = "".join(t.text or "" for t in si.iter(f"{{{NS_MAIN}}}t"))
            shared.append(text)

    wb = ET.fromstring(zf.read("xl/workbook.xml"))
    rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rid_to_target = {r.attrib["Id"]: r.attrib["Target"] for r in rels}
    sheet_to_xml: Dict[str, str] = {}
    for s in wb.findall(f".//{{{NS_MAIN}}}sheet"):
        rid = s.attrib[f"{{{NS_REL}}}id"]
        sheet_to_xml[s.attrib["name"]] = "xl/" + rid_to_target[rid]

    return zf, shared, sheet_to_xml


def _sheet_rows(zf: zipfile.ZipFile, shared: List[str], xml_path: str) -> List[List[str]]:
    root = ET.fromstring(zf.read(xml_path))
    out: List[List[str]] = []
    for row in root.findall(f".//{{{NS_MAIN}}}row"):
        vals: Dict[int, str] = {}
        for cell in row.findall(f"{{{NS_MAIN}}}c"):
            ref = cell.attrib.get("r", "A1")
            col = "".join(ch for ch in ref if ch.isalpha())
            idx = _col_to_idx(col)
            ctype = cell.attrib.get("t")
            val = ""
            if ctype == "s":
                v = cell.find(f"{{{NS_MAIN}}}v")
                if v is not None and v.text and v.text.isdigit():
                    i = int(v.text)
                    if 0 <= i < len(shared):
                        val = shared[i]
            elif ctype == "inlineStr":
                isel = cell.find(f"{{{NS_MAIN}}}is")
                if isel is not None:
                    val = "".join(t.text or "" for t in isel.iter(f"{{{NS_MAIN}}}t"))
            else:
                v = cell.find(f"{{{NS_MAIN}}}v")
                if v is not None and v.text:
                    val = v.text
            vals[idx] = val.strip()
        if vals:
            max_i = max(vals)
            out.append([vals.get(i, "") for i in range(max_i + 1)])
    return out


def _normalize_header(s: str) -> str:
    return re.sub(r"\s+", "", (s or "").strip().lower())


def _find_header_index(rows: List[List[str]], required: Iterable[str]) -> int:
    req = [_normalize_header(x) for x in required]
    for i, row in enumerate(rows):
        hs = [_normalize_header(c) for c in row]
        if all(any(r in h for h in hs) for r in req):
            return i
    return -1


def _sbom_from_sheet(rows: List[List[str]]) -> List[Dict[str, str]]:
    header_idx = _find_header_index(rows, ["componentname", "version", "architecture"])
    if header_idx < 0:
        return []
    header = rows[header_idx]
    idx_name = idx_ver = idx_arch = idx_purl = -1
    for i, h in enumerate(header):
        n = _normalize_header(h)
        if "componentname" in n:
            idx_name = i
        elif n == "version":
            idx_ver = i
        elif "architecture" in n:
            idx_arch = i
        elif n == "purl":
            idx_purl = i
    if min(idx_name, idx_ver, idx_arch) < 0:
        return []

    out: List[Dict[str, str]] = []
    for row in rows[header_idx + 1 :]:
        name = row[idx_name].strip() if idx_name < len(row) else ""
        ver = row[idx_ver].strip() if idx_ver < len(row) else ""
        arch = row[idx_arch].strip().lower() if idx_arch < len(row) else ""
        purl = row[idx_purl].strip() if (idx_purl >= 0 and idx_purl < len(row)) else ""
        if not name:
            continue
        arch = arch if arch in {"x86_64", "aarch64", "noarch", "src"} else "unknown"
        release = f"almalinux8:{arch}"
        if not purl:
            safe_ver = ver or "unknown"
            purl = f"pkg:rpm/almalinux/{name}@{safe_ver}?arch={arch}"
        out.append(
            {
                "type": "rpm",
                "name": name,
                "version": ver,
                "release": release,
                "purl": purl,
                "os_name": "almalinux",
                "os_version": "8",
                "arch": arch,
            }
        )
    dedup = {(r["type"], r["name"], r["version"], r["release"], r["purl"]): r for r in out}
    return list(dedup.values())


def _owner_from_sheet(rows: List[List[str]], source_sheet: str) -> List[Dict[str, str]]:
    header_idx = _find_header_index(rows, ["no.", "システム", "部署"])
    if header_idx < 0:
        return []
    header = rows[header_idx]
    idx_sys = idx_dep = -1
    for i, h in enumerate(header):
        if "システム" in h:
            idx_sys = i
        elif "部署" in h:
            idx_dep = i
    if min(idx_sys, idx_dep) < 0:
        return []

    out: List[Dict[str, str]] = []
    for row in rows[header_idx + 1 :]:
        sys_name = row[idx_sys].strip() if idx_sys < len(row) else ""
        dep = row[idx_dep].strip() if idx_dep < len(row) else ""
        if not sys_name or sys_name == "Fortigate":
            continue
        pattern = re.sub(r"\s+", " ", sys_name).strip().lower()
        if not pattern:
            continue
        priority = 9999 if pattern == "*" else max(1, 1000 - len(pattern))
        out.append(
            {
                "pattern": pattern,
                "system_name": sys_name,
                "owner_email": "",
                "owner_name": dep,
                "notes": f"source:{source_sheet}",
                "priority": priority,
            }
        )
    dedup = {
        (r["pattern"], r["system_name"], r["owner_email"], r["owner_name"], r["notes"]): r
        for r in out
    }
    return list(dedup.values())


def _write_jsonl(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _load_table(
    bq_bin: str, project: str, dataset: str, table: str, jsonl: Path, schema: str
) -> None:
    tmp = f"{project}:{dataset}.{table}"
    _run([bq_bin, "rm", "-f", "-t", tmp], check=False)
    _run(
        [
            bq_bin,
            "load",
            "--source_format=NEWLINE_DELIMITED_JSON",
            tmp,
            str(jsonl),
            schema,
        ]
    )


def _run_sync(
    bq_bin: str,
    project: str,
    dataset: str,
    sbom_table: str,
    owner_table: str,
    sbom_tmp: str,
    owner_tmp: str,
    owner_replace: bool,
) -> None:
    _bq(
        bq_bin,
        f"""
MERGE `{project}.{dataset}.{sbom_table}` t
USING `{project}.{dataset}.{sbom_tmp}` s
ON t.type=s.type
  AND t.name=s.name
  AND t.version=s.version
  AND t.release=s.release
  AND IFNULL(t.purl,'')=IFNULL(s.purl,'')
WHEN MATCHED THEN UPDATE SET
  os_name=s.os_name,
  os_version=s.os_version,
  arch=s.arch
WHEN NOT MATCHED THEN
  INSERT(type,name,version,release,purl,os_name,os_version,arch)
  VALUES(s.type,s.name,s.version,s.release,s.purl,s.os_name,s.os_version,s.arch)
"""
    )

    _bq(
        bq_bin,
        f"""
UPDATE `{project}.{dataset}.{sbom_table}`
SET
  release = CASE
    WHEN STARTS_WITH(LOWER(IFNULL(release,'')), 'almalinux8') THEN CONCAT(
      'almalinux8:',
      COALESCE(REGEXP_EXTRACT(LOWER(IFNULL(release,'')), r'(x86_64|aarch64|noarch|src)'), 'unknown')
    )
    WHEN type='rpm' AND REGEXP_CONTAINS(LOWER(IFNULL(purl,'')), r'^pkg:rpm/almalinux/') THEN CONCAT(
      'almalinux8:',
      COALESCE(REGEXP_EXTRACT(LOWER(IFNULL(purl,'')), r'arch=([a-z0-9_]+)'), 'unknown')
    )
    ELSE release
  END,
  purl = CASE
    WHEN type='rpm'
      AND (purl IS NULL OR TRIM(purl)='')
      AND STARTS_WITH(LOWER(IFNULL(release,'')), 'almalinux8:')
      AND name IS NOT NULL AND TRIM(name)!=''
    THEN CONCAT(
      'pkg:rpm/almalinux/',
      name,
      '@',
      IFNULL(NULLIF(TRIM(version), ''), 'unknown'),
      '?arch=',
      IFNULL(NULLIF(REGEXP_EXTRACT(LOWER(release), r'^almalinux8:([a-z0-9_]+)$'), ''), 'unknown')
    )
    ELSE purl
  END
WHERE STARTS_WITH(LOWER(IFNULL(release,'')), 'almalinux8')
   OR (type='rpm' AND REGEXP_CONTAINS(LOWER(IFNULL(purl,'')), r'^pkg:rpm/almalinux/'))
"""
    )

    _bq(
        bq_bin,
        f"""
CREATE OR REPLACE TABLE `{project}.{dataset}.{sbom_table}` AS
SELECT type, name, version, release, purl, os_name, os_version, arch
FROM (
  SELECT
    type, name, version, release, purl, os_name, os_version, arch,
    ROW_NUMBER() OVER (
      PARTITION BY type, name, version, release, purl
      ORDER BY type
    ) AS rn
  FROM `{project}.{dataset}.{sbom_table}`
)
WHERE rn = 1
"""
    )

    if owner_replace:
        _bq(bq_bin, f"DELETE FROM `{project}.{dataset}.{owner_table}` WHERE TRUE")

    _bq(
        bq_bin,
        f"""
MERGE `{project}.{dataset}.{owner_table}` t
USING (
  SELECT
    pattern,
    system_name,
    ANY_VALUE(owner_email) AS owner_email,
    ANY_VALUE(owner_name) AS owner_name,
    STRING_AGG(DISTINCT notes, ' / ') AS notes,
    MIN(priority) AS priority
  FROM `{project}.{dataset}.{owner_tmp}`
  GROUP BY pattern, system_name
) s
ON t.pattern=s.pattern
  AND IFNULL(t.system_name,'')=IFNULL(s.system_name,'')
WHEN MATCHED THEN UPDATE SET
  owner_email=s.owner_email,
  owner_name=s.owner_name,
  notes=s.notes,
  priority=s.priority
WHEN NOT MATCHED THEN
  INSERT(pattern,system_name,owner_email,owner_name,notes,priority)
  VALUES(s.pattern,s.system_name,s.owner_email,s.owner_name,s.notes,s.priority)
"""
    )

    _bq(
        bq_bin,
        f"""
CREATE OR REPLACE TABLE `{project}.{dataset}.{owner_table}` AS
SELECT pattern, system_name, owner_email, owner_name, notes, priority
FROM (
  SELECT
    pattern, system_name, owner_email, owner_name, notes, priority,
    ROW_NUMBER() OVER (
      PARTITION BY pattern, system_name
      ORDER BY
        IFNULL(owner_email,'') DESC,
        IFNULL(owner_name,'') DESC,
        IFNULL(notes,'') DESC
    ) AS rn
  FROM `{project}.{dataset}.{owner_table}`
)
WHERE rn = 1
"""
    )


def _run_validations(
    bq_bin: str, project: str, dataset: str, sbom_table: str, owner_table: str
) -> str:
    q = f"""
SELECT 'sbom_total' AS check_name, CAST(COUNT(*) AS STRING) AS value
FROM `{project}.{dataset}.{sbom_table}`
UNION ALL
SELECT 'sbom_al8_prefix_rows', CAST(COUNTIF(STARTS_WITH(LOWER(IFNULL(release,'')), 'almalinux8')) AS STRING)
FROM `{project}.{dataset}.{sbom_table}`
UNION ALL
SELECT 'sbom_al8_release_bad_format', CAST(COUNTIF(STARTS_WITH(LOWER(IFNULL(release,'')), 'almalinux8')
  AND NOT REGEXP_CONTAINS(LOWER(release), r'^almalinux8:(x86_64|aarch64|noarch|src|unknown)$')) AS STRING)
FROM `{project}.{dataset}.{sbom_table}`
UNION ALL
SELECT 'sbom_missing_key_fields', CAST(COUNTIF(type IS NULL OR TRIM(type)='' OR name IS NULL OR TRIM(name)='' OR release IS NULL OR TRIM(release)='') AS STRING)
FROM `{project}.{dataset}.{sbom_table}`
UNION ALL
SELECT 'sbom_duplicate_rows', CAST(SUM(cnt - 1) AS STRING)
FROM (
  SELECT COUNT(*) AS cnt
  FROM `{project}.{dataset}.{sbom_table}`
  GROUP BY type,name,version,release,purl
  HAVING COUNT(*) > 1
)
UNION ALL
SELECT 'owner_total', CAST(COUNT(*) AS STRING)
FROM `{project}.{dataset}.{owner_table}`
UNION ALL
SELECT 'owner_missing_pattern', CAST(COUNTIF(pattern IS NULL OR TRIM(pattern)='') AS STRING)
FROM `{project}.{dataset}.{owner_table}`
UNION ALL
SELECT 'owner_duplicate_pattern', CAST(SUM(cnt - 1) AS STRING)
FROM (
  SELECT COUNT(*) AS cnt
  FROM `{project}.{dataset}.{owner_table}`
  GROUP BY pattern,system_name
  HAVING COUNT(*) > 1
)
"""
    q = q.replace("CAST(SUM(cnt - 1) AS STRING)", "CAST(COALESCE(SUM(cnt - 1), 0) AS STRING)")
    return _bq(bq_bin, q)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--xlsx-path", required=True)
    p.add_argument("--project", default="info-sec-ai-platform")
    p.add_argument("--dataset", default="vuln_agent")
    p.add_argument("--sbom-table", default="sbom_packages")
    p.add_argument("--owner-table", default="owner_mapping")
    p.add_argument(
        "--sbom-sheet",
        default="参考：Almalinux8(aws-zabbix)パッケージ一",
        help="SBOM source sheet name",
    )
    p.add_argument(
        "--owner-sheets",
        default="脆弱性管理 Windows PC,脆弱性管理 Windows PC 以外",
        help="Comma separated owner source sheets",
    )
    p.add_argument("--out-dir", default="tmp_local")
    p.add_argument("--bq-bin", default=None, help="Path to bq executable")
    p.add_argument("--load", action="store_true")
    p.add_argument("--owner-replace", action="store_true")
    args = p.parse_args()

    xlsx = Path(args.xlsx_path)
    if not xlsx.exists():
        print(f"[ERROR] xlsx not found: {xlsx}", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir)
    sbom_jsonl = out_dir / "sbom_packages_ref_alma8.jsonl"
    owner_jsonl = out_dir / "owner_mapping_from_excel.jsonl"

    zf, shared, sheet_to_xml = _load_workbook(xlsx)
    try:
        if args.sbom_sheet not in sheet_to_xml:
            print(f"[ERROR] sheet not found: {args.sbom_sheet}", file=sys.stderr)
            return 2
        sbom_rows = _sheet_rows(zf, shared, sheet_to_xml[args.sbom_sheet])
        sbom_records = _sbom_from_sheet(sbom_rows)
        _write_jsonl(sbom_jsonl, sbom_records)

        owner_records: List[Dict[str, str]] = []
        for sname in [s.strip() for s in args.owner_sheets.split(",") if s.strip()]:
            if sname not in sheet_to_xml:
                continue
            rows = _sheet_rows(zf, shared, sheet_to_xml[sname])
            owner_records.extend(_owner_from_sheet(rows, sname))
        owner_dedup = {
            (r["pattern"], r["system_name"], r["owner_email"], r["owner_name"], r["notes"]): r
            for r in owner_records
        }
        owner_records = list(owner_dedup.values())
        _write_jsonl(owner_jsonl, owner_records)
    finally:
        zf.close()

    print(f"sbom_jsonl={sbom_jsonl} rows={len(sbom_records)}")
    print(f"owner_jsonl={owner_jsonl} rows={len(owner_records)}")

    bq_bin = _resolve_bq_bin(args.bq_bin)

    if not args.load:
        print("load=skipped (--load not specified)")
        return 0

    sbom_tmp = "sbom_sync_tmp"
    owner_tmp = "owner_sync_tmp"
    _load_table(
        bq_bin,
        args.project,
        args.dataset,
        sbom_tmp,
        sbom_jsonl,
        "type:STRING,name:STRING,version:STRING,release:STRING,purl:STRING,os_name:STRING,os_version:STRING,arch:STRING",
    )
    _load_table(
        bq_bin,
        args.project,
        args.dataset,
        owner_tmp,
        owner_jsonl,
        "pattern:STRING,system_name:STRING,owner_email:STRING,owner_name:STRING,notes:STRING,priority:INTEGER",
    )

    _run_sync(
        bq_bin,
        args.project,
        args.dataset,
        args.sbom_table,
        args.owner_table,
        sbom_tmp,
        owner_tmp,
        args.owner_replace,
    )
    report = _run_validations(
        bq_bin, args.project, args.dataset, args.sbom_table, args.owner_table
    )
    report_path = out_dir / "bq_validation_report.txt"
    report_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"validation_report={report_path}")

    _run(
        [bq_bin, "rm", "-f", "-t", f"{args.project}:{args.dataset}.{sbom_tmp}"],
        check=False,
    )
    _run(
        [bq_bin, "rm", "-f", "-t", f"{args.project}:{args.dataset}.{owner_tmp}"],
        check=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
