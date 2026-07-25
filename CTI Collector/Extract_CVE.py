import csv
import json
import os
import sys
import time
import argparse
import concurrent.futures as cf
from pathlib import Path

TAG_PRIORITY = {
    "patch": (1, "Patch"),
    "vendor-advisory": (2, "Vendor Advisory"),
    "mitigation": (3, "Mitigation"),
    "release-notes": (4, "Release Notes"),
    "third-party-advisory": (5, "Third Party Advisory"),
}

EXCLUDED_TAGS = {"exploit"}

MAX_LINKS_IN_SUMMARY = 10
MAX_AFFECTED_ITEMS = 20
MAX_CPE_ITEMS = 15

DEFAULT_WORKERS = min(32, (os.cpu_count() or 4) * 4)

CSV_FIELDNAMES = [
    "cve_id",
    "json_status",
    "id_mismatch",
    "state",
    "date_published",
    "date_updated",
    "assigner",
    "description_en",
    "cwe_ids",
    "cvss_v2_score",
    "cvss_v2_vector",
    "cvss_v2_severity",
    "cvss_v3_score",
    "cvss_v3_vector",
    "cvss_v3_severity",
    "affected_products",
    "affected_cpes",
    "top_priority_type",
    "top_priority_url",
    "all_remediation_links",
    "patch_urls",
    "vendor_advisory_urls",
    "mitigation_urls",
    "release_notes_urls",
    "third_party_advisory_urls",
    "official_solutions",
    "official_mitigations",
    "upgrade_recommendations",
]


def load_json(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def dedup(seq):
    seen = set()
    result = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def join_field(values, sep=" | "):
    return sep.join(dedup(v for v in values if v))


def cvss_v2_severity(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def get_all_containers(data):
    containers = data.get("containers", {})
    result = []
    cna = containers.get("cna")
    if cna:
        result.append(("cna", cna))
    for i, entry in enumerate(containers.get("adp", []) or []):
        provider = entry.get("providerMetadata", {}).get("shortName", f"adp[{i}]")
        result.append((f"adp:{provider}", entry))
    return result


def pick_description(container):
    for desc in container.get("descriptions", []) or []:
        if (desc.get("lang") or "").lower() == "en":
            val = (desc.get("value") or "").strip()
            if val:
                return val
    for desc in container.get("descriptions", []) or []:
        val = (desc.get("value") or "").strip()
        if val:
            return val
    return ""


def extract_cwe_ids(container):
    out = []
    for pt in container.get("problemTypes", []) or []:
        for desc in pt.get("descriptions", []) or []:
            cwe_id = (desc.get("cweId") or "").strip()
            if cwe_id:
                out.append(cwe_id)
                continue
            text = (desc.get("description") or "").strip()
            if text and text.upper().startswith("CWE-"):
                out.append(text)
    return out


def extract_cvss_metrics(container):
    v2_score = v2_vector = v3_score = v3_vector = v3_severity = None
    for metric in container.get("metrics", []) or []:
        if not isinstance(metric, dict):
            continue
        for key, value in metric.items():
            if not isinstance(value, dict):
                continue
            if key.startswith("cvssV2") and v2_score is None:
                v2_score = value.get("baseScore")
                v2_vector = value.get("vectorString") or ""
            elif key.startswith("cvssV3") and v3_score is None:
                v3_score = value.get("baseScore")
                v3_vector = value.get("vectorString") or ""
                v3_severity = value.get("baseSeverity") or ""
    return v2_score, v2_vector, v3_score, v3_vector, v3_severity


def summarize_affected(container):
    products = []
    cpes = []
    for aff in container.get("affected", []) or []:
        vendor = (aff.get("vendor") or "").strip()
        product = (aff.get("product") or "").strip()
        versions = []
        for v in aff.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            version = (v.get("version") or "").strip()
            fixed = v.get("lessThan") or v.get("lessThanOrEqual")
            if version and fixed:
                rel = "<" if v.get("lessThan") else "<="
                versions.append(f"{version} (fix {rel}{fixed})")
            elif version:
                versions.append(version)
            elif fixed:
                rel = "<" if v.get("lessThan") else "<="
                versions.append(f"fix {rel}{fixed}")
        if vendor or product:
            label = f"{vendor}/{product}".strip("/")
            if versions:
                label = f"{label}: {', '.join(versions[:5])}"
            products.append(label)
        for cpe in aff.get("cpes", []) or []:
            cpe = (cpe or "").strip()
            if cpe:
                cpes.append(cpe)
    return products, cpes


def extract_solutions(container):
    out = []
    for sol in container.get("solutions", []) or []:
        val = (sol.get("value") or "").strip()
        if val:
            out.append(val)
    return out


def extract_mitigations_text(container):
    out = []
    for item in container.get("mitigations", []) or []:
        val = (item.get("value") or "").strip()
        if val:
            out.append(val)
    return out


def classify_reference(ref):
    tags = {t.lower() for t in (ref.get("tags", []) or [])}
    tags_for_classify = tags - EXCLUDED_TAGS

    matched = [(TAG_PRIORITY[t][0], TAG_PRIORITY[t][1]) for t in tags_for_classify if t in TAG_PRIORITY]
    if not matched:
        return None

    priority, label = min(matched, key=lambda x: x[0])
    return {
        "priority": priority,
        "type": label,
        "url": ref.get("url", ""),
        "name": ref.get("name", ""),
    }


def extract_ranked_references(container):
    ranked = []
    for ref in container.get("references", []) or []:
        classified = classify_reference(ref)
        if classified:
            ranked.append(classified)
    return ranked


def extract_upgrade_versions(container):
    out = []
    for aff in container.get("affected", []) or []:
        vendor = aff.get("vendor", "")
        product = aff.get("product", "")
        for v in aff.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            fixed_version = v.get("lessThan") or v.get("lessThanOrEqual")
            if fixed_version:
                relation = "<" if v.get("lessThan") else "<="
                out.append(f"{vendor}/{product}: nâng cấp lên version {relation} {fixed_version}")
    return out


def extract_technical_info(data):
    meta = data.get("cveMetadata", {}) or {}
    description = ""
    cwe_ids = []
    v2_score = v2_vector = v3_score = v3_vector = v3_severity = None
    products = []
    cpes = []

    containers = get_all_containers(data)
    for label, container in containers:
        if not description:
            description = pick_description(container)
        cwe_ids.extend(extract_cwe_ids(container))
        cvss = extract_cvss_metrics(container)
        if v2_score is None and cvss[0] is not None:
            v2_score, v2_vector = cvss[0], cvss[1]
        if v3_score is None and cvss[2] is not None:
            v3_score, v3_vector, v3_severity = cvss[2], cvss[3], cvss[4]
        p, c = summarize_affected(container)
        products.extend(p)
        cpes.extend(c)

    return {
        "state": meta.get("state", ""),
        "date_published": meta.get("datePublished", ""),
        "date_updated": meta.get("dateUpdated", ""),
        "assigner": meta.get("assignerShortName", ""),
        "description_en": description,
        "cwe_ids": join_field(cwe_ids),
        "cvss_v2_score": "" if v2_score is None else v2_score,
        "cvss_v2_vector": v2_vector or "",
        "cvss_v2_severity": cvss_v2_severity(v2_score),
        "cvss_v3_score": "" if v3_score is None else v3_score,
        "cvss_v3_vector": v3_vector or "",
        "cvss_v3_severity": v3_severity or "",
        "affected_products": join_field(products[:MAX_AFFECTED_ITEMS]),
        "affected_cpes": join_field(cpes[:MAX_CPE_ITEMS]),
    }


def extract_remediation_info(data):
    all_solutions = []
    all_mitigations = []
    all_ranked_refs = []
    all_upgrades = []

    for _, container in get_all_containers(data):
        all_solutions.extend(extract_solutions(container))
        all_mitigations.extend(extract_mitigations_text(container))
        all_ranked_refs.extend(extract_ranked_references(container))
        all_upgrades.extend(extract_upgrade_versions(container))

    best_by_url = {}
    for ref in all_ranked_refs:
        url = ref["url"]
        if not url:
            continue
        if url not in best_by_url or ref["priority"] < best_by_url[url]["priority"]:
            best_by_url[url] = ref

    ranked_unique = sorted(best_by_url.values(), key=lambda r: r["priority"])
    top = ranked_unique[0] if ranked_unique else None

    summary_links = [
        f"[{r['priority']} - {r['type']}] {r['url']}"
        for r in ranked_unique[:MAX_LINKS_IN_SUMMARY]
    ]

    by_type = {label: [] for _, label in TAG_PRIORITY.values()}
    for r in ranked_unique:
        by_type[r["type"]].append(r["url"])

    return {
        "top_priority_type": top["type"] if top else "",
        "top_priority_url": top["url"] if top else "",
        "all_remediation_links": join_field(summary_links),
        "patch_urls": join_field(by_type["Patch"]),
        "vendor_advisory_urls": join_field(by_type["Vendor Advisory"]),
        "mitigation_urls": join_field(by_type["Mitigation"]),
        "release_notes_urls": join_field(by_type["Release Notes"]),
        "third_party_advisory_urls": join_field(by_type["Third Party Advisory"]),
        "official_solutions": join_field(all_solutions),
        "official_mitigations": join_field(all_mitigations),
        "upgrade_recommendations": join_field(all_upgrades[:MAX_LINKS_IN_SUMMARY]),
    }


def empty_row(cve_id, json_status="", id_mismatch=""):
    row = {name: "" for name in CSV_FIELDNAMES}
    row["cve_id"] = cve_id
    row["json_status"] = json_status
    row["id_mismatch"] = id_mismatch
    return row


def process_cve_file(path):
    data = load_json(path)
    file_stem = Path(path).stem.upper()
    cve_id = (data.get("cveMetadata", {}) or {}).get("cveId", file_stem)
    id_mismatch = "yes" if cve_id.upper() != file_stem else ""

    row = empty_row(cve_id, json_status="found", id_mismatch=id_mismatch)
    row.update(extract_technical_info(data))
    row.update(extract_remediation_info(data))
    return row


def load_cve_order(cve_list_path):
    p = Path(cve_list_path)
    ids = []
    if p.suffix.lower() == ".csv":
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames_lower = {name.lower(): name for name in (reader.fieldnames or [])}
            col = None
            for candidate in ("cve_id", "cve", "id", "cveid"):
                if candidate in fieldnames_lower:
                    col = fieldnames_lower[candidate]
                    break
            if col is None:
                raise ValueError(
                    f"Không tìm thấy cột chứa mã CVE trong CSV. Các cột hiện có: {reader.fieldnames}"
                )
            for row in reader:
                val = (row.get(col) or "").strip().upper()
                if val.startswith("CVE-"):
                    ids.append(val)
    else:
        with open(p, encoding="utf-8") as f:
            for line in f:
                val = line.strip().upper()
                if val.startswith("CVE-"):
                    ids.append(val)

    seen = set()
    unique_ids = []
    for cve_id in ids:
        if cve_id not in seen:
            seen.add(cve_id)
            unique_ids.append(cve_id)
    return unique_ids


def build_json_index(root: Path) -> dict[str, Path]:
    """
    Dung os.walk (thay vi Path.rglob) de quet thu muc nhanh hon: os.walk dung
    os.scandir noi bo va khong tao Path object thua cho nhung file bi bo qua,
    quan trong khi thu muc co hang tram nghin file.
    """
    index: dict[str, Path] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.lower().endswith(".json") or name.startswith("_"):
                continue
            cve_id = name[:-5].upper()  # bo duoi ".json" (5 ky tu)
            if not cve_id.startswith("CVE-"):
                continue
            full = Path(dirpath) / name
            existing = index.get(cve_id)
            if existing is None or len(full.parts) < len(existing.parts):
                index[cve_id] = full
    return index


def resolve_json_file(root: Path, cve_id: str, index: dict[str, Path] | None = None) -> Path | None:
    if index is not None:
        return index.get(cve_id.upper())

    candidates = [
        root / f"{cve_id}.json",
        root / "json_data" / f"{cve_id}.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def collect_files(path, limit=None, cve_list_path=None):
    p = Path(path)
    if p.is_file():
        return [p]

    json_index = build_json_index(p)

    if cve_list_path:
        ordered_ids = load_cve_order(cve_list_path)
        if limit is not None:
            ordered_ids = ordered_ids[:limit]
        files = []
        for cve_id in ordered_ids:
            found = resolve_json_file(p, cve_id, json_index)
            if found:
                files.append(found)
        return files, ordered_ids, json_index

    files = sorted(json_index.values(), key=lambda f: f.stem)
    if limit is not None:
        files = files[:limit]
    return files, None, json_index

def _process_one_safe(path):
    """Wrapper an toan de chay trong 1 luong: bat loi thay vi lam crash ca pool.
    Tra ve (True, row) neu thanh cong, hoac (False, (duong_dan, thong_bao_loi))."""
    try:
        return True, process_cve_file(path)
    except Exception as e:
        return False, (str(path), str(e))


def run_concurrent(files, workers, label="file"):
    """
    Chay process_cve_file song song cho danh sach `files`, tra ve list ket qua
    (ok, result) THEO DUNG THU TU cua `files` dau vao (ThreadPoolExecutor.map
    luon giu nguyen thu tu dau vao du cac luong hoan tat khong theo thu tu).
    In tien do dinh ky de theo doi voi tap du lieu lon (hang tram nghin file).
    """
    if not files:
        return []

    total = len(files)
    report_every = max(1, total // 20)  # ~20 lan cap nhat tien do
    results = []

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for i, res in enumerate(ex.map(_process_one_safe, files), start=1):
            results.append(res)
            if i % report_every == 0 or i == total:
                print(f"\r[*] Da xu ly {i}/{total} {label} ...", end="", flush=True)
    print()
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Trích xuất mã CVE, thông tin kỹ thuật và URL khắc phục "
        "(Patch > Vendor Advisory > Mitigation > Release Notes > Third Party Advisory)."
    )
    parser.add_argument("input", help="Đường dẫn tới 1 file JSON hoặc 1 thư mục chứa nhiều file JSON")
    parser.add_argument("--out", help="Đường dẫn file CSV output", default=None)
    parser.add_argument("--json", help="Đường dẫn file JSON output", default=None)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Chỉ xử lý N CVE đầu tiên (từ trên xuống dưới). Bỏ trống = xử lý toàn bộ.",
    )
    parser.add_argument(
        "--cve-list",
        default=None,
        help="Đường dẫn tới file danh sách CVE gốc (List_CVE_ID.csv) để giữ đúng thứ tự.",
    )
    parser.add_argument(
        "--include-missing",
        action="store_true",
        help="Khi dùng --cve-list, vẫn xuất dòng cho CVE không có file JSON (json_status=missing).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"So luong worker (threads) doc/parse file JSON song song (mac dinh: {DEFAULT_WORKERS}). "
        "Neu du lieu nam tren OneDrive/o dia mang, thu tang len 32-64 de tan dung do tre I/O.",
    )
    args = parser.parse_args()

    t_start = time.perf_counter()

    input_path = Path(args.input)
    if input_path.is_file():
        files = [input_path]
        ordered_ids = None
        json_index = {}
    else:
        files, ordered_ids, json_index = collect_files(
            args.input, limit=args.limit, cve_list_path=args.cve_list
        )

    t_indexed = time.perf_counter()
    print(f"[*] Da quet + lap chi muc thu muc trong {t_indexed - t_start:.1f}s")

    if not files and not (args.cve_list and args.include_missing):
        print(f"Không tìm thấy file JSON nào trong: {args.input}")
        sys.exit(1)

    limit_note = f" (giới hạn {args.limit} CVE đầu tiên)" if args.limit is not None else ""
    print(f"[*] Sẽ xử lý {len(files)} file JSON{limit_note} bang {args.workers} luong\n")

    rows = []
    processed_ids = set()

    if ordered_ids and args.include_missing:
        resolved = [(cve_id, resolve_json_file(input_path, cve_id, json_index)) for cve_id in ordered_ids]
        found_entries = [(i, cve_id, p) for i, (cve_id, p) in enumerate(resolved) if p and p.exists()]
        paths_to_process = [p for _, _, p in found_entries]

        mapped = run_concurrent(paths_to_process, args.workers, label="CVE")

        row_by_index = {}
        for (i, cve_id, p), (ok, result) in zip(found_entries, mapped):
            if ok:
                row_by_index[i] = result
                processed_ids.add(cve_id)
            else:
                row_by_index[i] = empty_row(cve_id, json_status="error")
                print(f"[LỖI] Không xử lý được {result[0]}: {result[1]}", file=sys.stderr)

        for i, (cve_id, _p) in enumerate(resolved):
            if i in row_by_index:
                rows.append(row_by_index[i])
            else:
                rows.append(empty_row(cve_id, json_status="missing"))
    else:
        mapped = run_concurrent(files, args.workers, label="CVE")
        for f, (ok, result) in zip(files, mapped):
            if ok:
                rows.append(result)
                processed_ids.add(result["cve_id"].upper())
            else:
                print(f"[LỖI] Không xử lý được {result[0]}: {result[1]}", file=sys.stderr)

    t_done = time.perf_counter()
    elapsed = t_done - t_indexed
    speed = len(rows) / elapsed if elapsed > 0 else 0.0
    print(f"[*] Xu ly xong {len(rows)} dong trong {elapsed:.1f}s (~{speed:.0f} CVE/s)\n")

    mismatch_count = sum(1 for r in rows if r.get("id_mismatch") == "yes")
    if mismatch_count:
        print(
            f"[!] Cảnh báo: {mismatch_count} file có cveMetadata.cveId không khớp tên file "
            f"(cột id_mismatch=yes). Nên kiểm tra chéo trước khi tin tưởng dữ liệu.",
            file=sys.stderr,
        )

    for row in rows[:20]:
        print("=" * 90)
        print(f"CVE: {row['cve_id']} [{row.get('json_status', 'found')}]")
        if row.get("description_en"):
            desc = row["description_en"]
            print(f"  Mô tả: {desc[:160]}{'...' if len(desc) > 160 else ''}")
        if row.get("cvss_v3_score") != "":
            print(f"  CVSS v3: {row['cvss_v3_score']} ({row['cvss_v3_severity']}) {row['cvss_v3_vector']}")
        elif row.get("cvss_v2_score") != "":
            print(f"  CVSS v2: {row['cvss_v2_score']} ({row['cvss_v2_severity']}) {row['cvss_v2_vector']}")
        if row.get("top_priority_type"):
            print(f"  Khắc phục ưu tiên: [{row['top_priority_type']}] {row['top_priority_url']}")
        elif row.get("json_status") == "found":
            print("  Khắc phục: không tìm thấy link theo bảng ưu tiên.")
        if row.get("official_solutions"):
            print(f"  Solutions: {row['official_solutions'][:200]}")
        if row.get("upgrade_recommendations"):
            print(f"  Nâng cấp: {row['upgrade_recommendations'][:200]}")

    if len(rows) > 20:
        print(f"\n... (ẩn {len(rows) - 20} dòng còn lại trên console, xem đầy đủ trong file output)")

    if args.out:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n✅ Đã xuất CSV: {args.out} ({len(rows)} dòng)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"✅ Đã xuất JSON: {args.json}")

    print(f"\n[*] Tong thoi gian chay: {time.perf_counter() - t_start:.1f}s")


if __name__ == "__main__":
    main()