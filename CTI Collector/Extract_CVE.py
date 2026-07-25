#!/usr/bin/env python3
"""
extract_cve_fixes.py
---------------------
Trích xuất thông tin "cách khắc phục" (remediation) từ file JSON CVE (chuẩn CVE
Record Format 5.0 - CTI-Wazuh/MITRE/NVD), ưu tiên hiển thị URL theo LOẠI TÀI LIỆU
theo bảng mức ưu tiên sau:

    Loại tài liệu           Mức ưu tiên   Mô tả
    ----------------------  -----------   --------------------------------------------
    Patch                   1             Bản vá chính thức do nhà cung cấp phát hành
    Vendor Advisory         2             Hướng dẫn kỹ thuật chính thức của nhà cung cấp
    Mitigation              3             Biện pháp giảm thiểu khi chưa có bản vá
    Release Notes           4             Ghi chú phát hành của bản đã sửa lỗi
    Third Party Advisory    5             Tài liệu tham khảo từ tổ chức bảo mật khác
    Exploit                 KHÔNG hiển thị (loại bỏ hoàn toàn để tránh hỗ trợ khai thác)

Ngoài các reference, script còn lấy field 'solutions' chính thức (nếu có) và suy ra
khuyến nghị nâng cấp version từ affected[].versions[] để bổ sung khi không có URL nào.

Cách dùng:
    python3 extract_cve_fixes.py <file_or_folder> [--out output.csv] [--json output.json] [--limit N]

Ví dụ:
    # Xử lý toàn bộ file JSON trong thư mục
    python3 extract_cve_fixes.py /mnt/user-data/uploads --out remediation_report.csv

    # Chỉ xử lý 10 CVE đầu tiên (theo thứ tự trong danh sách CVE gốc, ví dụ cve_list.txt/List_CVE_ID.csv)
    python3 extract_cve_fixes.py ./cve_data --out remediation_report.csv --limit 10 --cve-list ./cve_list.txt
"""

import json
import re
import sys
import csv
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Bảng ưu tiên loại tài liệu (khớp với tag trong field references[].tags)
# Số càng nhỏ càng ưu tiên cao. Tag không có trong bảng này sẽ bị bỏ qua.
# ---------------------------------------------------------------------------
TAG_PRIORITY = {
    "patch": (1, "Patch"),
    "vendor-advisory": (2, "Vendor Advisory"),
    "mitigation": (3, "Mitigation"),
    "release-notes": (4, "Release Notes"),
    "third-party-advisory": (5, "Third Party Advisory"),
}

# Tag tuyệt đối không hiển thị (loại bỏ hoàn toàn khỏi kết quả)
EXCLUDED_TAGS = {"exploit"}

# Số lượng URL tối đa muốn giữ lại trong cột tổng hợp (tránh quá dài)
MAX_LINKS_IN_SUMMARY = 10


def load_json(path):
    """Đọc file JSON, tự xử lý BOM (utf-8-sig) nếu có."""
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def get_all_containers(data):
    """Trả về danh sách (label, container_dict) gồm cna + từng phần tử trong adp."""
    containers = data.get("containers", {})
    result = []
    cna = containers.get("cna")
    if cna:
        result.append(("cna", cna))
    for i, entry in enumerate(containers.get("adp", []) or []):
        provider = entry.get("providerMetadata", {}).get("shortName", f"adp[{i}]")
        result.append((f"adp:{provider}", entry))
    return result


def extract_solutions(container):
    """Lấy field 'solutions' nếu có (thường chỉ có ở SUSE và một số nhà cung cấp khác)."""
    out = []
    for sol in container.get("solutions", []) or []:
        val = sol.get("value")
        if val:
            out.append(val.strip())
    return out


def classify_reference(ref):
    """
    Phân loại 1 reference theo bảng ưu tiên.
    Trả về None nếu:
      - ref có tag bị loại bỏ (exploit) -> KHÔNG hiển thị dù có tag khác.
      - ref không khớp bất kỳ tag ưu tiên nào.
    Nếu ref có nhiều tag ưu tiên, chọn tag có mức ưu tiên cao nhất (số nhỏ nhất).
    """
    tags = set(t.lower() for t in (ref.get("tags", []) or []))

    # Loại bỏ tuyệt đối nếu có tag exploit
    if tags & EXCLUDED_TAGS:
        return None

    matched = [(TAG_PRIORITY[t][0], TAG_PRIORITY[t][1]) for t in tags if t in TAG_PRIORITY]
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
    """Trả về danh sách reference đã phân loại + xếp hạng ưu tiên (đã loại exploit)."""
    ranked = []
    for ref in container.get("references", []) or []:
        classified = classify_reference(ref)
        if classified:
            ranked.append(classified)
    return ranked


def extract_upgrade_versions(container):
    """Suy ra khuyến nghị nâng cấp từ affected[].versions[] (lessThan / lessThanOrEqual)."""
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


def dedup(seq):
    """Loại trùng nhưng vẫn giữ thứ tự xuất hiện."""
    seen = set()
    result = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def process_cve_file(path):
    """Xử lý 1 file CVE JSON, trả về dict chứa link khắc phục đã xếp hạng ưu tiên."""
    data = load_json(path)
    cve_id = data.get("cveMetadata", {}).get("cveId", Path(path).stem)

    all_solutions = []
    all_ranked_refs = []
    all_upgrades = []

    for label, container in get_all_containers(data):
        all_solutions.extend(extract_solutions(container))
        all_ranked_refs.extend(extract_ranked_references(container))
        all_upgrades.extend(extract_upgrade_versions(container))

    # Loại trùng URL (giữ bản ghi có priority tốt nhất nếu 1 URL bị gắn nhiều tag khác nhau
    # ở nhiều container khác nhau)
    best_by_url = {}
    for ref in all_ranked_refs:
        url = ref["url"]
        if not url:
            continue
        if url not in best_by_url or ref["priority"] < best_by_url[url]["priority"]:
            best_by_url[url] = ref

    ranked_unique = sorted(best_by_url.values(), key=lambda r: r["priority"])

    # URL/loại tài liệu ưu tiên cao nhất hiện có (top 1)
    top = ranked_unique[0] if ranked_unique else None

    # Chuỗi tổng hợp tất cả link theo thứ tự ưu tiên: "[Mức ưu tiên - Loại] URL"
    summary_links = [
        f"[{r['priority']} - {r['type']}] {r['url']}"
        for r in ranked_unique[:MAX_LINKS_IN_SUMMARY]
    ]

    # Tách riêng theo từng loại (tiện cho việc lọc trong Excel/BI)
    by_type = {label: [] for _, label in TAG_PRIORITY.values()}
    for r in ranked_unique:
        by_type[r["type"]].append(r["url"])

    return {
        "cve_id": cve_id,
        "top_priority_type": top["type"] if top else "",
        "top_priority_url": top["url"] if top else "",
        "all_remediation_links": " | ".join(summary_links),
        "patch_urls": " | ".join(by_type["Patch"]),
        "vendor_advisory_urls": " | ".join(by_type["Vendor Advisory"]),
        "mitigation_urls": " | ".join(by_type["Mitigation"]),
        "release_notes_urls": " | ".join(by_type["Release Notes"]),
        "third_party_advisory_urls": " | ".join(by_type["Third Party Advisory"]),
        "official_solutions": " | ".join(dedup(all_solutions)),
        "upgrade_recommendations": " | ".join(dedup(all_upgrades)[:MAX_LINKS_IN_SUMMARY]),
    }


def load_cve_order(cve_list_path):
    """
    Đọc danh sách mã CVE gốc (cve_list.txt hoặc List_CVE_ID.csv - cùng định dạng
    dùng bởi cti_collector.py) để biết đúng THỨ TỰ từ trên xuống dưới.
    Trả về list các mã CVE (đã loại trùng, giữ nguyên thứ tự xuất hiện).
    """
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
                raise ValueError(f"Không tìm thấy cột chứa mã CVE trong CSV. Các cột hiện có: {reader.fieldnames}")
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


def collect_files(path, limit=None, cve_list_path=None):
    """
    Lấy danh sách file JSON cần xử lý.
      - Nếu path là 1 file -> trả về chính nó (bỏ qua limit).
      - Nếu path là thư mục:
          + Nếu có --cve-list -> sắp xếp file theo ĐÚNG thứ tự mã CVE trong file danh sách gốc
            (giống thứ tự tải về của cti_collector.py), rồi cắt lấy N file đầu (--limit).
          + Nếu không có --cve-list -> sắp xếp theo tên file (bảng chữ cái), rồi cắt N file đầu.
    """
    p = Path(path)
    if p.is_file():
        return [p]

    if cve_list_path:
        ordered_ids = load_cve_order(cve_list_path)
        if limit is not None:
            ordered_ids = ordered_ids[:limit]
        files = []
        for cve_id in ordered_ids:
            f = p / f"{cve_id}.json"
            if f.exists():
                files.append(f)
        return files

    files = sorted(p.glob("*.json"))
    if limit is not None:
        files = files[:limit]
    return files


def main():
    parser = argparse.ArgumentParser(
        description="Trích xuất URL khắc phục theo mức ưu tiên (Patch > Vendor Advisory > "
        "Mitigation > Release Notes > Third Party Advisory), loại bỏ Exploit."
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
        help="(Tuỳ chọn) Đường dẫn tới file danh sách CVE gốc (cve_list.txt hoặc "
             "List_CVE_ID.csv) để --limit lấy đúng theo THỨ TỰ ban đầu, thay vì "
             "theo bảng chữ cái tên file JSON.",
    )
    args = parser.parse_args()

    files = collect_files(args.input, limit=args.limit, cve_list_path=args.cve_list)
    if not files:
        print(f"Không tìm thấy file JSON nào trong: {args.input}")
        sys.exit(1)

    limit_note = f" (giới hạn {args.limit} CVE đầu tiên)" if args.limit is not None else ""
    print(f"[*] Sẽ xử lý {len(files)} file JSON{limit_note}\n")

    rows = []
    for f in files:
        try:
            rows.append(process_cve_file(f))
        except Exception as e:
            print(f"[LỖI] Không xử lý được {f}: {e}", file=sys.stderr)

    # In ra console
    for row in rows:
        print("=" * 90)
        print(f"CVE: {row['cve_id']}")
        if row["top_priority_type"]:
            print(f"  🎯 Ưu tiên cao nhất: [{row['top_priority_type']}] {row['top_priority_url']}")
        else:
            print("  ⚠️  Không tìm thấy tài liệu khắc phục nào theo bảng ưu tiên.")
        if row["official_solutions"]:
            print(f"  Solutions (chính thức): {row['official_solutions']}")
        if row["upgrade_recommendations"]:
            print(f"  Khuyến nghị nâng cấp: {row['upgrade_recommendations']}")
        if row["all_remediation_links"]:
            print("  Toàn bộ link (theo thứ tự ưu tiên):")
            for link in row["all_remediation_links"].split(" | "):
                print(f"    - {link}")

    # Xuất CSV nếu yêu cầu
    if args.out:
        fieldnames = [
            "cve_id",
            "top_priority_type",
            "top_priority_url",
            "all_remediation_links",
            "patch_urls",
            "vendor_advisory_urls",
            "mitigation_urls",
            "release_notes_urls",
            "third_party_advisory_urls",
            "official_solutions",
            "upgrade_recommendations",
        ]
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n✅ Đã xuất CSV: {args.out}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        print(f"✅ Đã xuất JSON: {args.json}")


if __name__ == "__main__":
    main()