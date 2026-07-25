#!/usr/bin/env python3
"""
extract_cve_from_wazuh_csv.py
------------------------------
Trích xuất cột chứa mã CVE từ file CSV được export ra từ module
"Vulnerability Detection" của Wazuh (Kibana/OpenSearch Dashboards export
hoặc Wazuh API export).

Vì tên cột CVE có thể khác nhau tùy cách export (ví dụ:
  "vulnerability.cve", "data.vulnerability.cve", "CVE", "cve_id", "CVEID"...),
script sẽ:
  1. Thử tìm cột có tên khớp với các pattern phổ biến (ưu tiên).
  2. Nếu không tìm thấy, quét toàn bộ các cột và chọn cột có nhiều giá trị
     khớp định dạng "CVE-YYYY-NNNNN" nhất.

Cách dùng:
    python3 extract_cve_from_wazuh_csv.py <input.csv> [--out output.csv]
                                           [--column TÊN_CỘT] [--unique] [--sep ,]
                                           [--limit N]

Ví dụ:
    # Tự động dò cột CVE, xuất danh sách CVE duy nhất
    python3 extract_cve_from_wazuh_csv.py wazuh_vuln_export.csv --out cve_list.csv --unique

    # Chỉ định rõ tên cột (khi việc tự động dò không chính xác)
    python3 extract_cve_from_wazuh_csv.py wazuh_vuln_export.csv --column "vulnerability.cve"

    # Chỉ lấy 10 mã CVE duy nhất đầu tiên (theo thứ tự xuất hiện từ trên xuống trong file)
    python3 extract_cve_from_wazuh_csv.py wazuh_vuln_export.csv --out cve_list.csv --unique --limit 10
"""

import argparse
import csv
import re
import sys
from pathlib import Path

# Pattern chuẩn của mã CVE: CVE-YYYY-NNNN (4 chữ số trở lên)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Các tên cột thường gặp trong export của Wazuh Vulnerability Detection
CANDIDATE_COLUMN_NAMES = [
    "vulnerability.cve",
    "data.vulnerability.cve",
    "data.vulnerability.cve.id",
    "vulnerability.id",
    "cve",
    "cve_id",
    "cveid",
    "cve.id",
]


def sniff_delimiter(path, encoding):
    """Tự động đoán ký tự phân cách (, hoặc ; hoặc tab)."""
    with open(path, encoding=encoding, errors="ignore") as f:
        sample = f.read(4096)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        return dialect.delimiter
    except csv.Error:
        return ","


def read_csv_rows(path, sep=None, encoding="utf-8-sig"):
    """Đọc CSV thành list[dict], tự dò delimiter nếu sep=None."""
    delimiter = sep or sniff_delimiter(path, encoding)
    with open(path, encoding=encoding, errors="ignore", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        rows = list(reader)
        fieldnames = reader.fieldnames or []
    return rows, fieldnames, delimiter


def find_cve_column(rows, fieldnames, forced_column=None):
    """
    Xác định cột nào chứa mã CVE.
    - Nếu forced_column được chỉ định -> dùng luôn (kiểm tra tồn tại).
    - Nếu không, thử match theo tên cột phổ biến trước.
    - Cuối cùng, quét toàn bộ cột và chọn cột có tỉ lệ giá trị khớp CVE_PATTERN cao nhất.
    """
    if forced_column:
        if forced_column not in fieldnames:
            raise ValueError(
                f"Không tìm thấy cột '{forced_column}'. Các cột hiện có: {fieldnames}"
            )
        return forced_column

    # Bước 1: match theo tên cột phổ biến (không phân biệt hoa/thường)
    lower_map = {c.lower(): c for c in fieldnames}
    for candidate in CANDIDATE_COLUMN_NAMES:
        if candidate.lower() in lower_map:
            return lower_map[candidate.lower()]

    # cũng thử match cột nào có chứa từ "cve" trong tên
    cve_like = [c for c in fieldnames if "cve" in c.lower()]
    if len(cve_like) == 1:
        return cve_like[0]

    # Bước 2: quét dữ liệu, chọn cột match pattern CVE nhiều nhất
    candidates = cve_like or fieldnames
    best_col, best_score = None, 0
    sample_rows = rows[:200] if len(rows) > 200 else rows  # lấy mẫu để nhanh

    for col in candidates:
        matched = sum(
            1 for r in sample_rows if r.get(col) and CVE_PATTERN.search(str(r[col]))
        )
        if matched > best_score:
            best_score = matched
            best_col = col

    if best_col is None or best_score == 0:
        raise ValueError(
            "Không tự động xác định được cột chứa mã CVE. "
            f"Vui lòng chỉ định thủ công bằng --column. Các cột hiện có: {fieldnames}"
        )
    return best_col


def extract_cves(rows, cve_column):
    """Trích toàn bộ mã CVE (có thể 1 dòng chứa nhiều CVE cách nhau bởi dấu phẩy/khoảng trắng).
    Giữ nguyên THỨ TỰ xuất hiện từ trên xuống dưới trong file."""
    results = []
    for row in rows:
        raw_value = row.get(cve_column, "") or ""
        # 1 ô có thể chứa nhiều CVE, ví dụ: "CVE-2021-44228, CVE-2021-45046"
        found = CVE_PATTERN.findall(raw_value)
        if not found:
            continue
        for cve in found:
            results.append({"cve_id": cve.upper(), "source_row": row})
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Trích xuất cột mã CVE từ file CSV export của Wazuh Vulnerability Detection"
    )
    parser.add_argument("input", help="Đường dẫn file CSV đầu vào")
    parser.add_argument("--out", help="Đường dẫn file CSV output", default="cve_list.csv")
    parser.add_argument(
        "--column", help="Tên cột chứa CVE (bỏ qua tự động dò nếu chỉ định)", default=None
    )
    parser.add_argument(
        "--unique", action="store_true", help="Chỉ giữ danh sách CVE duy nhất (loại trùng)"
    )
    parser.add_argument(
        "--sep", help="Ký tự phân cách CSV (mặc định: tự động dò)", default=None
    )
    parser.add_argument(
        "--encoding", help="Encoding của file (mặc định: utf-8-sig)", default="utf-8-sig"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Chỉ lấy N mã CVE đầu tiên (theo thứ tự từ trên xuống trong file). "
             "Với --unique: đếm theo CVE duy nhất. Không có --unique: đếm theo số bản ghi/dòng. "
             "Bỏ trống = lấy toàn bộ.",
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[LỖI] Không tìm thấy file: {in_path}", file=sys.stderr)
        sys.exit(1)

    rows, fieldnames, delimiter = read_csv_rows(in_path, sep=args.sep, encoding=args.encoding)
    print(f"Đã đọc {len(rows)} dòng, {len(fieldnames)} cột (delimiter='{delimiter}')")
    print(f"Các cột: {fieldnames}")

    cve_column = find_cve_column(rows, fieldnames, forced_column=args.column)
    print(f"\n✅ Cột được xác định chứa mã CVE: '{cve_column}'\n")

    extracted = extract_cves(rows, cve_column)
    if not extracted:
        print("⚠️  Không trích xuất được mã CVE nào từ cột đã chọn.")
        sys.exit(0)

    limit_note = f" (giới hạn {args.limit} đầu tiên)" if args.limit is not None else ""

    if args.unique:
        seen = set()
        unique_list = []
        for item in extracted:
            if item["cve_id"] not in seen:
                seen.add(item["cve_id"])
                unique_list.append(item["cve_id"])

        # Giới hạn số lượng CVE duy nhất lấy từ trên xuống
        if args.limit is not None:
            unique_list = unique_list[: args.limit]

        print(f"Tổng số CVE duy nhất{limit_note}: {len(unique_list)}")
        for cve in unique_list:
            print(f"  - {cve}")

        if args.out:
            with open(args.out, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["cve_id"])
                for cve in unique_list:
                    writer.writerow([cve])
            print(f"\n✅ Đã xuất file: {args.out}")
    else:
        # Giới hạn số lượng bản ghi lấy từ trên xuống
        if args.limit is not None:
            extracted = extracted[: args.limit]

        print(f"Tổng số bản ghi có CVE{limit_note}: {len(extracted)}")
        if args.out:
            # Giữ nguyên toàn bộ dữ liệu gốc + thêm cột cve_id đã chuẩn hoá lên đầu
            out_fieldnames = ["cve_id"] + fieldnames
            with open(args.out, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=out_fieldnames)
                writer.writeheader()
                for item in extracted:
                    row_out = {"cve_id": item["cve_id"]}
                    row_out.update(item["source_row"])
                    writer.writerow(row_out)
            print(f"\n✅ Đã xuất file: {args.out}")


if __name__ == "__main__":
    main()