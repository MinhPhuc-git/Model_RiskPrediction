import argparse
import csv
import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Tự suy ra đường dẫn mặc định dựa trên vị trí thực tế của file này trong project
# ---------------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../CTI Collector
_PROJECT_ROOT = os.path.abspath(os.path.join(_BASE_DIR, ".."))   # thư mục cha (chứa Data User)

DEFAULT_CSV = os.path.join(_BASE_DIR, "ket_qua_full.csv")
DEFAULT_DATA_USER_DIR = os.path.join(_PROJECT_ROOT, "Data User")

# ---------------------------------------------------------------------------
# Các cột remediation trong ket_qua_full.csv (do Extract_CVE.py sinh ra),
# giá trị trong mỗi cột được nối bằng " | " (xem hàm join_field trong Extract_CVE.py)
# ---------------------------------------------------------------------------
LIST_SEP = " | "

REMEDIATION_LIST_COLUMNS = [
    "patch_urls",
    "vendor_advisory_urls",
    "mitigation_urls",
    "release_notes_urls",
    "third_party_advisory_urls",
    "official_solutions",
    "official_mitigations",
    "upgrade_recommendations",
]

# Cột không dùng nữa vì đã có cùng thông tin ở các cột list phía trên,
# nhưng vẫn giữ lại raw string cho ai cần xem nguyên bản
REMEDIATION_RAW_COLUMNS = [
    "top_priority_type",
    "top_priority_url",
    "all_remediation_links",
]

# Thông tin ngữ cảnh CVE (bonus, không bắt buộc nhưng hữu ích để đọc kèm gợi ý)
CONTEXT_COLUMNS = [
    "description_en",
    "cvss_v3_score",
    "cvss_v3_severity",
    "cvss_v2_score",
    "cvss_v2_severity",
]

MSG_NOT_IN_DB = "No remediation information available for this CVE (CVE not found in remediation database)."
MSG_NO_REMEDIATION = "No official remediation information (patch, advisory, or mitigation) was found for this CVE."


def _split_list(value: str) -> list:
    """Tách 1 cột dạng 'a | b | c' thành list ['a', 'b', 'c']. Rỗng -> []."""
    value = (value or "").strip()
    if not value:
        return []
    return [v.strip() for v in value.split(LIST_SEP) if v.strip()]


class RemediationIndex:
    """
    Đọc ket_qua_full.csv 1 lần, xây dict tra cứu {CVE_ID: row} để map nhanh
    cho hàng loạt file kết quả (không phải đọc lại CSV mỗi lần).
    """

    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.index: dict[str, dict] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.csv_path):
            raise FileNotFoundError(
                f"Không tìm thấy file CSV remediation: {self.csv_path}\n"
                f"-> Hãy chạy Extract_CVE.py trước để sinh file này, hoặc truyền --csv đúng đường dẫn."
            )
        with open(self.csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = (row.get("cve_id") or "").strip().upper()
                if cve_id:
                    self.index[cve_id] = row
        print(f"[REMEDIATION] Da nap {len(self.index)} CVE tu {self.csv_path}")

    def _build_block(self, cve_id: str) -> dict:
        row = self.index.get(cve_id.upper())

        if row is None:
            return {
                "found_in_database": False,
                "has_remediation": False,
                "message": MSG_NOT_IN_DB,
            }

        block = {"found_in_database": True}

        # Các cột dạng list (patch/vendor_advisory/mitigation/.../upgrade_recommendations)
        for col in REMEDIATION_LIST_COLUMNS:
            block[col] = _split_list(row.get(col, ""))

        # Giữ nguyên top_priority_type / top_priority_url (không phải dạng list)
        block["top_priority_type"] = (row.get("top_priority_type") or "").strip()
        block["top_priority_url"] = (row.get("top_priority_url") or "").strip()

        # Ngữ cảnh CVE (bonus)
        block["cve_description"] = (row.get("description_en") or "").strip()

        has_remediation = bool(
            block["top_priority_url"]
            or any(block[col] for col in REMEDIATION_LIST_COLUMNS)
        )
        block["has_remediation"] = has_remediation
        block["message"] = None if has_remediation else MSG_NO_REMEDIATION

        return block

    def enrich(self, result: dict) -> dict:
        """
        Nhận dict kết quả dự đoán (đã có key 'CVE_ID', đúng format của
        Predictor.predict_json trong base_model.py) và trả về dict đó
        kèm thêm key 'Remediation'.
        """
        cve_id = result.get("CVE_ID") or result.get("cve_id") or ""
        if not cve_id:
            raise ValueError("Dict result khong co key 'CVE_ID' de mapping remediation.")

        result["Remediation"] = self._build_block(cve_id)
        return result

    # -- Tiện ích thao tác trực tiếp trên file --------------------------------

    def enrich_file(self, json_path: str, output_path: str | None = None) -> str:
        """Doc 1 file result.json, them 'Remediation', luu lai (ghi de neu output_path=None)."""
        with open(json_path, "r", encoding="utf-8") as f:
            result = json.load(f)

        result = self.enrich(result)

        out_path = output_path or json_path
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return out_path

    def enrich_folder(self, folder_path: str, pattern: str = "*_result.json") -> list:
        """Map hang loat cho moi file khop pattern trong 1 thu muc, ghi de tung file."""
        folder = Path(folder_path)
        processed = []
        for json_file in sorted(folder.glob(pattern)):
            try:
                self.enrich_file(str(json_file))
                processed.append(str(json_file))
            except Exception as e:
                print(f"[LOI] Khong xu ly duoc {json_file}: {e}", file=sys.stderr)
        return processed


def _print_summary(result: dict):
    rem = result.get("Remediation", {})
    print("\n")
    print(" Remediation Mapping Result")
    print("==============================")
    print("CVE :", result.get("CVE_ID"))
    if not rem.get("found_in_database"):
        print("Status :", rem.get("message"))
    elif not rem.get("has_remediation"):
        print("Status :", rem.get("message"))
    else:
        print("Top priority :", f"[{rem.get('top_priority_type')}] {rem.get('top_priority_url')}")
        for col in REMEDIATION_LIST_COLUMNS:
            if rem.get(col):
                print(f"{col} :")
                for link in rem[col]:
                    print("   -", link)
    print("==============================\n")


def main():
    parser = argparse.ArgumentParser(
        description="Ghep du lieu goi y khac phuc (remediation) tu ket_qua_full.csv "
        "vao file ket qua du doan (result.json) cua model."
    )
    parser.add_argument(
        "--csv", default=DEFAULT_CSV,
        help=f"Duong dan toi ket_qua_full.csv (mac dinh: {DEFAULT_CSV})",
    )
    parser.add_argument("--result", default=None, help="Duong dan toi 1 file <CVE_ID>_result.json can map")
    parser.add_argument("--out", default=None, help="Duong dan file JSON output (chi dung voi --result). Bo trong = ghi de file goc.")
    parser.add_argument(
        "--results-dir", default=None,
        help=f"Thu muc chua nhieu file *_result.json de map hang loat (mac dinh khi khong truyen --result: {DEFAULT_DATA_USER_DIR})",
    )
    args = parser.parse_args()

    # Khong truyen gi ca -> mac dinh xu ly hang loat toan bo thu muc Data User
    if not args.result and not args.results_dir:
        args.results_dir = DEFAULT_DATA_USER_DIR

    index = RemediationIndex(args.csv)

    if args.result:
        with open(args.result, "r", encoding="utf-8") as f:
            result_preview = json.load(f)
        out_path = index.enrich_file(args.result, args.out)
        with open(out_path, "r", encoding="utf-8") as f:
            result_preview = json.load(f)
        _print_summary(result_preview)
        print(f"[SAVE] Da luu ket qua (kem Remediation) tai: {out_path}")

    if args.results_dir:
        processed = index.enrich_folder(args.results_dir)
        print(f"[SAVE] Da map + ghi de {len(processed)} file trong: {args.results_dir}")


if __name__ == "__main__":
    main()