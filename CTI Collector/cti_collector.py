import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests

class WazuhCTIFetcher:
    def __init__(self, input_path: str, outdir: str, workers: int, retries: int, delay: float):
        self.input_path = Path(input_path)
        self.outdir = Path(outdir)
        self.workers = workers
        self.retries = retries
        self.delay = delay
        self.url_template = "https://cti.wazuh.com/vulnerabilities/cves/{cve_id}/json5"
        self.fail_log_path = self.outdir / "_failed.log"
        self.backoff_base = 1.0

    def load_cve_ids(self) -> list[str]:
        ids = []
        if self.input_path.suffix.lower() == ".csv":
            with open(self.input_path, newline="", encoding="utf-8") as f:
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
            with open(self.input_path, encoding="utf-8") as f:
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

    def fetch_cve(self, cve_id: str) -> tuple[str, dict | None, str | None]:
        url = self.url_template.format(cve_id=cve_id)
        last_error = None

        for attempt in range(1, self.retries + 1):
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code == 404:
                    return cve_id, None, "not_found"
                resp.raise_for_status()
                return cve_id, resp.json(), None
            except requests.RequestException as e:
                last_error = str(e)
                if attempt < self.retries:
                    time.sleep(self.backoff_base * attempt)

        return cve_id, None, last_error

    def run(self):
        self.outdir.mkdir(parents=True, exist_ok=True)
        
        if not self.input_path.exists():
            print(f"[!] Không tìm thấy file input: {self.input_path}", file=sys.stderr)
            sys.exit(1)

        all_ids = self.load_cve_ids()
        print(f"[*] Đọc được {len(all_ids)} mã CVE (đã loại trùng) từ {self.input_path}")

        todo_ids = [c for c in all_ids if not (self.outdir / f"{c}.json").exists()]
        skipped = len(all_ids) - len(todo_ids)
        if skipped:
            print(f"[*] Bỏ qua {skipped} CVE đã tải trước đó, còn lại {len(todo_ids)} cần tải")

        if not todo_ids:
            print("[+] Không có CVE nào cần tải. Xong.")
            return

        done_count = 0
        not_found_count = 0
        error_count = 0
        failed_entries = []

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {}
            for cve_id in todo_ids:
                futures[executor.submit(self.fetch_cve, cve_id)] = cve_id
                time.sleep(self.delay)

            for future in as_completed(futures):
                cve_id, data, error = future.result()
                done_count += 1

                if data is not None:
                    out_path = self.outdir / f"{cve_id}.json"
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                elif error == "not_found":
                    not_found_count += 1
                    failed_entries.append(f"{cve_id}\tnot_found")
                else:
                    error_count += 1
                    failed_entries.append(f"{cve_id}\terror: {error}")

                if done_count % 50 == 0 or done_count == len(todo_ids):
                    print(f"    ... {done_count}/{len(todo_ids)} "
                          f"(lỗi: {error_count}, không tìm thấy: {not_found_count})")

        if failed_entries:
            with open(self.fail_log_path, "w", encoding="utf-8") as f:
                f.write("\n".join(failed_entries))
            print(f"[!] Danh sách CVE lỗi/không tìm thấy được ghi vào: {self.fail_log_path}")

        print("\n=== XONG ===")
        print(f"- Tổng số CVE cần tải: {len(todo_ids)}")
        print(f"- Tải thành công:      {len(todo_ids) - not_found_count - error_count}")
        print(f"- Không tìm thấy:      {not_found_count}")
        print(f"- Lỗi:                 {error_count}")
        print(f"- Thư mục output:      {self.outdir}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--outdir", default="./cve_data")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.1)
    args = parser.parse_args()

    fetcher = WazuhCTIFetcher(
        input_path=args.input,
        outdir=args.outdir,
        workers=args.workers,
        retries=args.retries,
        delay=args.delay
    )
    fetcher.run()

if __name__ == "__main__":
    main()