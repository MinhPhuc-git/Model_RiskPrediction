import os
import sys
import csv
import glob
import json
import shutil
import subprocess
from pathlib import Path

# Thêm đường dẫn để import từ CTI Collector và Model
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
CTI_COLLECTOR_DIR = os.path.join(PROJECT_ROOT, "CTI Collector")
MODEL_DIR = os.path.join(PROJECT_ROOT, "Model")

sys.path.append(CTI_COLLECTOR_DIR)
sys.path.append(MODEL_DIR)

from cti_collector import WazuhCTIFetcher
from base_model import Predictor
from Remediation import RemediationIndex

def main():
    print("--- [1] LẤY TOÀN BỘ MÃ CVE TỪ FILE List_CVE_ID.csv ---")
    list_cve_path = os.path.join(CTI_COLLECTOR_DIR, "cve_data", "List_CVE_ID.csv")
    
    if not os.path.exists(list_cve_path):
        print(f"[!] Không tìm thấy file {list_cve_path}")
        return

    selected_cves = []
    with open(list_cve_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Fallback for both upper and lower case column names
            cve = row.get("CVE_ID") or row.get("cve_id") or ""
            cve = cve.strip().upper()
            if not cve.startswith("CVE-"):
                continue
            selected_cves.append(cve)

    if not selected_cves:
        print("[!] Không tìm thấy mã CVE nào hợp lệ trong file CSV.")
        return

    print(f"[*] Đã đọc {len(selected_cves)} mã CVE từ file CSV.")

    # Ghi tạm ra file để cti_collector có thể đọc
    temp_input_csv = os.path.join(PROJECT_ROOT, "temp_cve_input.csv")
    with open(temp_input_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["cve_id"])
        for cve in selected_cves:
            writer.writerow([cve])

    print("\n--- [2] TẢI DỮ LIỆU JSON QUA WAZUH ---")
    outdir_json = os.path.join(CTI_COLLECTOR_DIR, "cve_data", "json_data")
    os.makedirs(outdir_json, exist_ok=True)
    
    fetcher = WazuhCTIFetcher(
        input_path=temp_input_csv,
        outdir=outdir_json,
        workers=5,
        retries=3,
        delay=0.1
    )
    fetcher.run()

    print("\n--- [3] TRÍCH XUẤT ĐẶC TRƯNG VÀ REFENRENCE BẰNG EXTRACT_CVE.PY ---")
    extracted_csv = os.path.join(PROJECT_ROOT, "pipeline_extracted.csv")
    extract_script = os.path.join(CTI_COLLECTOR_DIR, "Extract_CVE.py")
    
    # Chạy qua subprocess để đảm bảo độc lập giống command line
    cmd = [
        sys.executable, extract_script,
        outdir_json,
        "--out", extracted_csv,
        "--workers", "4"
    ]
    subprocess.run(cmd, check=True)
    
    print("\n--- [4] DỰ ĐOÁN RỦI RO BẰNG XGBOOST ---")
    # Load Predictor (với XGBoost)
    xgboost_dir = os.path.join(PROJECT_ROOT, "Model Result", "xgboost")
    model_path = os.path.join(xgboost_dir, "xgboost_model.pkl")
    encoder_path = os.path.join(xgboost_dir, "xgboost_encoders.pkl")
    metrics_path = os.path.join(xgboost_dir, "xgboost_metrics.json")
    
    if not os.path.exists(metrics_path):
        print(f"[!] Lỗi: Không tìm thấy thư mục model đã train tại {xgboost_dir}.")
        print("[!] Vui lòng chạy file xgboost_model.py một lần để train mô hình trước.")
        return

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    predictor = Predictor(
        model_path=model_path,
        encoder_path=encoder_path,
        feature_names=metrics.get("feature_names"),
        threshold=0.6,
        risk_thresholds=metrics.get("risk_thresholds"),
        reference_probs=metrics.get("validation_probabilities", [])
    )
    
    # Tạo Index cho Remediation (Sử dụng trực tiếp file pipeline_extracted.csv)
    rem_index = RemediationIndex(extracted_csv)

    print("\n--- BẮT ĐẦU QUÉT VÀ DỰ ĐOÁN TỪNG CVE ---")
    results = []
    label_dir = os.path.join(PROJECT_ROOT, "Label")
    os.makedirs(label_dir, exist_ok=True)
    generated_label_files = []

    def to_float(val, default=0.0):
        try:
            if val == "" or val is None: return default
            return float(val)
        except:
            return default

    with open(extracted_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("cve_id"):
                continue
            
            cve_id = row["cve_id"]
            
            # Tạo dictionary đúng cấu trúc yêu cầu
            label_data = {
                "cve_id": cve_id,
                "cwe_id": row.get("cwe_id", "Unknown"),
                "cvss_version": row.get("cvss_final_version", "Unknown"),
                "base_score": to_float(row.get("cvss_final_score")),
                "av_label": row.get("cvss_v3_attack_vector") or row.get("cvss_v2_access_vector") or "unknown",
                "ac_label": row.get("cvss_v3_attack_complexity") or row.get("cvss_v2_access_complexity") or "unknown",
                "pr_label": row.get("cvss_v3_privileges_required") or row.get("cvss_v2_authentication") or "unknown",
                "ui_label": row.get("cvss_v3_user_interaction") or "unknown",
                "scope_label": row.get("cvss_v3_scope") or "unknown",
                "c_label": row.get("cvss_v3_confidentiality_impact") or row.get("cvss_v2_confidentiality_impact") or "unknown",
                "i_label": row.get("cvss_v3_integrity_impact") or row.get("cvss_v2_integrity_impact") or "unknown",
                "a_label": row.get("cvss_v3_availability_impact") or row.get("cvss_v2_availability_impact") or "unknown",
                "exploitability_score": to_float(row.get("cvss_final_exploitability_subscore")),
                "impact_score": to_float(row.get("cvss_final_impact_subscore")),
                "severity_label": row.get("cvss_final_severity", "Unknown")
            }

            # Ghi ra file JSON tạm trong thư mục Label
            temp_json_path = os.path.join(label_dir, f"{cve_id}_input.json")
            with open(temp_json_path, "w", encoding="utf-8") as jf:
                json.dump(label_data, jf, indent=2, ensure_ascii=False)
            generated_label_files.append(temp_json_path)

    # Dự đoán bằng cách quét thư mục Label (chỉ quét các file _input.json vừa tạo để tránh xoá nhầm data cũ)
    for file_path in generated_label_files:
        print(f"\n>> Đang xử lý {os.path.basename(file_path)}...")
        pred_result = predictor.predict_json(file_path, verbose=False)
        
        # Gắn thêm Remediation (gợi ý khắc phục)
        enriched_result = rem_index.enrich(pred_result)
        results.append(enriched_result)

        # Lưu lại kết quả đã làm giàu (enriched) đè lên file trong Data User
        saved_path = enriched_result.get("_saved_path")
        if saved_path and os.path.exists(saved_path):
            with open(saved_path, "w", encoding="utf-8") as out_f:
                json.dump(enriched_result, out_f, indent=2, ensure_ascii=False)

        # In thông tin tóm tắt ra màn hình
        print(f"Risk: {enriched_result['Risk']} | Prob: {enriched_result['Probability']*100:.2f}%")
        if enriched_result.get("Remediation", {}).get("has_remediation"):
            rem = enriched_result["Remediation"]
            print(f"Cách khắc phục chính: [{rem.get('top_priority_type')}] {rem.get('top_priority_url')}")
        else:
            print("Cách khắc phục: Không có dữ liệu chính thức.")

    # Lưu toàn bộ kết quả tổng hợp ra file JSON
    final_output = os.path.join(PROJECT_ROOT, "final_prediction_results.json")
    with open(final_output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Đã lưu toàn bộ kết quả tổng hợp vào {final_output}")

    print("\n--- [5] DỌN DẸP DỮ LIỆU ĐỂ NHẸ HỆ THỐNG ---")
    # Xoá json_data
    try:
        if os.path.exists(outdir_json):
            shutil.rmtree(outdir_json)
            os.makedirs(outdir_json, exist_ok=True)
            print("[*] Đã xoá toàn bộ dữ liệu trong thư mục cve_data/json_data.")
    except Exception as e:
        print(f"[!] Lỗi khi xoá json_data: {e}")

    # Xoá các file JSON tạm trong thư mục Label
    for file_path in generated_label_files:
        if os.path.exists(file_path):
            os.remove(file_path)
    print(f"[*] Đã xoá {len(generated_label_files)} file JSON tạm trong thư mục Label.")

    # (Tuỳ chọn) xoá file tạm
    if os.path.exists(temp_input_csv):
        os.remove(temp_input_csv)
    if os.path.exists(extracted_csv):
        os.remove(extracted_csv)

    print("\n--- HOÀN TẤT ---")

if __name__ == "__main__":
    main()
