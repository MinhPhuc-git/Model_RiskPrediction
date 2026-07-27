import csv
import json
import os
import sys
import time
import argparse
import concurrent.futures as cf
from pathlib import Path

try:
    from cvss31_calculator import compute_from_vector_string as compute_v31
    from cvss30_calculator import compute_from_vector_string_v30 as compute_v30
    from cvss20_calculator import compute_from_vector_string_v2 as compute_v20
except ImportError:
    print(
        "[LỖI] Không tìm thấy đủ cvss20_calculator.py / cvss30_calculator.py / "
        "cvss31_calculator.py. Cả 3 file này cần nằm CÙNG thư mục với extract_cve.py "
        "để tính điểm CVSS đúng công thức cho từng phiên bản (2.0 / 3.0 / 3.1) ngay khi quét.",
        file=sys.stderr,
    )
    raise

# Thu tu uu tien khi chon 1 "diem CVSS cuoi cung" cho moi CVE: 3.1 truoc, roi 3.0,
# roi moi den 2.0. Tat ca cac phien ban co mat deu duoc TU TINH VA KIEM TRA (doi chieu
# voi baseScore cong bo trong JSON goc) - khong chi rieng phien ban duoc chon.
CVSS_VERSION_PRIORITY = ("v31", "v30", "v2")

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

DEFAULT_WORKERS = min(64, (os.cpu_count() or 4) * 4)

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
    "cvss_v2_access_vector",
    "cvss_v2_access_complexity",
    "cvss_v2_authentication",
    "cvss_v2_confidentiality_impact",
    "cvss_v2_integrity_impact",
    "cvss_v2_availability_impact",
    "cvss_v2_exploitability_score",
    "cvss_v2_impact_score",
    "cvss_v2_computed_base_score",
    "cvss_v2_computed_impact_subscore",
    "cvss_v2_computed_exploitability_subscore",
    "cvss_v2_computed_temporal_score",
    "cvss_v2_computed_environmental_score",
    "cvss_v2_score_mismatch",
    "cvss_v2_compute_error",
    "cvss_v3_score",
    "cvss_v3_vector",
    "cvss_v3_severity",
    "cvss_v3_version",
    "cvss_v3_attack_vector",
    "cvss_v3_attack_complexity",
    "cvss_v3_privileges_required",
    "cvss_v3_user_interaction",
    "cvss_v3_scope",
    "cvss_v3_confidentiality_impact",
    "cvss_v3_integrity_impact",
    "cvss_v3_availability_impact",
    # (da bo "cvss_v3_exploitability_score" va "cvss_v3_impact_score" lay tu JSON -
    #  vi da co ban TU TINH ben duoi (cvss_v3_computed_exploitability_subscore /
    #  cvss_v3_computed_impact_subscore), khong can lay trung tu JSON nua)
    "cvss_v3_computed_base_score",
    "cvss_v3_computed_impact_subscore",
    "cvss_v3_computed_exploitability_subscore",
    "cvss_v3_computed_temporal_score",
    "cvss_v3_computed_environmental_score",
    "cvss_v3_score_mismatch",
    "cvss_v3_compute_error",
    # Neu 1 CVE co CA cvssV3_0 LAN cvssV3_1 (hiem, vd CNA cho 3.1 nhung mot ADP khac
    # con luu 3.0), cac cot cvss_v3_* o tren se uu tien phan anh 3.1. Cac cot rieng
    # ben duoi giup thay ca 2 ban ghi (neu co) de doi chieu, khong bo sot du lieu nao.
    "cvss_v30_found",
    "cvss_v30_vector",
    "cvss_v30_score",
    "cvss_v30_computed_base_score",
    "cvss_v30_score_mismatch",
    "cvss_v30_compute_error",
    "cvss_v31_found",
    "cvss_v31_vector",
    "cvss_v31_score",
    "cvss_v31_computed_base_score",
    "cvss_v31_score_mismatch",
    "cvss_v31_compute_error",
    # "Diem CVSS cuoi cung" duoc chon theo dung thu tu uu tien yeu cau: 3.1 neu co ->
    # giam dan xuong 3.0 -> 2.0. Day la cot nen dung de xep hang/loc muc do nghiem
    # trong cho tung CVE (thay vi tu chon giua cvss_v3_* va cvss_v2_*).
    "cvss_final_version",
    "cvss_final_vector",
    "cvss_final_score",
    "cvss_final_severity",
    "cvss_final_impact_subscore",
    "cvss_final_exploitability_subscore",
    "cvss_final_temporal_score",
    "cvss_final_environmental_score",
    "cvss_final_compute_error",
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


def cvss_v3_severity_from_score(score):
    """Fallback severity cho CVSS v3.0/3.1 khi JSON khong co san 'baseSeverity'
    (thang do giong nhau cho ca 2 phien ban v3)."""
    if score is None or score == "":
        return ""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s == 0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


def classify_cvss_key(key_lower, value):
    """Xac dinh 1 block metric trong 'metrics[]' la CVSS v2.0, v3.0 hay v3.1.
    Uu tien doc field 'version' ben trong (theo dung CVE JSON 5.0 schema: field
    ten 'cvssV2_0'/'cvssV3_0'/'cvssV3_1', ben trong co 'version': '2.0'/'3.0'/'3.1'),
    va dung ten key lam phuong an du phong neu 'version' bi thieu/sai."""
    if key_lower.startswith("cvssv4") or key_lower == "other":
        return None  # CVSS v4.0 (hoac format khac) - ngoai pham vi script nay

    version = str(value.get("version") or "").strip()

    if key_lower.startswith("cvssv2"):
        return "v2"

    if key_lower.startswith("cvssv3"):
        if version.startswith("3.1"):
            return "v31"
        if version.startswith("3.0"):
            return "v30"
        # 'version' thieu/khong hop le -> doan theo ten key
        if "3_1" in key_lower or key_lower.endswith("31"):
            return "v31"
        if "3_0" in key_lower or key_lower.endswith("30"):
            return "v30"
        return None  # khong the xac dinh chac chan phien ban -> bo qua, an toan hon doan bua

    return None


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


def _fields_v2(value):
    return {
        "score": value.get("baseScore"),
        "vector": value.get("vectorString") or "",
        "access_vector": value.get("accessVector") or "",
        "access_complexity": value.get("accessComplexity") or "",
        "authentication": value.get("authentication") or "",
        "confidentiality_impact": value.get("confidentialityImpact") or "",
        "integrity_impact": value.get("integrityImpact") or "",
        "availability_impact": value.get("availabilityImpact") or "",
        "exploitability_score": value.get("exploitabilityScore", ""),
        "impact_score": value.get("impactScore", ""),
    }


def _fields_v3(value):
    return {
        "score": value.get("baseScore"),
        "vector": value.get("vectorString") or "",
        "severity": value.get("baseSeverity") or "",
        "version": value.get("version") or "",
        "attack_vector": value.get("attackVector") or "",
        "attack_complexity": value.get("attackComplexity") or "",
        "privileges_required": value.get("privilegesRequired") or "",
        "user_interaction": value.get("userInteraction") or "",
        "scope": value.get("scope") or "",
        "confidentiality_impact": value.get("confidentialityImpact") or "",
        "integrity_impact": value.get("integrityImpact") or "",
        "availability_impact": value.get("availabilityImpact") or "",
    }


def extract_cvss_metrics(container):
    """Quet 'metrics[]' cua 1 container (cna hoac adp), tra ve toi da 1 block cho
    moi phien ban CVSS (v2, v30, v31) tim thay trong CHINH container nay. Neu 1
    container co nhieu block cung phien ban (hiem), lay block dau tien."""
    result = {"v2": None, "v30": None, "v31": None}

    for metric in container.get("metrics", []) or []:
        if not isinstance(metric, dict):
            continue
        for key, value in metric.items():
            if not isinstance(value, dict):
                continue
            kind = classify_cvss_key(key.lower(), value)
            if kind == "v2" and result["v2"] is None:
                result["v2"] = _fields_v2(value)
            elif kind == "v30" and result["v30"] is None:
                result["v30"] = _fields_v3(value)
            elif kind == "v31" and result["v31"] is None:
                result["v31"] = _fields_v3(value)

    return result


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


def _compute_and_check(vector, published_score, compute_fn):
    """Goi dung calculator (v2.0 / v3.0 / v3.1) cho 1 vectorString, tra ve diem tu
    tinh VA doi chieu voi baseScore cong bo trong JSON goc (lech > 0.1 -> mismatch).
    Dung chung cho ca 3 nhanh de khong lap code 3 lan."""
    result = {"base": "", "impact": "", "exploit": "", "temporal": "", "environmental": "",
              "mismatch": "", "error": ""}
    if not vector:
        return result

    calc = compute_fn(vector, cve_id="")
    if calc.get("parse_error"):
        result["error"] = calc["parse_error"]
        return result

    result["base"] = calc["base_score"]
    result["impact"] = calc["impact_subscore"]
    result["exploit"] = calc["exploitability_subscore"]
    result["temporal"] = calc["temporal_score"]
    result["environmental"] = calc["environmental_score"]

    if published_score is not None:
        try:
            result["mismatch"] = "yes" if abs(float(published_score) - result["base"]) > 0.1 else "no"
        except (TypeError, ValueError):
            result["mismatch"] = ""
    return result


def extract_technical_info(data):
    meta = data.get("cveMetadata", {}) or {}
    description = ""
    cwe_ids = []
    products = []
    cpes = []

    cvss_v2 = None
    cvss_v30 = None
    cvss_v31 = None

    containers = get_all_containers(data)
    for label, container in containers:
        if not description:
            description = pick_description(container)
        cwe_ids.extend(extract_cwe_ids(container))

        cvss = extract_cvss_metrics(container)
        if cvss_v2 is None and cvss["v2"] is not None:
            cvss_v2 = cvss["v2"]
        if cvss_v30 is None and cvss["v30"] is not None:
            cvss_v30 = cvss["v30"]
        if cvss_v31 is None and cvss["v31"] is not None:
            cvss_v31 = cvss["v31"]

        p, c = summarize_affected(container)
        products.extend(p)
        cpes.extend(c)

    cvss_v2 = cvss_v2 or {}
    cvss_v30 = cvss_v30 or {}
    cvss_v31 = cvss_v31 or {}

    v2_score = cvss_v2.get("score")
    v30_score = cvss_v30.get("score")
    v31_score = cvss_v31.get("score")

    # --- Tinh VA kiem tra DOC LAP ca 3 phien ban, bat ke phien ban nao se duoc
    # "chon" ben duoi. Day chinh la phan "kiem tra toan bo truoc khi lam". ---
    check_v2 = _compute_and_check(cvss_v2.get("vector", ""), v2_score, compute_v20)
    check_v30 = _compute_and_check(cvss_v30.get("vector", ""), v30_score, compute_v30)
    check_v31 = _compute_and_check(cvss_v31.get("vector", ""), v31_score, compute_v31)

    # --- Cac cot "cvss_v3_*" (giu ten cu de tuong thich nguoc): neu 1 CVE co CA
    # 3.0 lan 3.1, uu tien hien thi 3.1 (dung thu tu uu tien yeu cau). ---
    if cvss_v31.get("vector"):
        v3_display, v3_check = cvss_v31, check_v31
    elif cvss_v30.get("vector"):
        v3_display, v3_check = cvss_v30, check_v30
    else:
        v3_display, v3_check = {}, check_v31  # rong ca hai -> check rong

    v3_score_display = v3_display.get("score")
    v3_severity_display = v3_display.get("severity") or cvss_v3_severity_from_score(
        v3_check["base"] if v3_check["base"] != "" else v3_score_display
    )

    # --- "cvss_final_*": diem duoc CHON theo dung thu tu uu tien yeu cau
    # 3.1 -> 3.0 -> 2.0, chi roi xuong phien ban thap hon khi phien ban cao hon
    # HOAN TOAN khong co vectorString (khong phai vi loi parse). ---
    if cvss_v31.get("vector"):
        final_version, final_vector, final_check = "3.1", cvss_v31["vector"], check_v31
        final_severity = cvss_v31.get("severity") or cvss_v3_severity_from_score(final_check["base"])
        final_published = v31_score
    elif cvss_v30.get("vector"):
        final_version, final_vector, final_check = "3.0", cvss_v30["vector"], check_v30
        final_severity = cvss_v30.get("severity") or cvss_v3_severity_from_score(final_check["base"])
        final_published = v30_score
    elif cvss_v2.get("vector"):
        final_version, final_vector, final_check = "2.0", cvss_v2["vector"], check_v2
        final_severity = cvss_v2_severity(final_check["base"] if final_check["base"] != "" else v2_score)
        final_published = v2_score
    else:
        final_version, final_vector, final_check, final_published = "", "", check_v2, None
        final_severity = ""

    final_score = final_check["base"] if final_check["base"] != "" else (
        "" if final_published is None else final_published
    )

    return {
        "state": meta.get("state", ""),
        "date_published": meta.get("datePublished", ""),
        "date_updated": meta.get("dateUpdated", ""),
        "assigner": meta.get("assignerShortName", ""),
        "description_en": description,
        "cwe_ids": join_field(cwe_ids),

        "cvss_v2_score": "" if v2_score is None else v2_score,
        "cvss_v2_vector": cvss_v2.get("vector", ""),
        "cvss_v2_severity": cvss_v2_severity(v2_score),
        "cvss_v2_access_vector": cvss_v2.get("access_vector", ""),
        "cvss_v2_access_complexity": cvss_v2.get("access_complexity", ""),
        "cvss_v2_authentication": cvss_v2.get("authentication", ""),
        "cvss_v2_confidentiality_impact": cvss_v2.get("confidentiality_impact", ""),
        "cvss_v2_integrity_impact": cvss_v2.get("integrity_impact", ""),
        "cvss_v2_availability_impact": cvss_v2.get("availability_impact", ""),
        "cvss_v2_exploitability_score": cvss_v2.get("exploitability_score", ""),
        "cvss_v2_impact_score": cvss_v2.get("impact_score", ""),
        "cvss_v2_computed_base_score": check_v2["base"],
        "cvss_v2_computed_impact_subscore": check_v2["impact"],
        "cvss_v2_computed_exploitability_subscore": check_v2["exploit"],
        "cvss_v2_computed_temporal_score": check_v2["temporal"],
        "cvss_v2_computed_environmental_score": check_v2["environmental"],
        "cvss_v2_score_mismatch": check_v2["mismatch"],
        "cvss_v2_compute_error": check_v2["error"],

        "cvss_v3_score": "" if v3_score_display is None else v3_score_display,
        "cvss_v3_vector": v3_display.get("vector", ""),
        "cvss_v3_severity": v3_severity_display,
        "cvss_v3_version": v3_display.get("version", ""),
        "cvss_v3_attack_vector": v3_display.get("attack_vector", ""),
        "cvss_v3_attack_complexity": v3_display.get("attack_complexity", ""),
        "cvss_v3_privileges_required": v3_display.get("privileges_required", ""),
        "cvss_v3_user_interaction": v3_display.get("user_interaction", ""),
        "cvss_v3_scope": v3_display.get("scope", ""),
        "cvss_v3_confidentiality_impact": v3_display.get("confidentiality_impact", ""),
        "cvss_v3_integrity_impact": v3_display.get("integrity_impact", ""),
        "cvss_v3_availability_impact": v3_display.get("availability_impact", ""),
        "cvss_v3_computed_base_score": v3_check["base"],
        "cvss_v3_computed_impact_subscore": v3_check["impact"],
        "cvss_v3_computed_exploitability_subscore": v3_check["exploit"],
        "cvss_v3_computed_temporal_score": v3_check["temporal"],
        "cvss_v3_computed_environmental_score": v3_check["environmental"],
        "cvss_v3_score_mismatch": v3_check["mismatch"],
        "cvss_v3_compute_error": v3_check["error"],

        "cvss_v30_found": "yes" if cvss_v30.get("vector") else "no",
        "cvss_v30_vector": cvss_v30.get("vector", ""),
        "cvss_v30_score": "" if v30_score is None else v30_score,
        "cvss_v30_computed_base_score": check_v30["base"],
        "cvss_v30_score_mismatch": check_v30["mismatch"],
        "cvss_v30_compute_error": check_v30["error"],

        "cvss_v31_found": "yes" if cvss_v31.get("vector") else "no",
        "cvss_v31_vector": cvss_v31.get("vector", ""),
        "cvss_v31_score": "" if v31_score is None else v31_score,
        "cvss_v31_computed_base_score": check_v31["base"],
        "cvss_v31_score_mismatch": check_v31["mismatch"],
        "cvss_v31_compute_error": check_v31["error"],

        "cvss_final_version": final_version,
        "cvss_final_vector": final_vector,
        "cvss_final_score": final_score,
        "cvss_final_severity": final_severity,
        "cvss_final_impact_subscore": final_check["impact"],
        "cvss_final_exploitability_subscore": final_check["exploit"],
        "cvss_final_temporal_score": final_check["temporal"],
        "cvss_final_environmental_score": final_check["environmental"],
        "cvss_final_compute_error": final_check["error"],

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
    try:
        return True, process_cve_file(path)
    except Exception as e:
        return False, (str(path), str(e))


def run_concurrent(files, workers, label="file"):

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

    score_mismatch_count = sum(1 for r in rows if r.get("cvss_v3_score_mismatch") == "yes")
    if score_mismatch_count:
        print(
            f"[!] Cảnh báo: {score_mismatch_count} CVE có base_score công bố lệch >0.1 điểm "
            f"so với điểm tự tính từ vectorString v3 hiển thị (cột cvss_v3_score_mismatch=yes). "
            f"Có thể do vectorString/baseScore trong JSON gốc không khớp nhau.",
            file=sys.stderr,
        )

    v2_mismatch_count = sum(1 for r in rows if r.get("cvss_v2_score_mismatch") == "yes")
    if v2_mismatch_count:
        print(
            f"[!] Cảnh báo: {v2_mismatch_count} CVE có CVSS v2 base_score công bố lệch >0.1 điểm "
            f"so với điểm tự tính (cột cvss_v2_score_mismatch=yes).",
            file=sys.stderr,
        )

    both_v3_count = sum(1 for r in rows if r.get("cvss_v30_found") == "yes" and r.get("cvss_v31_found") == "yes")
    if both_v3_count:
        print(
            f"[i] Ghi chú: {both_v3_count} CVE có CẢ vectorString CVSS v3.0 lẫn v3.1 "
            f"(xem cột cvss_v30_* / cvss_v31_* để đối chiếu). Cột cvss_v3_* đã ưu tiên hiển thị v3.1.",
            file=sys.stderr,
        )

    compute_error_count = sum(
        1 for r in rows
        if r.get("cvss_v3_compute_error") or r.get("cvss_v2_compute_error")
        or r.get("cvss_v30_compute_error") or r.get("cvss_v31_compute_error")
    )
    if compute_error_count:
        print(
            f"[!] Cảnh báo: {compute_error_count} CVE có ít nhất 1 vectorString (v2/v3.0/v3.1) "
            f"không parse được, nên thiếu điểm tự tính cho phiên bản đó.",
            file=sys.stderr,
        )

    final_v31 = sum(1 for r in rows if r.get("cvss_final_version") == "3.1")
    final_v30 = sum(1 for r in rows if r.get("cvss_final_version") == "3.0")
    final_v2 = sum(1 for r in rows if r.get("cvss_final_version") == "2.0")
    final_none = sum(1 for r in rows if r.get("cvss_final_version") == "")
    print(
        f"[*] Điểm CVSS cuối cùng (ưu tiên 3.1 -> 3.0 -> 2.0, cột cvss_final_*): "
        f"{final_v31} dùng v3.1, {final_v30} dùng v3.0, {final_v2} dùng v2.0, "
        f"{final_none} không có vectorString nào."
    )

    for row in rows[:20]:
        print("=" * 90)
        print(f"CVE: {row['cve_id']} [{row.get('json_status', 'found')}]")
        if row.get("description_en"):
            desc = row["description_en"]
            print(f"  Mô tả: {desc[:160]}{'...' if len(desc) > 160 else ''}")
        if row.get("cvss_final_version"):
            print(
                f"  CVSS được chọn (v{row['cvss_final_version']}, ưu tiên 3.1->3.0->2.0): "
                f"{row['cvss_final_score']} ({row['cvss_final_severity']}) {row['cvss_final_vector']}"
            )
            if row.get("cvss_final_compute_error"):
                print(f"    -> [WARN] Không tính được điểm: {row['cvss_final_compute_error']}")
        if row.get("cvss_v3_score") != "":
            print(f"  CVSS v3 ({row.get('cvss_v3_version') or '?'}): {row['cvss_v3_score']} ({row['cvss_v3_severity']}) {row['cvss_v3_vector']}")
            print(f"    AV={row['cvss_v3_attack_vector']}  AC={row['cvss_v3_attack_complexity']}  "
                  f"PR={row['cvss_v3_privileges_required']}  UI={row['cvss_v3_user_interaction']}  "
                  f"Scope={row['cvss_v3_scope']}  C={row['cvss_v3_confidentiality_impact']}  "
                  f"I={row['cvss_v3_integrity_impact']}  A={row['cvss_v3_availability_impact']}")
            if row.get("cvss_v3_computed_base_score") != "":
                mismatch_note = "  [!] LECH VOI DIEM CONG BO" if row.get("cvss_v3_score_mismatch") == "yes" else ""
                print(f"    -> Tu tinh: base={row['cvss_v3_computed_base_score']}  "
                      f"impact_subscore={row['cvss_v3_computed_impact_subscore']}  "
                      f"exploitability_subscore={row['cvss_v3_computed_exploitability_subscore']}{mismatch_note}")
            elif row.get("cvss_v3_compute_error"):
                print(f"    -> [WARN] Khong tinh duoc diem: {row['cvss_v3_compute_error']}")
        elif row.get("cvss_v2_score") != "":
            print(f"  CVSS v2: {row['cvss_v2_score']} ({row['cvss_v2_severity']}) {row['cvss_v2_vector']}")
            print(f"    AV={row['cvss_v2_access_vector']}  AC={row['cvss_v2_access_complexity']}  "
                  f"Au={row['cvss_v2_authentication']}")
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