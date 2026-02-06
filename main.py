from fastapi import FastAPI, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

import io
import os
import re
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

# PDF анализ
from pypdf import PdfReader
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

# URL анализ
import tldextract

# Превью PDF -> PNG
from pdf2image import convert_from_bytes

# ИИ (только для VERIFY)
from google import genai

# -------------------------------
# КОНФИГУРАЦИЯ
# -------------------------------

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
BASE_URL = os.environ.get("BASE_URL", "https://gmail-delulu-pdf.onrender.com")

CTA_KEYWORDS = [
    "срочно", "urgent", "verify", "подтвердить", "login", "вход",
    "оплатить", "pay", "winner", "выигрыш", "счет", "invoice",
    "пароль", "password", "account", "аккаунт", "security check", "проверка"
]

BRAND_KEYWORDS = [
    "банк", "bank", "гос", "gosuslugi", "почта", "mail",
    "доставка", "delivery", "логин", "login", "sso", "auth", "signin"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "clck.ru", "tiny.cc", "ow.ly"
}

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "cn"}

app = FastAPI()

os.makedirs("static/previews", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------------
# УТИЛИТЫ
# -------------------------------

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def new_analysis_id() -> str:
    return f"an_{uuid.uuid4().hex[:16]}"


def safe_lower(text: str) -> str:
    return (text or "").lower()


def contains_any(text: str, words: List[str]) -> bool:
    t = safe_lower(text)
    return any(w in t for w in words)


def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    pattern = r'(https?://[^\s<>"\]\)]+)'
    return re.findall(pattern, text, flags=re.IGNORECASE)


def normalize_domain(url: str) -> Tuple[str, str]:
    info = tldextract.extract(url)
    domain = f"{info.domain}.{info.suffix}".strip(".").lower()
    suffix = (info.suffix or "").lower()
    return domain, suffix


def is_ip_url(url: str) -> bool:
    return re.search(r'https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)', url, re.IGNORECASE) is not None


def has_at_in_url_host_like(url: str) -> bool:
    return "@" in url


def build_preview_url(filename: str) -> str:
    return f"{BASE_URL}/static/previews/{filename}"


def is_real_pdf(content: bytes) -> bool:
    """
    Ранняя проверка "реально ли это PDF".
    Ищем сигнатуру %PDF- в первых 1024 байтах.
    """
    head = content[:1024]
    return b"%PDF-" in head


# -------------------------------
# PDF ТЕХНИЧЕСКИЙ АНАЛИЗ
# -------------------------------

def analyze_pdf_structure_with_pdfminer(pdf_stream: io.BytesIO) -> Dict[str, Any]:
    result = {
        "js": False,
        "open_action": False,
        "aa": False,
        "launch": False,
        "submitform": False,
        "importdata": False,
        "embedded_file": False,
        "malformed_pdf": False,
        "notes": []
    }

    try:
        pdf_stream.seek(0)
        parser = PDFParser(pdf_stream)
        doc = PDFDocument(parser)
        catalog = doc.catalog or {}
        keys = set(str(k) for k in catalog.keys())

        if "/OpenAction" in keys or "OpenAction" in keys:
            result["open_action"] = True
        if "/AA" in keys or "AA" in keys:
            result["aa"] = True
        if "/JavaScript" in keys or "JavaScript" in keys or "/JS" in keys or "JS" in keys:
            result["js"] = True

        pdf_stream.seek(0)
        raw = pdf_stream.read()

        if b"/JavaScript" in raw or b"/JS" in raw:
            result["js"] = True
        if b"/OpenAction" in raw:
            result["open_action"] = True
        if b"/AA" in raw:
            result["aa"] = True
        if b"/Launch" in raw:
            result["launch"] = True
        if b"/SubmitForm" in raw:
            result["submitform"] = True
        if b"/ImportData" in raw:
            result["importdata"] = True
        if b"/EmbeddedFile" in raw:
            result["embedded_file"] = True

    except Exception as e:
        result["malformed_pdf"] = True
        result["notes"].append(f"pdfminer_error: {e}")

    return result


def hard_malware_triggers(struct_flags: Dict[str, Any]) -> List[str]:
    reasons = []
    if struct_flags.get("js"):
        reasons.append("JavaScript/JS object detected")
    if struct_flags.get("open_action"):
        reasons.append("OpenAction detected (auto-run)")
    if struct_flags.get("aa"):
        reasons.append("AA detected (additional actions)")
    if struct_flags.get("launch"):
        reasons.append("Launch action detected")
    if struct_flags.get("submitform"):
        reasons.append("SubmitForm action detected")
    if struct_flags.get("importdata"):
        reasons.append("ImportData action detected")
    return reasons


# -------------------------------
# АНАЛИЗ ССЫЛОК
# -------------------------------

def analyze_links(links: List[str], full_text: str) -> Dict[str, Any]:
    malware_reasons = []
    verify_reasons = []
    annotated_links = []

    text_lower = safe_lower(full_text)
    has_cta = contains_any(text_lower, CTA_KEYWORDS)
    has_brand_words = contains_any(text_lower, BRAND_KEYWORDS)

    seen = set()
    dedup_links = []
    for l in links:
        ll = (l or "").strip()
        if ll and ll not in seen:
            dedup_links.append(ll)
            seen.add(ll)

    for link in dedup_links:
        domain, suffix = normalize_domain(link)
        link_lower = safe_lower(link)

        is_shortener = domain in SHORTENERS
        has_punycode = "xn--" in link_lower or domain.startswith("xn--")
        ip_url = is_ip_url(link)
        has_at = has_at_in_url_host_like(link)
        suspicious_tld = suffix in SUSPICIOUS_TLDS if suffix else False

        link_status = "normal"
        link_notes = []

        # MALWARE комбинации
        if is_shortener and has_cta:
            malware_reasons.append(f"Shortener + CTA: {domain}")
            link_status = "suspicious"
            link_notes.append("shortener+cta")

        if has_punycode and has_brand_words:
            malware_reasons.append("Punycode URL + brand impersonation context")
            link_status = "suspicious"
            link_notes.append("punycode+brand")

        if ip_url and has_cta:
            malware_reasons.append("IP URL + CTA")
            link_status = "suspicious"
            link_notes.append("ip+cta")

        if has_at and has_cta:
            malware_reasons.append("@ in URL + CTA")
            link_status = "suspicious"
            link_notes.append("at+cta")

        # VERIFY сигналы
        if is_shortener and not has_cta:
            verify_reasons.append(f"Shortener without CTA: {domain}")
            link_status = "suspicious"
            link_notes.append("shortener")

        if has_punycode and not has_brand_words:
            verify_reasons.append("Punycode URL without brand context")
            link_status = "suspicious"
            link_notes.append("punycode")

        if ip_url and not has_cta:
            verify_reasons.append("IP URL without CTA")
            link_status = "suspicious"
            link_notes.append("ip-url")

        if suspicious_tld:
            verify_reasons.append(f"Suspicious TLD: .{suffix}")
            link_status = "suspicious"
            link_notes.append("suspicious-tld")

        annotated_links.append({
            "url": link,
            "domain": domain,
            "status": link_status,
            "notes": link_notes
        })

    # CTA без hard evidence -> VERIFY
    if has_cta and not malware_reasons:
        verify_reasons.append("Phishing-like CTA language detected in text")

    return {
        "malware_reasons": list(dict.fromkeys(malware_reasons)),
        "verify_reasons": list(dict.fromkeys(verify_reasons)),
        "annotated_links": annotated_links
    }


# -------------------------------
# ПРЕВЬЮ
# -------------------------------

def generate_previews(pdf_bytes: bytes) -> List[str]:
    urls = []
    try:
        images = convert_from_bytes(pdf_bytes, first_page=1, last_page=2, fmt="png")
        for i, img in enumerate(images, start=1):
            filename = f"{uuid.uuid4().hex}_page_{i}.png"
            save_path = os.path.join("static", "previews", filename)
            img.save(save_path, "PNG")
            urls.append(build_preview_url(filename))
    except Exception as e:
        print(f"[WARN] Preview generation failed: {e}")
        return []
    return urls


# -------------------------------
# ИИ только для VERIFY
# -------------------------------

def ai_verify_analysis(extracted_text: str, links: List[str], tech_info: Dict[str, Any]) -> Dict[str, str]:
    if not GEMINI_API_KEY:
        return {"final_status": "VERIFY", "reason": "AI key missing; keeping VERIFY by policy."}

    prompt = f"""
Ты аналитик SOC. Есть PDF, который правилами уже классифицирован как VERIFY.
Дай финальный статус: CLEAN, VERIFY или MALWARE.

Текст (фрагмент): {extracted_text[:3000]}
Ссылки: {links[:30]}
Тех.флаги: {json.dumps(tech_info, ensure_ascii=False)}

Верни строго JSON:
{{
  "final_status": "CLEAN|VERIFY|MALWARE",
  "reason": "короткое объяснение на русском"
}}
"""

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config={"response_mime_type": "application/json"}
        )

        parsed = json.loads(response.text)
        final_status = parsed.get("final_status", "VERIFY")
        reason = parsed.get("reason", "AI returned no reason")

        if final_status not in {"CLEAN", "VERIFY", "MALWARE"}:
            return {"final_status": "VERIFY", "reason": f"Invalid AI status, fallback VERIFY. {reason}"}

        return {"final_status": final_status, "reason": reason}

    except Exception as e:
        return {"final_status": "VERIFY", "reason": f"AI error; keeping VERIFY. Details: {e}"}


# -------------------------------
# ENDPOINT
# -------------------------------

@app.get("/")
def health_root():
    return {"ok": True, "service": "pdf-analyzer", "version": "1.0.0"}


@app.post("/analyze_pdf")
async def analyze_pdf(
    file: UploadFile = File(...),
    sender_email: str = Form(...),
    subject: str = Form(""),
    received_at: str = Form(""),
    message_id: str = Form(""),
    thread_id: str = Form("")
):
    analysis_id = new_analysis_id()

    # 0) Чтение файла
    try:
        contents = await file.read()
        if not contents:
            return JSONResponse(status_code=400, content={"status": "ERROR", "message": "Empty file"})
        pdf_stream = io.BytesIO(contents)
        sha256 = calculate_sha256(contents)
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "ERROR", "message": f"File read error: {e}"})

    # Базовый отчет
    report: Dict[str, Any] = {
        "analysis_id": analysis_id,
        "header": {
            "subject": subject or "(no subject)",
            "sender": sender_email,
            "received_at": received_at or "",
            "attachment": {
                "filename": file.filename,
                "size_bytes": len(contents),
                "sha256": sha256
            },
            "message_id": message_id or "",
            "thread_id": thread_id or ""
        },
        "status": "CLEAN",
        "reasons": [],
        "tech_details": {
            "flags": {
                "js": False,
                "open_action": False,
                "aa": False,
                "launch": False,
                "submitform": False,
                "importdata": False,
                "embedded_file": False,
                "malformed_pdf": False
            },
            "links": [],
            "preview_urls": []
        }
    }

    # 0.1) Ранняя проверка "это вообще PDF?"
    if not is_real_pdf(contents):
        report["status"] = "VERIFY"
        report["reasons"].append("File extension is .pdf but content is not a valid PDF")
        report["analyzed_at_utc"] = datetime.now(timezone.utc).isoformat()
        return report

    extracted_text = ""
    extracted_links: List[str] = []

    # 1) Извлечение текста и ссылок (pypdf)
    try:
        pdf_stream.seek(0)
        reader = PdfReader(pdf_stream)

        for page in reader.pages:
            page_text = page.extract_text() or ""
            extracted_text += page_text + "\n"

            if "/Annots" in page:
                for annot in page["/Annots"]:
                    obj = annot.get_object()
                    if "/A" in obj and "/URI" in obj["/A"]:
                        extracted_links.append(str(obj["/A"]["/URI"]))

            extracted_links.extend(extract_urls_from_text(page_text))

        extracted_links = list(dict.fromkeys([u.strip() for u in extracted_links if u.strip()]))

    except Exception as e:
        report["status"] = "VERIFY"
        report["reasons"].append(f"PDF parsing error (pypdf): {e}")

    # 2) Технический анализ структуры
    struct_flags = analyze_pdf_structure_with_pdfminer(pdf_stream)
    report["tech_details"]["flags"] = {
        "js": struct_flags["js"],
        "open_action": struct_flags["open_action"],
        "aa": struct_flags["aa"],
        "launch": struct_flags["launch"],
        "submitform": struct_flags["submitform"],
        "importdata": struct_flags["importdata"],
        "embedded_file": struct_flags["embedded_file"],
        "malformed_pdf": struct_flags["malformed_pdf"]
    }

    if struct_flags["malformed_pdf"] and report["status"] == "CLEAN":
        report["status"] = "VERIFY"
        report["reasons"].append("Malformed PDF structure")

    hard_reasons = hard_malware_triggers(struct_flags)
    if hard_reasons:
        report["status"] = "MALWARE"
        report["reasons"].extend(hard_reasons)

    if report["status"] != "MALWARE" and struct_flags["embedded_file"]:
        if report["status"] == "CLEAN":
            report["status"] = "VERIFY"
        report["reasons"].append("EmbeddedFile detected without active action (manual verification required)")

    # 3) Анализ ссылок + CTA
    link_result = analyze_links(extracted_links, extracted_text)
    report["tech_details"]["links"] = link_result["annotated_links"]

    if report["status"] != "MALWARE":
        if link_result["malware_reasons"]:
            report["status"] = "MALWARE"
            report["reasons"].extend(link_result["malware_reasons"])
        elif link_result["verify_reasons"]:
            if report["status"] == "CLEAN":
                report["status"] = "VERIFY"
            report["reasons"].extend(link_result["verify_reasons"])

    # 4) Превью
    report["tech_details"]["preview_urls"] = generate_previews(contents)

    # 5) ИИ только для VERIFY
    if report["status"] == "VERIFY":
        ai_result = ai_verify_analysis(
            extracted_text=extracted_text,
            links=extracted_links,
            tech_info=report["tech_details"]["flags"]
        )
        ai_status = ai_result.get("final_status", "VERIFY")
        ai_reason = ai_result.get("reason", "No reason")

        if ai_status in {"CLEAN", "VERIFY", "MALWARE"}:
            report["status"] = ai_status
        report["reasons"].append(f"AI verdict: {ai_reason}")

    # 6) Если чисто и причин нет
    if report["status"] == "CLEAN" and not report["reasons"]:
        report["reasons"].append("No active content, no suspicious links, no phishing-like CTA detected.")

    report["reasons"] = list(dict.fromkeys(report["reasons"]))[:7]
    report["analyzed_at_utc"] = datetime.now(timezone.utc).isoformat()

    return report
