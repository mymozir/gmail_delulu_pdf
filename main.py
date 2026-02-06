from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
import io
import os
import re
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any

from pypdf import PdfReader
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from google import genai


# =========================
# CONFIG
# =========================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

CTA_WORDS = [
    "срочно", "urgent", "подтвердить", "verify", "вход", "login",
    "оплатить", "pay", "пароль", "password", "аккаунт", "account",
    "invoice", "счет"
]

app = FastAPI()


# =========================
# HELPERS
# =========================
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_real_pdf(data: bytes) -> bool:
    """Ранняя проверка: файл действительно похож на PDF."""
    return b"%PDF-" in data[:1024]


def unique(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def safe_snippet(value: Any, max_len: int = 500) -> str:
    try:
        s = str(value)
    except Exception:
        s = repr(value)
    return s[:max_len]


def parse_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r'https?://[^\s<>"\]\)]+', text, flags=re.IGNORECASE)


def contains_cta(text: str) -> bool:
    t = (text or "").lower()
    return any(w in t for w in CTA_WORDS)


# =========================
# THREAT DETECTION
# =========================
def check_technical_threats(pdf_bytes: bytes, doc: PDFDocument) -> List[Dict[str, str]]:
    """
    Ищет жесткие техпризнаки MALWARE.
    Возвращает список:
    [
      {"type": "...", "quote": "..."},
      ...
    ]
    """
    threats: List[Dict[str, str]] = []
    catalog = doc.catalog or {}

    # Ключи бывают со слешем и без
    keys = set(str(k) for k in catalog.keys())

    # OpenAction
    if "/OpenAction" in keys or "OpenAction" in keys:
        val = catalog.get("/OpenAction") if "/OpenAction" in catalog else catalog.get("OpenAction")
        threats.append({
            "type": "OpenAction (Auto-Run)",
            "quote": safe_snippet(val)
        })

    # AA
    if "/AA" in keys or "AA" in keys:
        val = catalog.get("/AA") if "/AA" in catalog else catalog.get("AA")
        threats.append({
            "type": "AA (Additional Actions)",
            "quote": safe_snippet(val)
        })

    # JavaScript / JS
    if "/JavaScript" in keys or "JavaScript" in keys or "/JS" in keys or "JS" in keys:
        val = (
            catalog.get("/JavaScript")
            or catalog.get("JavaScript")
            or catalog.get("/JS")
            or catalog.get("JS")
        )
        threats.append({
            "type": "JavaScript/JS object",
            "quote": safe_snippet(val)
        })

    # Fallback по сырым байтам
    raw_markers = [
        (b"/JavaScript", "JavaScript marker"),
        (b"/JS", "JS marker"),
        (b"/OpenAction", "OpenAction marker"),
        (b"/AA", "AA marker"),
        (b"/Launch", "Launch action marker"),
        (b"/SubmitForm", "SubmitForm action marker"),
        (b"/ImportData", "ImportData action marker"),
    ]

    for marker, label in raw_markers:
        idx = pdf_bytes.find(marker)
        if idx != -1:
            start = max(0, idx - 80)
            end = min(len(pdf_bytes), idx + 220)
            quote = pdf_bytes[start:end].decode("latin-1", errors="ignore")
            threats.append({
                "type": label,
                "quote": quote[:500]
            })

    # Уникализируем
    uniq: List[Dict[str, str]] = []
    seen = set()
    for t in threats:
        key = (t["type"], t["quote"])
        if key not in seen:
            seen.add(key)
            uniq.append(t)

    return uniq


def evaluate_links_and_context(links: List[str], text: str) -> Dict[str, List[str]]:
    """
    Мягкие признаки для VERIFY/MALWARE по ссылкам + CTA.
    """
    verify_reasons: List[str] = []
    malware_reasons: List[str] = []

    text_l = (text or "").lower()
    has_cta = contains_cta(text_l)

    for link in links:
        l = link.lower()

        has_shortener = any(s in l for s in ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "clck.ru"])
        has_puny = "xn--" in l
        has_ip = re.search(r'https?://\d{1,3}(?:\.\d{1,3}){3}', l) is not None
        has_at = "@" in l

        # MALWARE-комбинации только с CTA
        if has_cta and has_shortener:
            malware_reasons.append(f"Shortener + CTA: {link}")
        if has_cta and has_ip:
            malware_reasons.append(f"IP URL + CTA: {link}")
        if has_cta and has_at:
            malware_reasons.append(f"'@' in URL + CTA: {link}")
        if has_cta and has_puny:
            malware_reasons.append(f"Punycode + CTA: {link}")

        # VERIFY-мягкие признаки
        if has_shortener and not has_cta:
            verify_reasons.append(f"Shortener URL: {link}")
        if has_ip and not has_cta:
            verify_reasons.append(f"IP URL: {link}")
        if has_puny and not has_cta:
            verify_reasons.append(f"Punycode URL: {link}")
        if has_at and not has_cta:
            verify_reasons.append(f"'@' in URL: {link}")

    if has_cta and not malware_reasons:
        verify_reasons.append("CTA language detected in text")

    return {
        "verify_reasons": unique(verify_reasons),
        "malware_reasons": unique(malware_reasons),
    }


# =========================
# AI (ONLY VERIFY)
# =========================
def ask_gemini_verify(
    sender: str,
    auth_results: str,
    text: str,
    links: List[str],
    reasons: List[str]
) -> Dict[str, str]:
    """
    Вызывается ТОЛЬКО для VERIFY.
    Возвращает JSON-структуру:
    {"final_status": "CLEAN|VERIFY|MALWARE", "reason": "..."}
    """
    if not GEMINI_API_KEY:
        return {"final_status": "VERIFY", "reason": "AI key missing, keep VERIFY"}

    prompt = f"""
Ты SOC-аналитик. Документ уже помечен как VERIFY правилами.
Нужно дать финальный вывод.

Отправитель: {sender}
Auth results: {auth_results}
Ссылки: {links[:20]}
Причины rules: {reasons[:12]}
Текст (фрагмент): {text[:2200]}

Верни строго JSON:
{{
  "final_status": "CLEAN|VERIFY|MALWARE",
  "reason": "краткое объяснение по-русски"
}}
"""

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        resp = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(resp.text)

        status = str(parsed.get("final_status", "VERIFY")).upper().strip()
        reason = str(parsed.get("reason", "No reason")).strip()

        if status not in {"CLEAN", "VERIFY", "MALWARE"}:
            return {"final_status": "VERIFY", "reason": f"Invalid AI status: {status}"}

        return {"final_status": status, "reason": reason}

    except Exception as e:
        return {"final_status": "VERIFY", "reason": f"AI error: {e}"}


# =========================
# ROUTES
# =========================
@app.get("/")
def health():
    return {"ok": True, "service": "gmail-delulu-pdf", "time_utc": datetime.now(timezone.utc).isoformat()}


@app.post("/analyze_pdf")
async def analyze_pdf(
    file: UploadFile = File(...),
    sender_email: str = Form(...),
    auth_results: str = Form(""),
    subject: str = Form(""),
    received_at: str = Form(""),
    message_id: str = Form(""),
    thread_id: str = Form("")
):
    # 0) Read file
    try:
        contents = await file.read()
        if not contents:
            return JSONResponse(status_code=400, content={"status": "ERROR", "message": "Empty file"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "ERROR", "message": f"Read error: {e}"})

    report: Dict[str, Any] = {
        "status": "CLEAN",
        "header": {
            "subject": subject or "(no subject)",
            "sender": sender_email,
            "received_at": received_at or "",
            "attachment": {
                "filename": file.filename,
                "size_bytes": len(contents),
                "sha256": sha256_hex(contents),
            },
            "message_id": message_id or "",
            "thread_id": thread_id or "",
        },
        "reasons": [],
        "technical_findings": [],   # type + quote
        "admin_summary": "",
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    # 0.1) Early file-type check
    if not is_real_pdf(contents):
        report["status"] = "VERIFY"
        report["reasons"].append("File has .pdf extension but content is not a valid PDF header")
        report["admin_summary"] = "🟡 VERIFY: невалидный PDF-формат, нужна ручная проверка"
        return report

    extracted_text = ""
    links: List[str] = []

    # 1) Extract text + links (pypdf)
    try:
        reader = PdfReader(io.BytesIO(contents))

        for page in reader.pages:
            text = page.extract_text() or ""
            extracted_text += text + "\n"

            # annots links
            if "/Annots" in page:
                for annot in page["/Annots"]:
                    obj = annot.get_object()
                    if "/A" in obj and "/URI" in obj["/A"]:
                        links.append(str(obj["/A"]["/URI"]))

            # raw links in text
            links.extend(parse_urls_from_text(text))

        links = unique([u.strip() for u in links if u.strip()])

    except Exception as e:
        if report["status"] == "CLEAN":
            report["status"] = "VERIFY"
        report["reasons"].append(f"PDF parsing error (pypdf): {e}")

    # 2) Technical malware checks (pdfminer)
    threats: List[Dict[str, str]] = []
    try:
        parser = PDFParser(io.BytesIO(contents))
        doc = PDFDocument(parser)
        threats = check_technical_threats(contents, doc)

        if threats:
            report["status"] = "MALWARE"
            report["technical_findings"] = threats
            for t in threats:
                report["reasons"].append(f"FOUND: {t['type']}; quote: {t['quote']}")
            report["admin_summary"] = "🔴 MALWARE (technical triggers found)"
    except Exception as e:
        # parsing issues => VERIFY (not auto-malware)
        if report["status"] == "CLEAN":
            report["status"] = "VERIFY"
        report["reasons"].append(f"pdfminer error: {e}")

    # 3) If not MALWARE, apply soft rules
    if report["status"] != "MALWARE":
        link_eval = evaluate_links_and_context(links, extracted_text)
        verify_reasons = link_eval["verify_reasons"]
        malware_reasons = link_eval["malware_reasons"]

        auth_fail = "fail" in (auth_results or "").lower()

        if auth_fail:
            verify_reasons.append("Authentication-Results contain FAIL")

        if malware_reasons:
            report["status"] = "MALWARE"
            report["reasons"].extend(malware_reasons)
            report["admin_summary"] = "🔴 MALWARE (link/context rule triggers)"

        elif verify_reasons:
            report["status"] = "VERIFY"
            report["reasons"].extend(verify_reasons)

            # AI only for VERIFY
            ai = ask_gemini_verify(
                sender=sender_email,
                auth_results=auth_results,
                text=extracted_text,
                links=links,
                reasons=report["reasons"]
            )
            ai_status = ai.get("final_status", "VERIFY")
            ai_reason = ai.get("reason", "")

            if ai_status in {"CLEAN", "VERIFY", "MALWARE"}:
                report["status"] = ai_status
            report["admin_summary"] = f"🟡 VERIFY + AI: {ai_reason}"
            report["reasons"].append(f"AI verdict: {ai_reason}")

        else:
            report["status"] = "CLEAN"
            report["admin_summary"] = "✅ CLEAN: no technical triggers, no suspicious context"

    # Final cleanup
    report["reasons"] = unique(report["reasons"])[:12]

    return report
