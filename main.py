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

# ВАЖНО: замени на свой актуальный публичный URL backend
BASE_URL = os.environ.get("BASE_URL", "https://gmail-delulu-pdf.onrender.com")

# Ключевые слова "призыв к действию" (CTA)
CTA_KEYWORDS = [
    "срочно", "urgent", "verify", "подтвердить", "login", "вход",
    "оплатить", "pay", "winner", "выигрыш", "счет", "invoice",
    "пароль", "password", "account", "аккаунт", "security check", "проверка"
]

# "Брендовые" слова для эвристики punycode-фишинга
BRAND_KEYWORDS = [
    "банк", "bank", "гос", "gosuslugi", "почта", "mail",
    "доставка", "delivery", "логин", "login", "sso", "auth", "signin"
]

# Shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "rb.gy", "clck.ru", "tiny.cc", "ow.ly"
}

# TLD из твоего предыдущего списка (как мягкий сигнал)
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "cn"}

# Маркеры активного содержимого в сыром PDF
RAW_ACTIVE_MARKERS = [
    b"/JavaScript", b"/JS", b"/OpenAction", b"/AA",
    b"/Launch", b"/SubmitForm", b"/ImportData"
]

app = FastAPI()

# Статика для превью
os.makedirs("static/previews", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# -------------------------------
# УТИЛИТЫ
# -------------------------------

def calculate_sha256(content: bytes) -> str:
    """SHA256 файла для идентификации вложения."""
    return hashlib.sha256(content).hexdigest()


def new_analysis_id() -> str:
    """Уникальный ID анализа (для логов, аудита, UI)."""
    return f"an_{uuid.uuid4().hex[:16]}"


def safe_lower(text: str) -> str:
    return (text or "").lower()


def contains_any(text: str, words: List[str]) -> bool:
    """Проверка: содержит ли текст хотя бы одно слово из списка."""
    t = safe_lower(text)
    return any(w in t for w in words)


def extract_urls_from_text(text: str) -> List[str]:
    """
    Резервное извлечение URL из текста страницы.
    Нужно потому, что не все PDF хранят ссылки в /Annots.
    """
    if not text:
        return []
    pattern = r'(https?://[^\s<>"\]\)]+)'
    return re.findall(pattern, text, flags=re.IGNORECASE)


def normalize_domain(url: str) -> Tuple[str, str]:
    """
    Возвращает:
    - registrable domain (например, example.com)
    - suffix (tld)
    """
    info = tldextract.extract(url)
    domain = f"{info.domain}.{info.suffix}".strip(".").lower()
    suffix = (info.suffix or "").lower()
    return domain, suffix


def is_ip_url(url: str) -> bool:
    return re.search(r'https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)', url, re.IGNORECASE) is not None


def has_at_in_url_host_like(url: str) -> bool:
    """
    Простая эвристика для user@host в URL.
    По твоему правилу: '@' + CTA => MALWARE.
    """
    return "@" in url


def build_preview_url(filename: str) -> str:
    return f"{BASE_URL}/static/previews/{filename}"


# -------------------------------
# PDF ТЕХНИЧЕСКИЙ АНАЛИЗ
# -------------------------------

def analyze_pdf_structure_with_pdfminer(pdf_stream: io.BytesIO) -> Dict[str, Any]:
    """
    Анализ структуры PDF через pdfminer:
    - попытка найти активные механизмы (по catalog + fallback по raw)
    - поиск EmbeddedFile
    """
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

        # В pdf словарях ключи часто идут с "/"
        keys = set(str(k) for k in catalog.keys())

        # Прямые ключи в catalog
        if "/OpenAction" in keys or "OpenAction" in keys:
            result["open_action"] = True

        if "/AA" in keys or "AA" in keys:
            result["aa"] = True

        # Проверка Names/JavaScript на верхнем уровне
        if "/JavaScript" in keys or "JavaScript" in keys or "/JS" in keys or "JS" in keys:
            result["js"] = True

        # Поиск в сырых байтах (fallback, часто надежнее для быстрых правил)
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
        # Если структура кривая — это минимум VERIFY
        result["malformed_pdf"] = True
        result["notes"].append(f"pdfminer_error: {e}")

    return result


def hard_malware_triggers(struct_flags: Dict[str, Any]) -> List[str]:
    """
    Правило 3.1 (жесткие признаки MALWARE):
    если есть хотя бы один активный механизм => MALWARE.
    """
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
# АНАЛИЗ ССЫЛОК ПО ПРАВИЛАМ
# -------------------------------

def analyze_links(links: List[str], full_text: str) -> Dict[str, Any]:
    """
    Делит сигналы на:
    - malware_reasons (жесткие комбинации)
    - verify_reasons (подозрительно, но не доказано)
    - annotated_links (для техблока отчета)
    """
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

        # ---- MALWARE комбинации по твоим правилам ----
        # shortener + CTA
        if is_shortener and has_cta:
            malware_reasons.append(f"Shortener + CTA: {domain}")
            link_status = "suspicious"
            link_notes.append("shortener+cta")

        # punycode + brand words
        if has_punycode and has_brand_words:
            malware_reasons.append("Punycode URL + brand impersonation context")
            link_status = "suspicious"
            link_notes.append("punycode+brand")

        # IP URL + CTA
        if ip_url and has_cta:
            malware_reasons.append("IP URL + CTA")
            link_status = "suspicious"
            link_notes.append("ip+cta")

        # @ in URL + CTA
        if has_at and has_cta:
            malware_reasons.append("@ in URL + CTA")
            link_status = "suspicious"
            link_notes.append("at+cta")

        # ---- VERIFY сигналы ----
        # shortener без CTA
        if is_shortener and not has_cta:
            verify_reasons.append(f"Shortener without CTA: {domain}")
            link_status = "suspicious"
            link_notes.append("shortener")

        # punycode без brand context
        if has_punycode and not has_brand_words:
            verify_reasons.append("Punycode URL without brand context")
            link_status = "suspicious"
            link_notes.append("punycode")

        # IP URL без CTA
        if ip_url and not has_cta:
            verify_reasons.append("IP URL without CTA")
            link_status = "suspicious"
            link_notes.append("ip-url")

        # suspicious tld как мягкий сигнал
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

    # Если в тексте есть явный CTA, но нет hard evidence — это минимум VERIFY
    cta_only_verify = False
    if has_cta and not malware_reasons:
        cta_only_verify = True
        verify_reasons.append("Phishing-like CTA language detected in text")

    return {
        "malware_reasons": list(dict.fromkeys(malware_reasons)),
        "verify_reasons": list(dict.fromkeys(verify_reasons)),
        "annotated_links": annotated_links,
        "has_cta": has_cta,
        "has_brand_words": has_brand_words,
        "cta_only_verify": cta_only_verify
    }


# -------------------------------
# ПРЕВЬЮ (2 СТРАНИЦЫ)
# -------------------------------

def generate_previews(pdf_bytes: bytes) -> List[str]:
    """
    Пытаемся отрендерить первые 2 страницы.
    Если Poppler недоступен — не падаем, возвращаем [].
    """
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
# ИИ ТОЛЬКО ДЛЯ VERIFY
# -------------------------------

def ai_verify_analysis(extracted_text: str, links: List[str], tech_info: Dict[str, Any]) -> Dict[str, str]:
    """
    Вызываем ИИ только если rule-engine вернул VERIFY.
    ИИ может:
    - оставить VERIFY
    - повысить до MALWARE
    - снизить до CLEAN
    """
    if not GEMINI_API_KEY:
        return {
            "final_status": "VERIFY",
            "reason": "AI key missing; keeping VERIFY by policy."
        }

    prompt = f"""
Ты аналитик SOC. Есть PDF, который правилами уже классифицирован как VERIFY.
Нужно дать финальный статус: CLEAN, VERIFY или MALWARE.

Контекст:
- Текст PDF (фрагмент): {extracted_text[:3000]}
- Ссылки: {links[:30]}
- Тех.флаги: {json.dumps(tech_info, ensure_ascii=False)}

Правила:
1) Если есть явная фишинговая цель (логин/оплата/подтверждение личности) и обманный контекст -> MALWARE.
2) Если документ нейтральный/информативный и риски слабые -> CLEAN.
3) Если есть сомнения без прямого доказательства -> VERIFY.

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
            final_status = "VERIFY"
            reason = f"AI returned invalid status; fallback VERIFY. Raw reason: {reason}"

        return {"final_status": final_status, "reason": reason}

    except Exception as e:
        return {
            "final_status": "VERIFY",
            "reason": f"AI error; keeping VERIFY. Details: {e}"
        }


# -------------------------------
# ОСНОВНОЙ ENDPOINT
# -------------------------------

@app.post("/analyze_pdf")
async def analyze_pdf(
    file: UploadFile = File(...),
    sender_email: str = Form(...),
    subject: str = Form(""),
    received_at: str = Form(""),
    message_id: str = Form(""),
    thread_id: str = Form("")
):
    """
    Основной обработчик:
    1) читает PDF
    2) извлекает текст + ссылки
    3) гонит rule-engine
    4) при VERIFY зовет ИИ
    5) возвращает отчет
    """

    analysis_id = new_analysis_id()

    # ---------- 0. Чтение файла ----------
    try:
        contents = await file.read()
        if not contents:
            return JSONResponse(
                status_code=400,
                content={"status": "ERROR", "message": "Empty file"}
            )
        pdf_stream = io.BytesIO(contents)
        sha256 = calculate_sha256(contents)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "ERROR", "message": f"File read error: {e}"}
        )

    # ---------- 1. База отчета ----------
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
        "status": "CLEAN",  # дефолт
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

    extracted_text = ""
    extracted_links: List[str] = []

    # ---------- 2. Извлечение текста/ссылок (pypdf) ----------
    try:
        pdf_stream.seek(0)
        reader = PdfReader(pdf_stream)

        for page in reader.pages:
            page_text = page.extract_text() or ""
            extracted_text += page_text + "\n"

            # Ссылки из аннотаций
            if "/Annots" in page:
                for annot in page["/Annots"]:
                    obj = annot.get_object()
                    if "/A" in obj and "/URI" in obj["/A"]:
                        extracted_links.append(str(obj["/A"]["/URI"]))

            # Иногда ссылки есть только в тексте
            extracted_links.extend(extract_urls_from_text(page_text))

        # dedup
        extracted_links = list(dict.fromkeys([u.strip() for u in extracted_links if u.strip()]))

    except Exception as e:
        # Ошибка парсинга — это не auto-malware, но VERIFY
        report["status"] = "VERIFY"
        report["reasons"].append(f"PDF parsing error (pypdf): {e}")

    # ---------- 3. Технический анализ структуры (pdfminer + raw markers) ----------
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

    # malformed -> минимум VERIFY (если еще CLEAN)
    if struct_flags["malformed_pdf"] and report["status"] == "CLEAN":
        report["status"] = "VERIFY"
        report["reasons"].append("Malformed PDF structure")

    # Hard malware triggers (правило 3.1)
    hard_reasons = hard_malware_triggers(struct_flags)
    if hard_reasons:
        report["status"] = "MALWARE"
        report["reasons"].extend(hard_reasons)

    # EmbeddedFile без hard triggers => VERIFY
    if (
        report["status"] != "MALWARE"
        and struct_flags["embedded_file"]
    ):
        if report["status"] == "CLEAN":
            report["status"] = "VERIFY"
        report["reasons"].append("EmbeddedFile detected without active action (manual verification required)")

    # ---------- 4. Анализ ссылок + CTA ----------
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

    # ---------- 5. Превью ----------
    report["tech_details"]["preview_urls"] = generate_previews(contents)

    # ---------- 6. ИИ только для VERIFY ----------
    if report["status"] == "VERIFY":
        ai_result = ai_verify_analysis(
            extracted_text=extracted_text,
            links=extracted_links,
            tech_info=report["tech_details"]["flags"]
        )
        ai_status = ai_result.get("final_status", "VERIFY")
        ai_reason = ai_result.get("reason", "No reason")

        # Финальный override от ИИ разрешен только в зоне VERIFY
        if ai_status in {"CLEAN", "VERIFY", "MALWARE"}:
            report["status"] = ai_status
        report["reasons"].append(f"AI verdict: {ai_reason}")

    # ---------- 7. Если ничего не найдено ----------
    if report["status"] == "CLEAN" and not report["reasons"]:
        report["reasons"].append(
            "No active content, no suspicious links, no phishing-like CTA detected."
        )

    # Ограничим причины до 7 (как просила)
    report["reasons"] = list(dict.fromkeys(report["reasons"]))[:7]

    # timestamp анализа
    report["analyzed_at_utc"] = datetime.now(timezone.utc).isoformat()

    return report
