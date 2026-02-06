# =========================
# 1) Импорты библиотек
# =========================
# FastAPI — веб-фреймворк для создания API-эндпоинта.
# UploadFile/File/Form — прием файла и полей формы multipart/form-data.
# JSONResponse — удобный возврат ошибок с HTTP-кодами.
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse

# io.BytesIO — чтобы читать загруженный PDF из памяти как файловый поток.
import io

# os — для чтения переменной окружения GEMINI_API_KEY (без хардкода ключа в коде).
import os

# re — для извлечения чистого email из формата "Имя <mail@domain.com>".
import re

# pypdf — извлечение текста, ссылок и базовой структуры страниц PDF.
from pypdf import PdfReader

# ВАЖНО: правильный импорт pdfminer (НЕ from pdfminer.six ...).
# Используется для низкоуровневой проверки OpenAction/JavaScript в catalog PDF.
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument

# Клиент Gemini для LLM-анализа рисков.
from google import genai


# =========================
# 2) Конфигурация приложения
# =========================
# Ключ Gemini берется из окружения Render:
# Dashboard -> Environment -> GEMINI_API_KEY
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Лимит размера файла на сервере (дублируем защиту, даже если клиент уже проверяет).
MAX_FILE_SIZE_MB = 20

# Инициализация FastAPI-приложения.
app = FastAPI(title="PDF Security Analyzer")


# =========================
# 3) Вспомогательные функции
# =========================
def extract_email(raw_sender: str) -> str:
    """
    Извлекает "чистый" email.
    Примеры:
    - "user@example.com" -> user@example.com
    - "John Doe <user@example.com>" -> user@example.com
    """
    if not raw_sender:
        return ""
    match = re.search(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', raw_sender)
    return match.group(1).lower() if match else raw_sender.strip().lower()


def detect_auth_fail(auth_results: str) -> bool:
    """
    Определяет провал SPF/DKIM/DMARC по строке auth_results.
    Срабатывает на fail/softfail.
    """
    ar = (auth_results or "").lower()
    return (
        ("spf=fail" in ar)
        or ("dkim=fail" in ar)
        or ("dmarc=fail" in ar)
        or ("softfail" in ar)
    )


def generate_security_verdict(
    sender_email: str,
    auth_results: str,
    extracted_text: str,
    links: list,
    tech_risks: list
) -> dict:
    """
    Вызывает Gemini и получает итоговый вердикт по письму.
    Возвращает:
    {
      "summary": "...",
      "is_malware": bool
    }
    """
    # Если ключа нет, возвращаем безопасный fallback.
    if not GEMINI_API_KEY:
        return {
            "summary": "ОПАСНО: отсутствует GEMINI_API_KEY, AI-анализ недоступен.",
            "is_malware": True
        }

    try:
        # Создаем клиента Gemini.
        client = genai.Client(api_key=GEMINI_API_KEY)

        # Нормализуем email отправителя.
        clean_sender = extract_email(sender_email)

        # Готовим строки для промпта.
        links_str = "\n".join([f"- {l.get('url', '')}" for l in links]) if links else "- Нет ссылок"
        risks_str = "\n".join([f"- {r.get('type', '')}: {r.get('details', '')}" for r in tech_risks]) if tech_risks else "- Нет технических рисков"

        # Берем только начало текста, чтобы не раздувать токены.
        text_preview = (extracted_text or "")[:1500]

        # Промпт с приоритетами анализа.
        prompt = f"""
Ты — офицер кибербезопасности (SOC/Forensics).

ДАННЫЕ:
1) Отправитель: {clean_sender}
2) Auth results: {auth_results}
3) Ссылки:
{links_str}
4) Активный контент в PDF:
{risks_str}
5) Фрагмент текста:
{text_preview}

ПРАВИЛА:
- Приоритет 1: если auth_results содержит fail/softfail для SPF/DKIM/DMARC — высокий риск подмены.
- Приоритет 2: если "официальная" тематика (банк/госуслуги/налоги/доставка), а отправитель выглядит несоответствующим — фишинг.
- Приоритет 3: "срочно", "выплата", "компенсация", "подтвердите", "перейдите по ссылке" + внешние ссылки — скам.

ОТВЕТ СТРОГО:
Вердикт: MALWARE или CLEAN
Причина: до 60 слов
"""

        # Запрос к модели.
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        # Текст ответа модели.
        text_resp = (response.text or "").strip()

        # Простая логика определения MALWARE.
        upper = text_resp.upper()
        is_malware = "MALWARE" in upper

        # Чистим ответ для admin_summary.
        summary = text_resp.replace("Вердикт:", "").strip()

        # Защита от пустого ответа модели.
        if not summary:
            summary = "ОПАСНО: модель не вернула корректный ответ."

        return {"summary": summary, "is_malware": is_malware}

    except Exception as e:
        # Если AI упал, считаем риск повышенным (fail-safe).
        return {"summary": f"ОПАСНО: ошибка AI-анализа ({e})", "is_malware": True}


# =========================
# 4) API-эндпоинт анализа PDF
# =========================
@app.post("/analyze_pdf")
async def analyze_pdf(
    # Файл из multipart/form-data (поле file).
    file: UploadFile = File(...),

    # Email отправителя письма (поле sender_email).
    sender_email: str = Form(...),

    # Результаты SPF/DKIM/DMARC (поле auth_results), делаем необязательным для совместимости.
    auth_results: str = Form("")
):
    """
    Основной маршрут:
    1) Проверяет, что файл похож на PDF.
    2) Читает текст + ссылки.
    3) Низкоуровнево ищет OpenAction/JavaScript.
    4) Запускает AI-вердикт с учетом auth_results.
    5) Возвращает status + admin_summary + артефакты.
    """

    # -------------------------
    # 4.1) Базовая валидация файла
    # -------------------------
    filename = file.filename or "unknown.pdf"
    content_type = (file.content_type or "").lower()

    # Принимаем PDF либо по mime-type, либо по расширению.
    is_probably_pdf = (content_type == "application/pdf") or filename.lower().endswith(".pdf")
    if not is_probably_pdf:
        return JSONResponse(
            status_code=400,
            content={"status": "ERROR", "message": "Поддерживаются только PDF-файлы"}
        )

    # -------------------------
    # 4.2) Чтение файла в память + лимит размера
    # -------------------------
    try:
        contents = await file.read()

        # Серверный лимит размера.
        if len(contents) > MAX_FILE_SIZE_MB * 1024 * 1024:
            return JSONResponse(
                status_code=413,
                content={"status": "ERROR", "message": f"Файл больше {MAX_FILE_SIZE_MB}MB"}
            )

        # Создаем in-memory поток для pypdf/pdfminer.
        pdf_file = io.BytesIO(contents)

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "ERROR", "message": f"Ошибка чтения файла: {e}"}
        )

    # -------------------------
    # 4.3) Стартовая структура отчета
    # -------------------------
    report = {
        "status": "CLEAN",               # CLEAN | HIGH_RISK | MALWARE | ERROR
        "filename": filename,
        "metadata": {},
        "risks": [],                     # Технические риски
        "links": [],                     # Найденные URL
        "admin_summary": ""              # Итог для администратора
    }

    extracted_text = ""

    # -------------------------
    # 4.4) Извлечение текста/ссылок через pypdf
    # -------------------------
    try:
        reader = PdfReader(pdf_file)
        report["metadata"]["pages"] = len(reader.pages)

        for page in reader.pages:
            # Текст страницы.
            text = page.extract_text()
            if text:
                extracted_text += text + " "

            # Поиск аннотаций/ссылок.
            if "/Annots" in page:
                for annot_ref in page["/Annots"]:
                    try:
                        obj = annot_ref.get_object()
                        if "/A" in obj and "/URI" in obj["/A"]:
                            uri = str(obj["/A"]["/URI"])
                            report["links"].append({"url": uri})
                    except Exception as e:
                        # Не валим весь анализ из-за битой аннотации.
                        report["risks"].append({
                            "type": "ANNOT_PARSE_WARNING",
                            "details": str(e)
                        })

    except Exception as e:
        # Если pypdf не смог читать — отмечаем риск и продолжаем.
        report["risks"].append({"type": "PDF_READ_WARNING", "details": str(e)})

    # -------------------------
    # 4.5) Низкоуровневая проверка OpenAction/JavaScript через pdfminer
    # -------------------------
    try:
        # Перематываем поток в начало.
        pdf_file.seek(0)

        parser = PDFParser(pdf_file)
        doc = PDFDocument(parser)
        catalog = getattr(doc, "catalog", {}) or {}

        # OpenAction — автодействие при открытии.
        if catalog.get("OpenAction"):
            report["risks"].append({
                "type": "OPEN_ACTION",
                "details": "Обнаружено автодействие OpenAction"
            })

        # JavaScript/JS в каталоге.
        if catalog.get("JavaScript") or catalog.get("JS"):
            report["risks"].append({
                "type": "JAVASCRIPT",
                "details": "Обнаружен встроенный JavaScript"
            })

    except Exception as e:
        # Если низкоуровневый разбор не удался — просто логируем в риски.
        report["risks"].append({"type": "LOW_LEVEL_PARSE_WARNING", "details": str(e)})

    # -------------------------
    # 4.6) Решение: запускать AI или нет
    # -------------------------
    # Запускаем AI, если:
    # - есть текст,
    # - или ссылки,
    # - или тех.риски,
    # - или auth_results содержит fail/softfail.
    auth_fail = detect_auth_fail(auth_results)
    need_ai = bool(report["links"] or report["risks"] or len(extracted_text.strip()) > 10 or auth_fail)

    if need_ai:
        ai_result = generate_security_verdict(
            sender_email=sender_email,
            auth_results=auth_results,
            extracted_text=extracted_text,
            links=report["links"],
            tech_risks=report["risks"]
        )

        report["admin_summary"] = ai_result["summary"]

        # Приоритет статусов:
        # 1) MALWARE от AI
        # 2) HIGH_RISK при auth_fail или активном контенте
        # 3) CLEAN в остальных случаях
        if ai_result["is_malware"]:
            report["status"] = "MALWARE"
        else:
            risk_types = {r.get("type") for r in report["risks"]}
            if auth_fail or ("OPEN_ACTION" in risk_types) or ("JAVASCRIPT" in risk_types):
                report["status"] = "HIGH_RISK"
            else:
                report["status"] = "CLEAN"

    else:
        # Если сигналов нет вообще.
        report["status"] = "CLEAN"
        report["admin_summary"] = "ЧИСТО: явных признаков угрозы не обнаружено."

    # -------------------------
    # 4.7) Финальный ответ API
    # -------------------------
    return report
