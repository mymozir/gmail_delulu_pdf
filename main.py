from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
import io
import os
import re
import json
import hashlib
from typing import List, Dict, Any

from pypdf import PdfReader
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from google import genai

# --- КОНФИГУРАЦИЯ ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

CTA_WORDS = [
    "срочно", "подтвердить", "вход", "login", "оплатить", "pay",
    "пароль", "password", "аккаунт", "account", "verify"
]

app = FastAPI()


# ---------- УТИЛИТЫ ----------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_real_pdf(data: bytes) -> bool:
    # Ранняя проверка: это вообще PDF?
    return b"%PDF-" in data[:1024]


def unique(items: List[str]) -> List[str]:
    out = []
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


# ---------- ТЕХ. УГРОЗЫ ----------
def check_technical_threats(pdf_bytes: bytes, doc: PDFDocument) -> List[Dict[str, str]]:
    """
    Ищет жесткие сигналы MALWARE и возвращает:
    [{"type": "...", "quote": "..."}]
    """
    threats: List[Dict[str, str]] = []
    catalog = doc.catalog or {}

    # Ключи могут быть с / и без /
    keys = set(str(k) for k in catalog.keys())

    # Проверка OpenAction / AA в catalog
    if "/OpenAction" in keys or "OpenAction" in keys:
        val = catalog.get("/OpenAction") if "/OpenAction" in catalog else catalog.get("OpenAction")
        threats.append({
            "type": "OpenAction (Auto-Run)",
            "quote": safe_snippet(val)
        })

    if "/AA" in key
