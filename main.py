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

    # Fallback по сырым байтам (ищем сигнатуры и даем цитату)
    raw_map = [
        (b"/JavaScript", "JavaScript marker"),
        (b"/JS", "JS marker"),
        (b"/OpenAction", "OpenAction marker"),
        (b"/AA", "AA marker"),
        (b"/Launch", "Launch action marker"),
        (b"/SubmitForm", "SubmitForm action marker"),
        (b"/ImportData", "ImportData action marker"),
    ]

    for marker, label in raw_map:
        idx = pdf_bytes.find(marker)
        if idx != -1:
            start = max(0, idx - 80)
            end = min(len(pdf_bytes), idx + 220)
            quote = pdf_bytes[start:end].decode("latin-1", errors="ignore")
            threats.append({
                "type": label,
                "quote": quote[:500]
            })

    # Убираем дубли
    uniq = []
    seen = set()
    for t in threats:
        k = (t["type"], t["quote"])
        if k not in seen:
            seen.add(k)
            uniq.append(t)

    return uniq
