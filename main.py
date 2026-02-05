from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
import io
from pypdf import PdfReader
from pdfminer.six import PDFParser, PDFDocument

# Используем библиотеку Google GenAI для доступа к Gemini
from google import genai 
from google.genai.errors import APIError as GenAI_APIError

# --- КОНФИГУРАЦИЯ ---
# Вставьте сюда ваш API Key.
GEMINI_API_KEY = "AIzaSyDXbkd_usLnfh5at5V_l38UNv1af74aZLE"

app = FastAPI()

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def generate_admin_summary(report_data: dict) -> str:
    """
    Генерирует краткий отчет для администратора с помощью Gemini AI.
    Вызывается только при наличии рисков.
    """
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        # Составляем промпт на основе найденных рисков
        risks_str = "\n".join([f"- {r['type']}: {r['details']}" for r in report_data["risks"]])
        
        prompt = (
            f"Составь краткий и понятный отчет о потенциальной угрозе по следующим техническим данным:\n"
            f"Статус проверки файла: {report_data['status']}\n"
            f"Найденные угрозы:\n{risks_str}\n\n"
            f"Начни с Вердикта (ОПАСНО/ПОДОЗРИТЕЛЬНО) и затем дай краткое обоснование для администратора. Не превышай 50 слов."
        )

        response = client.models.generate_content(
            model="gemini-2.5-flash", 
            contents=[
                {"role": "user", "parts": [{"text": prompt}]}
            ]
        )
        return response.text
        
    except GenAI_APIError as e:
        return f"Ошибка при создании AI-отчета (Gemini API): {e}. Проверьте ключ и квоты."
    except Exception as e:
        return f"Общая ошибка AI: {e}"

# --- ЭНДПОИНТЫ API ---

@app.get("/")
def read_root():
    """Проверка доступности сервера."""
    return {"message": "PDF Security Analyzer is running"}

@app.post("/analyze_pdf")
async def analyze_pdf(
    file: UploadFile = File(...)     # PDF-файл
):
    """Основной эндпоинт для анализа PDF."""
    
    # 1. Читаем файл в память
    try:
        contents = await file.read()
        pdf_file = io.BytesIO(contents)
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "message": f"Ошибка чтения файла: {e}"})

    # Инициализация отчета
    report = {
        "status": "CLEAN", 
        "filename": file.filename,
        "risks": [], 
        "metadata": {},
        "links": [],
        "admin_summary": ""
    }
    
    # --- 2. Анализ PDF (Высокоуровневый - pypdf) ---
    try:
        reader = PdfReader(pdf_file)
        
        info = reader.metadata
        report["metadata"] = {
            "author": info.author if info and info.author else "Unknown",
            "creator": info.creator if info and info.creator else "Unknown",
            "pages": len(reader.pages)
        }

        # Поиск ссылок (URI)
        for page_num, page in enumerate(reader.pages):
            if "/Annots" in page:
                for annot in page["/Annots"]:
                    obj = annot.get_object()
                    if "/A" in obj and "/URI" in obj["/A"]:
                        uri = str(obj["/A"]["/URI"])
                        report["links"].append({"page": page_num + 1, "url": uri})
                        
    except Exception as e:
        report["risks"].append({"type": "MALFORMED_PDF", "details": f"Ошибка парсинга pypdf. Файл может быть намеренно искажен. Ошибка: {e}"})
        report["status"] = "HIGH_RISK"
        
    # --- 3. Анализ PDF (Низкоуровневый - pdfminer.six) ---
    try:
        pdf_file.seek(0)
        parser = PDFParser(pdf_file)
        doc = PDFDocument(parser)
        
        # Поиск OpenAction (автозапуск)
        if doc.catalog.get("OpenAction"):
            report["risks"].append({"type": "OPEN_ACTION", "details": "Найден автоматический запуск действия при открытии (OpenAction)." })
            if report["status"] not in ["MALWARE", "HIGH_RISK"]: report["status"] = "HIGH_RISK"

        # Поиск JavaScript
        if doc.catalog.get("JavaScript") or doc.catalog.get("JS"):
             report["risks"].append({"type": "JAVASCRIPT", "details": "В документе найден исполняемый JavaScript." })
             report["status"] = "MALWARE"
             
    except Exception as e:
        report["risks"].append({"type": "STREAM_ERROR", "details": f"Ошибка анализа структуры PDF-потоков. Ошибка: {e}"})
        if report["status"] not in ["MALWARE", "HIGH_RISK"]: report["status"] = "HIGH_RISK"
            
    # --- 4. Окончательный вердикт и ОПТИМИЗАЦИЯ ИИ-отчета ---
    
    # Пересчитываем статус, если он был "CLEAN", но найдены риски
    if report["status"] == "CLEAN" and report["risks"]:
        report["status"] = "SUSPECT"
        
    # Вызываем ИИ-отчет только при наличии подозрительности или рисков
    if report["status"] != "CLEAN":
        report["admin_summary"] = generate_admin_summary(report)
    else:
        report["admin_summary"] = "Проверен: угроз не найдено. Файл чист."
    
    return report
