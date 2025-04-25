from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import os
import uuid
import shutil
import json
from backend.security import verify_user, get_current_user, require_admin
from backend.anonymizer import anonymize_file
from backend.utils import generate_file_hash, cleanup_temp_files

app = FastAPI()

# Setup
app.add_middleware(SessionMiddleware, secret_key="super-secret-session-key")
app.mount("/static", StaticFiles(directory="frontend"), name="static")
templates = Jinja2Templates(directory="frontend")

UPLOAD_DIR = "temp"
RESULT_DIR = "results"
LOG_DIR = "backend/logs"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = verify_user(username, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    request.session["user"] = user
    return RedirectResponse("/", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)

@app.post("/api/process")
def process_file(request: Request, file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in [".csv", ".xlsx"]:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    file_id = str(uuid.uuid4())
    input_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    preview_data, headers, pii_detected = anonymize_file(input_path, preview_only=True)
    return {
        "temp_id": file_id,
        "detected_pii": pii_detected,
        "headers": headers,
        "preview_data": preview_data
    }

@app.post("/api/anonymize/{file_id}")
def anonymize_endpoint(file_id: str, payload: dict, user: dict = Depends(get_current_user)):
    input_path = None
    for ext in [".csv", ".xlsx"]:
        potential_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
        if os.path.exists(potential_path):
            input_path = potential_path
            break

    if not input_path:
        raise HTTPException(status_code=404, detail="Original file not found")

    output_path = os.path.join(RESULT_DIR, f"anonymized_{file_id}{os.path.splitext(input_path)[1]}")

    anonymize_file(input_path, output_path, payload)

    return FileResponse(output_path, filename=f"anonymized_{file_id}.csv", media_type="application/octet-stream")

@app.get("/download/{file_id}")
def download_file(file_id: str):
    for ext in [".csv", ".xlsx"]:
        path = os.path.join(RESULT_DIR, f"anonymized_{file_id}{ext}")
        if os.path.exists(path):
            return FileResponse(path, filename=f"anonymized{ext}")
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/logs")
def get_logs(user: dict = Depends(require_admin)):
    log_path = os.path.join(LOG_DIR, "actions.log")
    if not os.path.exists(log_path):
        return {"logs": []}
    with open(log_path, "r") as log_file:
        lines = log_file.readlines()
    return {"logs": lines[-100:]}

@app.on_event("shutdown")
def shutdown_event():
    cleanup_temp_files(UPLOAD_DIR, max_age_seconds=600)