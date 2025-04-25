from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import os
import uuid
import shutil
import json
import logging # Import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv # Import dotenv

from backend.security import verify_user, get_current_user, require_admin
from backend.anonymizer import anonymize_file
from backend.utils import generate_file_hash, cleanup_temp_files

# --- Load Environment Variables ---
# Load .env file if it exists (mainly for local development)
load_dotenv()

# --- Configuration & Setup ---
SESSION_SECRET = os.environ.get("SESSION_SECRET_KEY")
if not SESSION_SECRET:
    # Fallback to a default (less secure) key with a warning if not set
    SESSION_SECRET = "change-this-super-secret-default-key-in-production"
    print("WARNING: SESSION_SECRET_KEY environment variable not set. Using default key. THIS IS INSECURE FOR PRODUCTION.") # Use logging here too

UPLOAD_DIR = "temp"
RESULT_DIR = "results"
LOG_DIR = "backend/logs"
LOG_FILE = os.path.join(LOG_DIR, "actions.log")
MAX_LOG_SIZE = 5 * 1024 * 1024 # 5 MB
LOG_BACKUP_COUNT = 3

# Create directories if they don't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# --- Logging Setup ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
log_handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT, encoding='utf-8')
log_handler.setFormatter(log_formatter)

# Get the root logger and add the handler
# Use a specific name for your app's logger
log = logging.getLogger("obscura")
log.setLevel(logging.INFO) # Set default level
log.addHandler(log_handler)
log.propagate = False # Prevent duplication if root logger also has handlers

# Optional: Add console handler for development
# console_handler = logging.StreamHandler()
# console_handler.setFormatter(log_formatter)
# log.addHandler(console_handler)

log.info("--- Obscura Application Starting ---")

# --- FastAPI App Initialization ---
app = FastAPI(title="Obscura Anonymization Tool")

# --- Middleware ---
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# --- Static Files and Templates ---
app.mount("/static", StaticFiles(directory="frontend"), name="static")
templates = Jinja2Templates(directory="frontend")

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Serves the main dashboard page."""
    user = request.session.get("user")
    if not user: # Redirect to login if not authenticated
        return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)
    log.debug(f"Serving dashboard to user: {user.get('username')}")
    return templates.TemplateResponse("index.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Serves the login page."""
    user = request.session.get("user")
    if user: # If already logged in, redirect to dashboard
         return RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handles user login authentication."""
    user = verify_user(username, password) # Logging is done inside verify_user
    if not user:
        # Log failed attempt already done in verify_user
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    request.session["user"] = user
    log.info(f"User '{username}' logged in successfully.")
    return RedirectResponse("/", status_code=status.HTTP_302_FOUND)

@app.get("/logout")
def logout(request: Request):
    """Clears the user session (logs out)."""
    username = request.session.get("user", {}).get("username")
    request.session.clear()
    if username:
        log.info(f"User '{username}' logged out.")
    else:
        log.info("Logout requested for user with no active session.")
    return RedirectResponse("/", status_code=status.HTTP_302_FOUND)

@app.post("/api/process")
async def process_file(request: Request, file: UploadFile = File(...), user: Dict[str, str] = Depends(get_current_user)):
    """Handles file upload, basic validation, PII detection preview."""
    username = user.get("username", "unknown")
    log.info(f"User '{username}' initiating file processing for: {file.filename}")

    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in [".csv", ".xlsx"]:
        log.warning(f"User '{username}' uploaded unsupported file type: {file.filename} ({file_ext})")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported file type: {file_ext}. Please upload CSV or XLSX.")

    file_id = str(uuid.uuid4())
    input_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")

    try:
        # Save uploaded file temporarily
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        log.info(f"File '{file.filename}' uploaded by '{username}', saved as temp ID: {file_id}")

        # Get preview and detected PII
        preview_data, headers, pii_detected = anonymize_file(input_path, preview_only=True)
        log.info(f"Generated preview for temp ID: {file_id}. Detected PII fields: {list(pii_detected.keys())}")

        return {
            "temp_id": file_id,
            "detected_pii": pii_detected,
            "headers": headers,
            "preview_data": preview_data,
            "original_filename": file.filename # Send original name back for clarity
        }

    except ValueError as e:
        log.error(f"Value error during processing for {file_id} by '{username}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        log.exception(f"Unexpected error during file processing for {file_id} by '{username}': {e}") # Use log.exception to include traceback
        # Clean up potentially corrupted temp file
        if os.path.exists(input_path):
            try:
                os.remove(input_path)
            except OSError as rm_err:
                log.error(f"Could not remove temp file {input_path} after error: {rm_err}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal error occurred during file processing.")
    finally:
         # Ensure file handle is closed (though `with open` should handle it)
         if hasattr(file, 'file') and not file.file.closed:
            file.file.close()


@app.post("/api/anonymize/{file_id}")
async def anonymize_endpoint(file_id: str, payload: Dict[str, Any], user: Dict[str, str] = Depends(get_current_user)):
    """Applies selected anonymization techniques and returns the file for download."""
    username = user.get("username", "unknown")
    log.info(f"User '{username}' requesting anonymization for file ID: {file_id}")
    log.debug(f"Anonymization payload for {file_id}: {payload}")

    input_path = None
    original_ext = None
    # Find the temporary input file
    for ext in [".csv", ".xlsx"]:
        potential_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
        if os.path.exists(potential_path):
            input_path = potential_path
            original_ext = ext
            break

    if not input_path or not original_ext:
        log.error(f"Anonymization request failed for '{username}': Original file not found for ID: {file_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Original temporary file not found. It might have expired or been deleted.")

    output_filename = f"anonymized_{file_id}{original_ext}"
    output_path = os.path.join(RESULT_DIR, output_filename)

    try:
        # Perform anonymization (which saves the file)
        anonymize_file(input_path=input_path, output_path=output_path, payload=payload, preview_only=False)

        selected_cols = payload.get("selected_pii", [])
        techniques = payload.get("techniques", {})
        log.info(f"Anonymization successful for file ID: {file_id} by '{username}'. Output: {output_path}. Columns anonymized: {selected_cols}. Techniques: {techniques}")

        # Return the anonymized file as a download response
        return FileResponse(
            path=output_path,
            filename=output_filename, # Suggests a filename to the browser
            media_type="application/octet-stream" # Generic binary stream type
        )

    except ValueError as e:
        log.error(f"Value error during anonymization for {file_id} by '{username}': {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except FileNotFoundError as e:
         log.error(f"File not found error during anonymization for {file_id} by '{username}': {e}")
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Could not find necessary file during anonymization.")
    except Exception as e:
        log.exception(f"Unexpected error during anonymization for {file_id} by '{username}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal error occurred during anonymization.")


# Note: This endpoint might be redundant if anonymize_endpoint always triggers download.
# Keep it if you want a way to re-download results (requires persistent storage logic).
# SECURED: Added authentication dependency
@app.get("/download/{file_id}")
async def download_file(file_id: str, user: Dict[str, str] = Depends(get_current_user)):
    """Allows re-downloading of an already anonymized file."""
    username = user.get("username", "unknown")
    log.info(f"User '{username}' requesting download for result ID: {file_id}")

    found_path = None
    download_filename = None
    # Check for possible output file extensions
    for ext in [".csv", ".xlsx"]:
        path = os.path.join(RESULT_DIR, f"anonymized_{file_id}{ext}")
        if os.path.exists(path):
            found_path = path
            download_filename = f"anonymized_{file_id}{ext}" # Use the actual found filename
            break

    if not found_path or not download_filename:
        log.warning(f"Download failed for user '{username}': Result file not found for ID: {file_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anonymized file not found.")

    log.info(f"Providing download of '{download_filename}' to user '{username}'.")
    return FileResponse(
        path=found_path,
        filename=download_filename,
        media_type="application/octet-stream"
        )

@app.get("/logs", response_class=HTMLResponse) # Changed to HTMLResponse for better presentation
async def get_logs_page(request: Request, user: Dict[str, str] = Depends(require_admin)):
    """Displays the last N lines of the log file (Admin only)."""
    username = user.get("username", "admin")
    log.info(f"Admin user '{username}' accessed logs.")
    lines: List[str] = []
    error_message: Optional[str] = None
    log_file_exists = False

    try:
        if os.path.exists(LOG_FILE):
            log_file_exists = True
            with open(LOG_FILE, "r", encoding='utf-8') as log_file:
                # Read all lines, take the last 100 (or fewer if less than 100 lines)
                all_lines = log_file.readlines()
                lines = all_lines[-100:]
        else:
            log.warning(f"Admin '{username}' tried to access logs, but log file '{LOG_FILE}' does not exist.")
            error_message = f"Log file ({LOG_FILE}) not found."

    except Exception as e:
        log.exception(f"Error reading log file '{LOG_FILE}' for admin '{username}': {e}")
        error_message = f"Error reading log file: {e}"

    # Simple HTML template response (could be a separate Jinja template)
    html_content = f"""
    <html>
        <head><title>Application Logs</title></head>
        <body>
            <h1>Application Logs (Last {len(lines)} Lines)</h1>
            {'<p style="color:red;">' + error_message + '</p>' if error_message else ''}
            {f'<p>Log file: {LOG_FILE}</p>' if log_file_exists else ''}
            <hr>
            <pre><code>{''.join(lines) if lines else 'No log entries found.'}</code></pre>
            <hr>
            <a href="/">Back to Dashboard</a>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# --- Event Handlers ---
@app.on_event("startup")
async def startup_event():
    log.info("Application startup complete.")
    # Initial cleanup check (optional)
    # removed_count = len(cleanup_temp_files(UPLOAD_DIR, max_age_seconds=600))
    # if removed_count > 0:
    #    log.info(f"Cleaned up {removed_count} old files from '{UPLOAD_DIR}' on startup.")

@app.on_event("shutdown")
def shutdown_event():
    """Cleans up old temporary files on shutdown."""
    log.info("--- Obscura Application Shutting Down ---")
    try:
        removed_files = cleanup_temp_files(UPLOAD_DIR, max_age_seconds=1) # Clean almost all on shutdown
        log.info(f"Cleaned up {len(removed_files)} files from '{UPLOAD_DIR}' on shutdown.")
    except Exception as e:
        log.exception(f"Error during shutdown cleanup: {e}")
