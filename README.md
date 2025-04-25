# Obscura_ver3

## Description
A secure data anonymization tool with a modern frontend and FastAPI backend. Supports login, PII detection, and masking/hashing options.

## Requirements
- Python 3.8+
- pip install fastapi uvicorn pandas openpyxl bcrypt==4.0.1 "passlib[bcrypt]" itsdangerous jinja2 python-multipart dotenv

## How to Run
```bash
python3 -m venv venv
source venv/bin/activate
```
install dependencies 

```bash
uvicorn backend.main:app --reload
```

Then visit: http://localhost:8000

## Login Credentials
- admin / admin123
- user / user123

## Features
- File upload and preview
- PII auto-detection
- Masking or hashing
- Download anonymized file
- Logs (admin only)

## Project Structure
- `backend/` — FastAPI logic and anonymization code
- `frontend/` — HTML, CSS, JS interface
- `temp/` — temporary files (auto-deleted)
- `results/` — anonymized outputs
