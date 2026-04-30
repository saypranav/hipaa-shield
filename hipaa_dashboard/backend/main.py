import os
from dotenv import load_dotenv
# Load API Key from .env before anything else
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .scanner_runner import scanner_runner
from .analyzer import analyzer
from .chatbot import router as chatbot_router

app = FastAPI(title="HIPAA Scanner Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chatbot_router)

@app.post("/upload-policy")
async def upload_policy(file: UploadFile = File(...)):
    if not file.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files allowed")
    
    upload_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'policies')
    os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, file.filename)
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())
    return {"message": f"Policy {file.filename} uploaded successfully"}

import shlex
from urllib.parse import urlparse

class ScanRequest(BaseModel):
    target_url: str = "http://localhost:9901"

@app.post("/scan/{scanner_id}")
async def start_scan(scanner_id: str, request: ScanRequest):
    allowed_scanners = ["nmap", "nikto", "trufflehog", "code_sast", "openmrs_security", "openmrs_app", "mysql_logs"]
    if scanner_id not in allowed_scanners:
        raise HTTPException(status_code=404, detail="Scanner not found")
    
    # Basic validation/sanitization for URL based scanners
    parsed = urlparse(request.target_url)
    hostname = parsed.hostname or parsed.path.split(':')[0] or "localhost"
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    
    if scanner_id == "nmap":
        command = f"nmap -sV {shlex.quote(hostname)} -p {port}"
    elif scanner_id == "nikto":
        command = f"nikto -h {shlex.quote(request.target_url)} -nocheck"
    elif scanner_id == "trufflehog":
        command = "trufflehog filesystem . --only-verified --no-update"
    elif scanner_id == "code_sast":
        command = "semgrep scan --config auto --json openmrs-hospital/synthea/src"
    elif scanner_id == "openmrs_security":
        command = "docker logs --tail 500 banda_openmrs_master"
    elif scanner_id == "openmrs_app":
        command = "docker exec banda_openmrs_master tail -n 500 /root/.OpenMRS/openmrs.log"
    elif scanner_id == "mysql_logs":
        command = "docker logs --tail 500 banda_mysql_master"

    success = scanner_runner.run_scan(scanner_id, command)
    if not success:
        raise HTTPException(status_code=400, detail="Scan already running")
    
    return {"message": f"Started {scanner_id} audit"}

@app.get("/scan/{scanner_id}/status")
async def get_scan_status(scanner_id: str):
    return scanner_runner.get_status(scanner_id)

@app.get("/report")
async def get_compliance_report():
    all_findings = []
    scanners_to_check = ["nmap", "nikto", "trufflehog", "code_sast", "openmrs_security", "openmrs_app", "mysql_logs"]
    for scanner_id in scanners_to_check:
        status = scanner_runner.get_status(scanner_id)
        findings = analyzer.analyze_logs(status["logs"])
        for f in findings:
            f["scanner"] = scanner_id
            all_findings.append(f)
    
    return {
        "is_compliant": len(all_findings) == 0,
        "findings": all_findings
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
