import os
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import google.generativeai as genai
from .analyzer import analyzer
from .scanner_runner import scanner_runner
from .policy_parser import get_all_policy_text
import sys
from dotenv import load_dotenv

# Ensure .env is loaded
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(ROOT))
from ingest_hipaa import hybrid_search

router = APIRouter()

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    reply: str

# Configure Gemini
api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.5-flash-lite')
else:
    model = None

@router.post("/chat")
async def chat(request: ChatRequest):
    if not model:
        return ChatResponse(reply="⚠️ GEMINI_API_KEY is not set.")

    query = request.message
    triggered_scanners = []
    
    # 1. Trigger scanners
    q_lower = query.lower()
    if any(k in q_lower for k in ["scan", "audit", "check", "monitor"]):
        if any(k in q_lower for k in ["network", "nmap"]):
            scanner_runner.run_scan("nmap", "nmap -sV localhost -p 9901")
            triggered_scanners.append("Network")
        if any(k in q_lower for k in ["web", "nikto"]):
            scanner_runner.run_scan("nikto", "nikto -h http://localhost:9901 -nocheck")
            triggered_scanners.append("Web Server")
        if any(k in q_lower for k in ["credential", "trufflehog"]):
            scanner_runner.run_scan("trufflehog", "trufflehog filesystem . --only-verified --no-update")
            triggered_scanners.append("Credentials")

    try:
        # 2. RAG: HIPAA + Internal Policy Search
        hits = hybrid_search(query, collection="hipaa_controls", final_limit=3)
        policy_context = ""
        for h in hits:
            p = h.payload
            policy_context += f"Citation: {p.get('citation')}\nTitle: {p.get('section_title')}\nRequirement: {p.get('text_raw')}\n\n"

        internal_policies = get_all_policy_text()

        # 3. Get current findings
        all_logs = []
        for s_id in ["nmap", "nikto", "trufflehog", "code_sast", "openmrs_security", "openmrs_app", "mysql_logs"]:
            all_logs.extend(scanner_runner.get_status(s_id)["logs"])
        
        findings = analyzer.analyze_logs(all_logs)
        findings_context = "\n".join([f"- {f['citation']}: {f['title']} ({f['keyword']})" for f in findings])

        # 4. Gemini Prompt
        prompt = f"""
You are a HIPAA Compliance Assistant. Analyze the user's query against HIPAA policies AND internal hospital security policies.

USER QUERY: {query}

HIPAA POLICIES:
{policy_context}

INTERNAL HOSPITAL POLICIES:
{internal_policies if internal_policies else "None provided."}

CURRENT SCAN FINDINGS:
{findings_context if findings_context else "None."}

INSTRUCTIONS: 
- Compare findings against both HIPAA and Internal policies.
- Explain if a policy is violated.
- Keep response professional and concise.
"""
        response = model.generate_content(prompt)
        return ChatResponse(reply=response.text)
    except Exception as e:
        return ChatResponse(reply=f"Analysis error: {str(e)}")
