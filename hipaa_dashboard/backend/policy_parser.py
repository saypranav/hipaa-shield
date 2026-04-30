import os
from pypdf import PdfReader

def extract_text_from_pdf(pdf_path):
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return text

def get_all_policy_text():
    policy_dir = os.path.join(os.path.dirname(__file__), 'uploads', 'policies')
    combined_text = ""
    for filename in os.listdir(policy_dir):
        if filename.endswith(".pdf"):
            combined_text += f"--- POLICY: {filename} ---\n"
            combined_text += extract_text_from_pdf(os.path.join(policy_dir, filename)) + "\n\n"
    return combined_text
