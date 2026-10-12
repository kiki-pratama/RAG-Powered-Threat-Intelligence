"""
app.py
Backend API untuk RAG-Powered Threat Intelligence Assistant menggunakan FastAPI.
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Langchain imports
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser

# Import modul yang sudah kita buat sebelumnya
from rag.vector_store import retrieve_context
from llm.prompt_templates import get_incident_triage_prompt

# Setup environment variable untuk OpenAI API Key
# (Untuk showcase lokal tanpa biaya, Anda bisa mengganti ChatOpenAI dengan ChatOllama)
os.environ["OPENAI_API_KEY"] = "sk-proj-YOUR_API_KEY_HERE"

# 1. Inisialisasi FastAPI
app = FastAPI(
    title="SOC Threat Intel API",
    description="API untuk menganalisis log SIEM menggunakan RAG dan LLM.",
    version="1.0.0"
)

# 2. Definisikan Skema Request menggunakan Pydantic
class LogRequest(BaseModel):
    raw_log: str

# 3. Setup LLM Pipeline
def setup_rag_pipeline():
    """
    Membuat chain Langchain: Prompt -> LLM -> JSON Parser.
    Temperature diset 0.0 agar LLM tidak kreatif dan sangat deterministik (wajib untuk security).
    """
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0)
    
    # JsonOutputParser otomatis membuang format markdown (```json ... ```) dari output LLM
    # sehingga langsung menjadi dictionary/JSON yang valid.
    parser = JsonOutputParser()
    
    prompt = get_incident_triage_prompt()
    
    # Rangkai pipeline (LCEL - LangChain Expression Language)
    rag_chain = prompt | llm | parser
    return rag_chain

# Inisialisasi chain saat server berjalan
chain = setup_rag_pipeline()

# 4. Endpoint Utama API
@app.post("/api/analyze-log")
async def analyze_siem_log(request: LogRequest):
    try:
        print(f"[*] Menerima log untuk dianalisis: {request.raw_log}")
        
        # Langkah A: Retrieve context dari ChromaDB (FAISS/Local)
        print("[*] Mencari Threat Intel context yang relevan...")
        context = retrieve_context(query=request.raw_log)
        
        # Langkah B: Eksekusi LLM Chain
        print("[*] Mengirim data ke LLM untuk dianalisis...")
        result_json = chain.invoke({
            "context": context,
            "raw_log": request.raw_log
        })
        
        # FastAPI otomatis mengonversi Python dictionary (result_json) menjadi HTTP JSON Response
        return result_json

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Block untuk menjalankan server (jika dieksekusi langsung)
if __name__ == "__main__":
    print("[*] Starting SOC AI Backend Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
