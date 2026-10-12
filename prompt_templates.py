"""
prompt_templates.py
Kumpulan template prompt untuk RAG-Powered Threat Intelligence Assistant.
"""

from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

# 1. System Prompt: Menentukan persona dan aturan ketat untuk LLM
# Kita menggunakan background SOC Level 2 agar LLM memberikan analisis teknis mendalam.
SOC_SYSTEM_PROMPT = """You are an Expert SOC Level 2 Analyst and SIEM Engineer specializing in Elastic Security.
Your primary task is to analyze raw SIEM logs, correlate them with provided Threat Intelligence context, and generate actionable triage reports.

STRICT RULES:
1. Base your analysis ONLY on the provided Raw Log and Threat Intelligence Context.
2. If the context does not contain relevant information, state "Insufficient Threat Intel context" rather than hallucinating facts.
3. Classify the severity strictly as: CRITICAL, HIGH, MEDIUM, or LOW.
4. You MUST respond ONLY in valid JSON format matching the exact structure requested, with no markdown formatting blocks outside the JSON.
"""

# 2. Human Prompt: Menempatkan variabel dinamis dari RAG (context) dan Elasticsearch (raw_log)
TRIAGE_HUMAN_PROMPT = """
--- THREAT INTELLIGENCE CONTEXT ---
{context}

--- RAW SIEM LOG (Elastic) ---
{raw_log}

--- TASK ---
Analyze the log above. Identify if it matches any known attack vectors from the context (e.g., unusual bandwidth spikes, API token abuse). 

Provide your response in the following JSON schema:
{{
    "incident_summary": "A clear, 2-sentence summary of what occurred.",
    "severity_level": "CRITICAL | HIGH | MEDIUM | LOW",
    "mitre_attck_tactics": ["List of applicable MITRE tactics, e.g., Initial Access, Exfiltration"],
    "indicators_of_compromise": ["List of IPs, Hashes, or anomalous metrics like 'Bandwidth > 50GB'"],
    "recommended_actions": [
        "Step 1 for mitigation",
        "Step 2 for mitigation"
    ],
    "is_false_positive_likely": true/false
}}
"""

# 3. Menggabungkan System dan Human menjadi satu ChatPromptTemplate
def get_incident_triage_prompt() -> ChatPromptTemplate:
    """
    Mengembalikan template prompt utama untuk analisis log harian.
    """
    system_message = SystemMessagePromptTemplate.from_template(SOC_SYSTEM_PROMPT)
    human_message = HumanMessagePromptTemplate.from_template(TRIAGE_HUMAN_PROMPT)
    
    return ChatPromptTemplate.from_messages([system_message, human_message])

# (Opsional) Template khusus untuk use-case API Expiration 
API_EXPIRATION_HUMAN_PROMPT = """
--- THREAT INTELLIGENCE CONTEXT ---
{context}

--- API EXPIRATION LOG ---
{raw_log}

--- TASK ---
This log indicates an API key is approaching expiration or has expired. 
Determine the security risk: Is this a routine expiration, or is there evidence of post-expiration usage attempts (Potential credential harvesting/abuse)?

Provide response in JSON:
{{
    "status": "ROUTINE | ABUSE_ATTEMPT",
    "risk_score": 1-100,
    "affected_service": "Service name",
    "action_required": "Revoke key | Notify owner | Block IP"
}}
"""

def get_api_security_prompt() -> ChatPromptTemplate:
    system_message = SystemMessagePromptTemplate.from_template(SOC_SYSTEM_PROMPT)
    human_message = HumanMessagePromptTemplate.from_template(API_EXPIRATION_HUMAN_PROMPT)
    return ChatPromptTemplate.from_messages([system_message, human_message])
