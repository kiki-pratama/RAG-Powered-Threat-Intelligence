# 1. SIEM menangkap log aneh (misal dari Elastic)
raw_elastic_log = "timestamp=2026-10-12T02:00:00Z user=admin bytes_out=500GB protocol=ssh destination=unknown_ip"

# 2. Cari Threat Intel (context) yang relevan dengan log tersebut di ChromaDB
retrieved_context = retrieve_context(query=raw_elastic_log)

# 3. Suntikkan ke prompt
prompt_chain = get_incident_triage_prompt()
final_prompt = prompt_chain.invoke({
    "context": retrieved_context,
    "raw_log": raw_elastic_log
})

# 4. Kirim final_prompt ke LLM (OpenAI / Llama 3) untuk mendapatkan JSON
# llm.invoke(final_prompt)
