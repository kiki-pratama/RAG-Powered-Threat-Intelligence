"""
vector_store.py
Script untuk ingest dokumen Threat Intelligence ke ChromaDB dan melakukan retrieval.
"""

import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

# Konfigurasi Path
DOCS_DIR = "./data/threat_intel_docs"
CHROMA_PERSIST_DIR = "./chroma_db"

def get_embedding_model():
    """
    Menggunakan model open-source ringan yang dioptimalkan untuk CPU.
    """
    print("[*] Loading CPU-friendly embedding model...")
    return HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

def ingest_threat_intel():
    """
    Membaca dokumen dari folder, memecahnya (chunking), dan menyimpannya ke Vector DB.
    """
    if not os.path.exists(DOCS_DIR):
        print(f"[!] Folder {DOCS_DIR} tidak ditemukan. Buat folder dan isi dengan file .txt")
        return None

    # 1. Load Documents (Misal: Laporan MITRE, CVE, atau aturan SOC internal)
    print(f"[*] Loading documents from {DOCS_DIR}...")
    loader = DirectoryLoader(DOCS_DIR, glob="**/*.txt", loader_cls=TextLoader)
    documents = loader.load()
    
    if not documents:
        print("[!] Tidak ada dokumen yang ditemukan.")
        return None

    # 2. Text Chunking (Membagi dokumen panjang menjadi potongan kecil dengan overlap)
    # Overlap penting agar konteks kalimat yang terpotong tidak hilang
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000, 
        chunk_overlap=150
    )
    chunks = text_splitter.split_documents(documents)
    print(f"[*] Dokumen berhasil dipecah menjadi {len(chunks)} chunks.")

    # 3. Embed & Ingest to ChromaDB
    print("[*] Ingesting ke ChromaDB (Proses ini mungkin memakan waktu sebentar)...")
    embedding_model = get_embedding_model()
    
    vector_db = Chroma.from_documents(
        documents=chunks,
        embedding=embedding_model,
        persist_directory=CHROMA_PERSIST_DIR
    )
    
    print(f"[+] Berhasil! Vector Database tersimpan di {CHROMA_PERSIST_DIR}")
    return vector_db

def retrieve_context(query: str, k: int = 3) -> str:
    """
    Mencari konteks Threat Intel yang paling relevan berdasarkan log Elastic.
    """
    embedding_model = get_embedding_model()
    
    # Load database yang sudah ada di disk
    vector_db = Chroma(
        persist_directory=CHROMA_PERSIST_DIR, 
        embedding_function=embedding_model
    )
    
    # Ambil top-K chunk paling relevan
    retriever = vector_db.as_retriever(search_kwargs={"k": k})
    relevant_docs = retriever.invoke(query)
    
    # Gabungkan isi dokumen menjadi satu string teks untuk disuntikkan ke {context}
    context_text = "\n\n---\n\n".join([doc.page_content for doc in relevant_docs])
    return context_text

# Block ini digunakan jika script dijalankan langsung (standalone)
if __name__ == "__main__":
    ingest_threat_intel()
