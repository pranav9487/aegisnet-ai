"""Bootstrap static security reference documents into ChromaDB static_security_docs collection."""
from __future__ import annotations

import glob
import logging
import os
import re
import sys
from typing import List, Optional, Tuple

# Ensure project root is in sys.path for direct execution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import chromadb
from chromadb.utils import embedding_functions

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("bootstrap_static_docs")

COLLECTION_NAME = "static_security_docs"
MODEL_NAME = "all-MiniLM-L6-v2"


def chunk_markdown(content: str, max_chunk_chars: int = 1500) -> List[Tuple[str, str]]:
    """Chunk markdown document by top-level or second-level headings.

    Returns list of (section_title, section_text).
    """
    lines = content.strip().split("\n")
    title = "Reference Document"
    for line in lines:
        if line.startswith("# "):
            title = line.replace("# ", "").strip()
            break

    sections = re.split(r"\n(?=## )", content)
    chunks: List[Tuple[str, str]] = []

    for section in sections:
        section_str = section.strip()
        if not section_str:
            continue
        first_line = section_str.split("\n", 1)[0]
        sec_title = first_line.replace("## ", "").replace("# ", "").strip()
        chunks.append((f"{title} - {sec_title}", section_str))

    # If document has no ## headings or splitting yielded 0 chunks
    if not chunks:
        chunks.append((title, content.strip()))

    return chunks


def bootstrap_static_docs(
    raw_docs_dir: str = "data/raw_docs",
    persist_dir: Optional[str] = None,
) -> int:
    """Load and embed static reference documents into ChromaDB."""
    persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./data/chromadb")
    os.makedirs(persist_dir, exist_ok=True)

    doc_files = sorted(glob.glob(os.path.join(raw_docs_dir, "*.*")))
    if not doc_files:
        logger.error("No doc files found in %s", raw_docs_dir)
        return 0

    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=MODEL_NAME
    )
    client = chromadb.PersistentClient(path=persist_dir)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
    )

    ids = []
    documents = []
    metadatas = []

    for filepath in doc_files:
        filename = os.path.basename(filepath)
        doc_id_base = os.path.splitext(filename)[0]
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        chunks = chunk_markdown(content)
        for idx, (section_title, chunk_text) in enumerate(chunks):
            chunk_id = f"{doc_id_base}_{idx}"
            ids.append(chunk_id)
            documents.append(chunk_text)
            metadatas.append({
                "source": filename,
                "title": section_title,
                "chunk_index": idx,
            })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    total_docs = collection.count()
    logger.info("Successfully ingested %d chunks from %d files into %s (collection count: %d)",
                len(ids), len(doc_files), COLLECTION_NAME, total_docs)
    return total_docs


if __name__ == "__main__":
    count = bootstrap_static_docs()
    if count < 8:
        logger.error("Expected at least 8 documents, got %d", count)
        sys.exit(1)
    print(f"static_security_docs count: {count}")
    sys.exit(0)
