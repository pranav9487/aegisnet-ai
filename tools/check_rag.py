#!/usr/bin/env python3
"""Smoke-test the RAG: does retrieval return the right content for known attacks?"""
import os, sys
import chromadb
from chromadb.utils import embedding_functions

PATH = os.path.expanduser("~/aegisnet-ai/data/chromadb")
ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path=PATH)
exp = client.get_collection("sera_ids_experiences", embedding_function=ef)
docs = client.get_collection("static_security_docs", embedding_function=ef)

failures = []

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not ok:
        failures.append(name)

# 1. Experience retrieval: each attack alert should return rules of its own class first
probes = {
    "ARP_POISON_MITM": "ARP binding mismatch: 172.28.0.20 claimed by MAC 02:42:ac:1c:00:42, delta_arp=1",
    "TCP_SESSION_HIJACK": "TCP sequence drift delta_seq=48200, duplicate_acks=5, payload entropy 7.8",
}
for expected_class, text in probes.items():
    res = exp.query(query_texts=[text], n_results=5)
    classes = [m.get("attack_class") for m in res["metadatas"][0]]
    check(f"top-5 contains {expected_class}", expected_class in classes, str(classes))

# 2. Benign traffic should retrieve benign rules, not attack rules
benign = "Client reconnect: small sequence jump 300 bytes, 1 duplicate ACK, normal entropy 4.0"
res = exp.query(query_texts=[benign], n_results=5)
top_class = res["metadatas"][0][0].get("attack_class")
check("benign query top hit is BENIGN_SPIKE", top_class == "BENIGN_SPIKE", top_class)

# 3. Static docs: syntax lookups must return the matching manual
syntax_probes = {
    "ip_xfrm_syntax.md": "ip xfrm state add aead rfc4106(gcm(aes)) spi mode transport",
    "ebtables_syntax.md": "ebtables append INPUT source MAC drop",
    "rfc4303_esp.md": "ESP header sequence number authentication data ICV",
}
for expected_src, text in syntax_probes.items():
    res = docs.query(query_texts=[text], n_results=3)
    srcs = [m.get("source", "") for m in res["metadatas"][0]]
    check(f"static query returns {expected_src}", any(expected_src in s for s in srcs), str(srcs))

# 4. Correction note must never be in the store
all_src = {m.get("source", "") for m in docs.get(include=["metadatas"])["metadatas"]}
check("correction note NOT embedded", not any("correction" in s for s in all_src))

print("\nRESULT:", "PASS" if not failures else f"FAIL ({len(failures)})")
sys.exit(1 if failures else 0)