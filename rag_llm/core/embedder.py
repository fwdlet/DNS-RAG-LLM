import json
import os
import pickle

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from config import EMBEDDING_MODEL, FAISS_INDEX_FILE, FAISS_META_FILE, FAISS_DIR, FAISS_MANIFEST_FILE, ANOMALY_CHUNKS_FILE


class Embedder:
    def __init__(self, model_name=None):
        self.model_name = model_name or EMBEDDING_MODEL
        self.model = None

    def _load_model(self):
        if self.model is None:
            self.model = SentenceTransformer(self.model_name)
        return self.model

    def encode(self, texts, show_progress=False):
        model = self._load_model()
        if isinstance(texts, str):
            texts = [texts]
        embeddings = model.encode(texts, show_progress_bar=show_progress, normalize_embeddings=True)
        return np.array(embeddings, dtype=np.float32)

    def encode_query(self, query):
        return self.encode([query])[0]


class FAISSIndex:
    def __init__(self, embedder=None, source_type=None):
        self.embedder = embedder or Embedder()
        self.source_type = source_type
        self.index = None
        self.metadata = []

    def _get_paths(self):
        from config import SOURCE_INDEX_CONFIG, FAISS_INDEX_FILE, FAISS_META_FILE
        if self.source_type and self.source_type in SOURCE_INDEX_CONFIG:
            cfg = SOURCE_INDEX_CONFIG[self.source_type]
            return cfg["index_file"], cfg["meta_file"]
        return FAISS_INDEX_FILE, FAISS_META_FILE

    def build(self, chunks):
        if not chunks:
            return
        texts = [c["text"] for c in chunks]
        self.metadata = [c.get("metadata", {}) for c in chunks]
        embeddings = self.embedder.encode(texts, show_progress=True)
        dim = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dim)
        self.index.add(embeddings)

    def add_chunks(self, chunks):
        if not chunks:
            return
        texts = [c["text"] for c in chunks]
        new_meta = [c.get("metadata", {}) for c in chunks]
        embeddings = self.embedder.encode(texts, show_progress=True)
        if self.index is None:
            dim = embeddings.shape[1]
            self.index = faiss.IndexFlatIP(dim)
        self.index.add(embeddings)
        self.metadata.extend(new_meta)

    def search(self, query, top_k=5):
        if self.index is None:
            return [], []
        query_vec = self.embedder.encode_query(query).reshape(1, -1)
        scores, indices = self.index.search(query_vec, min(top_k, self.index.ntotal))
        results = []
        meta_results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.metadata):
                continue
            results.append(self.metadata[idx].get("source_text", ""))
            meta_results.append(self.metadata[idx])
        return results, meta_results

    def search_with_text(self, query, top_k=5):
        if self.index is None:
            return []
        query_vec = self.embedder.encode_query(query).reshape(1, -1)
        scores, indices = self.index.search(query_vec, min(top_k, self.index.ntotal))
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self.metadata):
                continue
            meta = self.metadata[idx]
            results.append({
                "score": float(score),
                "metadata": meta,
                "index": int(idx),
            })
        return results

    def save(self, index_file=None, meta_file=None):
        if self.index is None:
            return
        if index_file is not None and meta_file is not None:
            idx_file, mt_file = index_file, meta_file
        else:
            idx_file, mt_file = self._get_paths()
        os.makedirs(os.path.dirname(idx_file), exist_ok=True)
        faiss.write_index(self.index, idx_file)
        with open(mt_file, "wb") as f:
            pickle.dump(self.metadata, f)

    def load(self, index_file=None, meta_file=None):
        if index_file is not None and meta_file is not None:
            idx_file, mt_file = index_file, meta_file
        else:
            idx_file, mt_file = self._get_paths()
        if not os.path.exists(idx_file) or not os.path.exists(mt_file):
            return False
        self.index = faiss.read_index(idx_file)
        with open(mt_file, "rb") as f:
            self.metadata = pickle.load(f)
        return True

    def is_loaded(self):
        return self.index is not None

    def get_stats(self):
        if self.index is None:
            return {"total_chunks": 0, "dimension": 0}
        return {
            "total_chunks": self.index.ntotal,
            "dimension": self.index.d,
        }

    def load_manifest(self):
        if not os.path.exists(FAISS_MANIFEST_FILE):
            return {}
        try:
            with open(FAISS_MANIFEST_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save_manifest(self, manifest):
        os.makedirs(os.path.dirname(FAISS_MANIFEST_FILE), exist_ok=True)
        with open(FAISS_MANIFEST_FILE, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)

    def get_indexed_sources(self):
        manifest = self.load_manifest()
        result = {}
        for src_type, entries in manifest.items():
            if isinstance(entries, list):
                result[src_type] = [e.get("source_path") for e in entries if e.get("source_path")]
        return result

    def mark_source_indexed(self, source_type, source_path, agg_file, chunk_count):
        manifest = self.load_manifest()
        if source_type not in manifest:
            manifest[source_type] = []
        existing = {e["source_path"]: i for i, e in enumerate(manifest[source_type]) if isinstance(e, dict)}
        from datetime import datetime
        entry = {
            "source_path": source_path,
            "agg_file": agg_file,
            "chunk_count": chunk_count,
            "indexed_at": datetime.now().isoformat(),
        }
        if source_path in existing:
            manifest[source_type][existing[source_path]] = entry
        else:
            manifest[source_type].append(entry)
        self.save_manifest(manifest)

    def save_anomaly_chunks(self, chunks):
        os.makedirs(os.path.dirname(ANOMALY_CHUNKS_FILE), exist_ok=True)
        with open(ANOMALY_CHUNKS_FILE, "w", encoding="utf-8") as f:
            json.dump(chunks, f, ensure_ascii=False, indent=2)

    def load_anomaly_chunks(self):
        if not os.path.exists(ANOMALY_CHUNKS_FILE):
            return []
        try:
            with open(ANOMALY_CHUNKS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def remove_source_from_manifest(self, source_type, source_path):
        manifest = self.load_manifest()
        if source_type in manifest and isinstance(manifest[source_type], list):
            manifest[source_type] = [
                e for e in manifest[source_type]
                if not (isinstance(e, dict) and e.get("source_path") == source_path)
            ]
        self.save_manifest(manifest)


def _enrich_chunk(c):
    enriched = dict(c)
    enriched["metadata"] = dict(c.get("metadata", {}))
    enriched["metadata"]["source_text"] = c["text"]
    return enriched


def build_index_from_chunks(chunks, save=True, existing_index=None, source_type=None):
    embedder = Embedder()
    faiss_idx = existing_index if existing_index else FAISSIndex(embedder, source_type=source_type)
    enriched_chunks = [_enrich_chunk(c) for c in chunks]
    for c in enriched_chunks:
        c["metadata"]["source_type"] = source_type or "unknown"
    if faiss_idx.index is None:
        texts = [c["text"] for c in enriched_chunks]
        embeddings = embedder.encode(texts, show_progress=True)
        dim = embeddings.shape[1]
        faiss_idx.index = faiss.IndexFlatIP(dim)
        faiss_idx.metadata = [c["metadata"] for c in enriched_chunks]
        faiss_idx.index.add(embeddings)
    else:
        texts = [c["text"] for c in enriched_chunks]
        embeddings = embedder.encode(texts, show_progress=True)
        faiss_idx.index.add(embeddings)
        faiss_idx.metadata.extend([c["metadata"] for c in enriched_chunks])
    if save:
        faiss_idx.save()
    return faiss_idx


def build_index_from_file(chunks_file, save=True):
    with open(chunks_file, "r", encoding="utf-8") as f:
        chunks = json.load(f)
    return build_index_from_chunks(chunks, save=save)


def load_or_build_index(chunks=None, source_type=None):
    faiss_idx = FAISSIndex(source_type=source_type)
    if faiss_idx.load():
        return faiss_idx
    if chunks:
        return build_index_from_chunks(chunks, save=True, source_type=source_type)
    return faiss_idx
