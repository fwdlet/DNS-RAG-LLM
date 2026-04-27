from config import TOP_K
from core.embedder import FAISSIndex, Embedder


class Retriever:
    def __init__(self, faiss_index=None, indices=None):
        self.faiss_indices = []
        if faiss_index:
            self.faiss_indices.append(faiss_index)
        if indices:
            self.faiss_indices.extend(indices)

    def load_index(self):
        any_loaded = False
        for idx in self.faiss_indices:
            if idx.load():
                any_loaded = True
        return any_loaded

    def retrieve(self, query, top_k=None):
        k = top_k or TOP_K
        if not self.faiss_indices:
            return []
        all_results = []
        for idx in self.faiss_indices:
            if not idx.is_loaded():
                continue
            results = idx.search_with_text(query, top_k=k)
            all_results.extend(results)
        all_results.sort(key=lambda r: r["score"], reverse=True)
        return all_results[:k]

    def retrieve_context(self, query, top_k=None):
        results = self.retrieve(query, top_k)
        if not results:
            return "", []
        context_parts = []
        for i, r in enumerate(results, 1):
            meta = r.get("metadata", {})
            source = meta.get("source", "未知来源")
            agg_type = meta.get("agg_type", "")
            attack = meta.get("attack_mapping", "")
            text = meta.get("source_text", "")
            header = f"[证据块 {i}] 来源: {source}"
            if agg_type:
                header += f" | 类型: {agg_type}"
            if attack:
                header += f" | ATT&CK: {attack}"
            context_parts.append(f"{header}\n{text}")
        context = "\n\n---\n\n".join(context_parts)
        return context, results
