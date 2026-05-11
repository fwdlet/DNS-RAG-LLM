import json
import os

from core.aggregator import run_all_aggregations, run_all_zeek_aggregations, save_aggregations
from core.preprocessor import process_all, save_chunks, process_dns_aggregations, process_pcap_aggregations
from core.embedder import FAISSIndex, Embedder, build_index_from_chunks, load_or_build_index
from core.retriever import Retriever
from core.analyzer import Analyzer
from config import PROCESSED_DIR, FAISS_DIR, RAW_DNS_DIR, RAW_PCAP_DIR, RAW_ZEEK_DNS_DIR, ANOMALY_CHUNKS_FILE


class RAGPipeline:
    def __init__(self):
        self.embedder = Embedder()
        self.source_indices = {}
        self.retriever = Retriever()
        self.analyzer = Analyzer()

    def _get_source_index(self, source_type):
        if source_type not in self.source_indices:
            self.source_indices[source_type] = FAISSIndex(self.embedder, source_type=source_type)
        return self.source_indices[source_type]

    def _fresh_source_index(self, source_type):
        idx_for_paths = FAISSIndex(self.embedder, source_type=source_type)
        idx_file, meta_file = idx_for_paths._get_paths()
        for f in [idx_file, meta_file]:
            if os.path.exists(f):
                os.remove(f)
        idx = FAISSIndex(self.embedder, source_type=source_type)
        self.source_indices[source_type] = idx
        return idx

    def _load_existing_index(self):
        any_loaded = False
        for st in ["dns_json", "pcap_agg", "zeek_dns", "anomaly"]:
            idx = self._get_source_index(st)
            if idx.load():
                any_loaded = True
        if any_loaded:
            self._build_retriever_for_sources()
        return any_loaded

    def _fresh_index(self):
        self.source_indices = {}
        self.retriever = Retriever()

    def _build_retriever_for_sources(self, source_types=None):
        indices = []
        if source_types:
            for st in source_types:
                idx = self.source_indices.get(st)
                if idx and idx.is_loaded():
                    indices.append(idx)
        else:
            for idx in self.source_indices.values():
                if idx and idx.is_loaded():
                    indices.append(idx)
        self.retriever = Retriever(indices=indices)

    def _reset_source_manifest(self, source_type):
        manifest = FAISSIndex(self.embedder).load_manifest()
        if source_type in manifest:
            manifest[source_type] = []
            FAISSIndex(self.embedder).save_manifest(manifest)

    def _source_dir(self, source_type):
        dirs = {
            "dns_json": RAW_DNS_DIR,
            "pcap_agg": RAW_PCAP_DIR,
            "zeek_dns": RAW_ZEEK_DNS_DIR,
        }
        return dirs.get(source_type, RAW_DNS_DIR)

    def _update_manifest_entry(self, source_type, entry):
        manifest = FAISSIndex(self.embedder).load_manifest()
        manifest.setdefault(source_type, [])
        existing_idx = next(
            (i for i, e in enumerate(manifest[source_type])
             if isinstance(e, dict) and e.get("source_path") == entry.get("source_path")),
            None
        )
        if existing_idx is not None:
            manifest[source_type][existing_idx] = entry
        else:
            manifest[source_type].append(entry)
        FAISSIndex(self.embedder).save_manifest(manifest)

    def build_from_dns_logs(self, source=None, rebuild=False):
        if source and os.path.isfile(source):
            return self._build_from_dns_json_file(os.path.basename(source), rebuild=rebuild)
        return self._build_from_dns_json_all(rebuild=rebuild)

    def _build_from_dns_json_file(self, fname, rebuild=False):
        source_type = "dns_json"
        fpath = os.path.join(RAW_DNS_DIR, fname)
        if not os.path.exists(fpath):
            return {"status": "error", "message": f"文件不存在: {fname}"}

        manifest = FAISSIndex(self.embedder).load_manifest()
        dns_entries = manifest.get("dns_json", [])
        current_mtime = os.path.getmtime(fpath)
        is_indexed = any(
            isinstance(e, dict) and e.get("source_path") == fname
            for e in dns_entries
        )
        has_changed = any(
            isinstance(e, dict) and e.get("source_path") == fname
            and e.get("source_mtime", 0) != current_mtime
            for e in dns_entries
        )

        if not is_indexed or has_changed or rebuild:
            if rebuild:
                self._fresh_source_index(source_type)
            else:
                idx = self._get_source_index(source_type)
                idx.load()
            dns_aggs = run_all_aggregations(fpath)
            if not dns_aggs:
                return {"status": "warning", "message": f"文件 {fname} 聚合结果为空"}
            save_aggregations(dns_aggs)
            chunks = process_dns_aggregations(dns_aggs)
            self.source_indices[source_type] = build_index_from_chunks(
                chunks, save=True,
                existing_index=None if rebuild else self.source_indices.get(source_type),
                source_type=source_type,
            )
            self._update_manifest_entry("dns_json", {
                "source_path": fname,
                "source_mtime": current_mtime,
                "chunk_count": len(chunks),
            })
            self._build_retriever_for_sources([source_type])
            return {
                "status": "success",
                "mode": "rebuild" if rebuild else ("new" if not is_indexed else "updated"),
                "source_file": fname,
                "chunks": len(chunks),
                "index_stats": self.source_indices[source_type].get_stats(),
            }
        return {"status": "skip", "message": f"文件 {fname} 未变化，跳过构建"}

    def _build_from_dns_json_all(self, rebuild=False):
        source_type = "dns_json"
        if rebuild:
            self._fresh_source_index(source_type)
            self._reset_source_manifest(source_type)
        elif not self._get_source_index(source_type).load():
            self._fresh_source_index(source_type)

        dns_aggs = run_all_aggregations()
        chunks = process_dns_aggregations(dns_aggs)
        if not chunks:
            return {"status": "warning", "message": "DNS日志目录下无数据或聚合结果为空"}
        if dns_aggs:
            save_aggregations(dns_aggs)

        manifest = FAISSIndex(self.embedder).load_manifest()
        dns_entries = manifest.get("dns_json", [])
        indexed_paths = {
            e["source_path"] for e in dns_entries
            if isinstance(e, dict) and e.get("source_path")
        }
        new_entries = []
        if os.path.isdir(RAW_DNS_DIR):
            for fname in sorted(os.listdir(RAW_DNS_DIR)):
                if fname.endswith(".json") and fname not in indexed_paths:
                    fpath = os.path.join(RAW_DNS_DIR, fname)
                    new_entries.append({
                        "source_path": fname,
                        "source_mtime": os.path.getmtime(fpath),
                        "chunk_count": len(chunks),
                    })
        self.source_indices[source_type] = build_index_from_chunks(
            chunks, save=True,
            existing_index=None if rebuild else self.source_indices.get(source_type),
            source_type=source_type,
        )
        for entry in new_entries:
            self._update_manifest_entry("dns_json", entry)
        self._build_retriever_for_sources([source_type])
        return {
            "status": "success",
            "mode": "rebuild" if rebuild else "incremental",
            "aggregations": len(dns_aggs),
            "chunks": len(chunks),
            "index_stats": self.source_indices[source_type].get_stats(),
        }

    def _restore_anomaly_chunks(self):
        if not os.path.exists(ANOMALY_CHUNKS_FILE):
            return
        try:
            with open(ANOMALY_CHUNKS_FILE, "r", encoding="utf-8") as f:
                anomaly_chunks = json.load(f)
        except Exception:
            return
        if not anomaly_chunks:
            return
        enriched = []
        for c in anomaly_chunks:
            enriched.append({
                "text": c["text"],
                "metadata": {
                    **c.get("metadata", {}),
                    "source_text": c["text"],
                    "source_type": "anomaly",
                },
            })
        anomaly_idx = self._get_source_index("anomaly")
        anomaly_idx.add_chunks(enriched)
        anomaly_idx.save()

    def build_from_pcap_aggregations(self, rebuild=False):
        source_type = "pcap_agg"
        if rebuild:
            self._fresh_source_index(source_type)
            self._reset_source_manifest(source_type)
        elif not self._get_source_index(source_type).load():
            self._fresh_source_index(source_type)

        chunks = process_pcap_aggregations()
        if not chunks:
            return {"status": "warning", "message": "pcap_agg目录下无数据"}
        self.source_indices[source_type] = build_index_from_chunks(
            chunks, save=True,
            existing_index=None if rebuild else self.source_indices.get(source_type),
            source_type=source_type,
        )
        manifest = FAISSIndex(self.embedder).load_manifest()
        manifest.setdefault("pcap_agg", [])
        existing_paths = {e.get("source_path") for e in manifest["pcap_agg"] if isinstance(e, dict)}
        if os.path.isdir(RAW_PCAP_DIR):
            for fname in sorted(os.listdir(RAW_PCAP_DIR)):
                if fname.endswith(".json") and fname not in existing_paths:
                    self._update_manifest_entry("pcap_agg", {"source_path": fname, "chunk_count": len(chunks)})
        self._build_retriever_for_sources([source_type])
        return {
            "status": "success",
            "mode": "rebuild" if rebuild else "incremental",
            "chunks": len(chunks),
            "index_stats": self.source_indices[source_type].get_stats(),
        }

    def build_from_zeek_dns(self, source=None, rebuild=False):
        source_type = "zeek_dns"
        if rebuild:
            self._fresh_source_index(source_type)
            self._reset_source_manifest(source_type)
        elif not self._get_source_index(source_type).load():
            self._fresh_source_index(source_type)

        zeek_aggs = run_all_zeek_aggregations(source)
        if not zeek_aggs:
            return {"status": "warning", "message": "Zeek DNS目录下无数据或无有效日志"}
        save_aggregations(zeek_aggs)
        chunks = process_dns_aggregations(zeek_aggs)
        if not chunks:
            return {"status": "warning", "message": "Zeek DNS聚合结果转换为文本块为空"}

        self.source_indices[source_type] = build_index_from_chunks(
            chunks, save=True,
            existing_index=None if rebuild else self.source_indices.get(source_type),
            source_type=source_type,
        )
        self._update_manifest_entry("zeek_dns", {
            "source_path": source or "all_zeek_dns",
            "chunk_count": len(chunks),
        })
        self._build_retriever_for_sources([source_type])
        return {
            "status": "success",
            "mode": "rebuild" if rebuild else "incremental",
            "aggregations": len(zeek_aggs),
            "chunks": len(chunks),
            "index_stats": self.source_indices[source_type].get_stats(),
        }

    def build_from_all(self, dns_source=None, rebuild=False):
        if rebuild:
            self._fresh_index()
            FAISSIndex(self.embedder).save_manifest({"dns_json": [], "pcap_agg": [], "zeek_dns": []})
        elif not self._load_existing_index():
            self._fresh_index()

        agg_counts = {}
        total_chunks = 0

        dns_aggs = run_all_aggregations(dns_source)
        if dns_aggs:
            save_aggregations(dns_aggs)
            dns_chunks = process_dns_aggregations(dns_aggs)
            if dns_chunks:
                existing = None if rebuild else self.source_indices.get("dns_json")
                self.source_indices["dns_json"] = build_index_from_chunks(
                    dns_chunks, save=True, existing_index=existing, source_type="dns_json",
                )
                total_chunks += len(dns_chunks)
                agg_counts["dns"] = len(dns_aggs)
                manifest = FAISSIndex(self.embedder).load_manifest()
                manifest.setdefault("dns_json", [])
                indexed_paths = {e.get("source_path") for e in manifest["dns_json"] if isinstance(e, dict)}
                if os.path.isdir(RAW_DNS_DIR):
                    for fname in sorted(os.listdir(RAW_DNS_DIR)):
                        if fname.endswith(".json") and fname not in indexed_paths:
                            self._update_manifest_entry("dns_json", {"source_path": fname, "source_mtime": os.path.getmtime(os.path.join(RAW_DNS_DIR, fname)), "chunk_count": len(dns_chunks)})

        pcap_chunks = process_pcap_aggregations()
        if pcap_chunks:
            existing = None if rebuild else self.source_indices.get("pcap_agg")
            self.source_indices["pcap_agg"] = build_index_from_chunks(
                pcap_chunks, save=True, existing_index=existing, source_type="pcap_agg",
            )
            total_chunks += len(pcap_chunks)
            agg_counts["pcap"] = len(pcap_chunks)
            if os.path.isdir(RAW_PCAP_DIR):
                manifest = FAISSIndex(self.embedder).load_manifest()
                manifest.setdefault("pcap_agg", [])
                existing_paths = {e.get("source_path") for e in manifest["pcap_agg"] if isinstance(e, dict)}
                for fname in sorted(os.listdir(RAW_PCAP_DIR)):
                    if fname.endswith(".json") and fname not in existing_paths:
                        self._update_manifest_entry("pcap_agg", {"source_path": fname, "chunk_count": len(pcap_chunks)})

        zeek_aggs = run_all_zeek_aggregations()
        if zeek_aggs:
            save_aggregations(zeek_aggs)
            zeek_chunks = process_dns_aggregations(zeek_aggs)
            if zeek_chunks:
                existing = None if rebuild else self.source_indices.get("zeek_dns")
                self.source_indices["zeek_dns"] = build_index_from_chunks(
                    zeek_chunks, save=True, existing_index=existing, source_type="zeek_dns",
                )
                total_chunks += len(zeek_chunks)
                agg_counts["zeek"] = len(zeek_aggs)
                self._update_manifest_entry("zeek_dns", {"source_path": "all_zeek_dns", "chunk_count": len(zeek_chunks)})

        if not total_chunks:
            return {"status": "warning", "message": "无可用数据"}

        self._fresh_source_index("anomaly")
        self._restore_anomaly_chunks()
        self._build_retriever_for_sources()
        return {
            "status": "success",
            "mode": "rebuild" if rebuild else "incremental",
            "agg_counts": agg_counts,
            "total_chunks": total_chunks,
            "index_stats": {"total_chunks": total_chunks, "dimension": 0},
        }

    def add_anomaly_chunks(self, chunks):
        if not chunks:
            return {"status": "warning", "message": "无异常数据块"}
        enriched = []
        for c in chunks:
            enriched.append({
                "text": c["text"],
                "metadata": {
                    **c.get("metadata", {}),
                    "source_text": c["text"],
                    "source_type": "anomaly",
                },
            })

        existing_anomaly = FAISSIndex(self.embedder).load_anomaly_chunks()
        existing_ids = {
            (c.get("metadata", {}).get("agg_type"), c.get("metadata", {}).get("created_at"))
            for c in existing_anomaly
        }
        new_chunks = [
            c for c in enriched
            if (c.get("metadata", {}).get("agg_type"), c.get("metadata", {}).get("created_at"))
            not in existing_ids
        ]

        if new_chunks:
            anomaly_idx = self._get_source_index("anomaly")
            anomaly_idx.add_chunks(new_chunks)
            anomaly_idx.save()
            FAISSIndex(self.embedder).save_anomaly_chunks(existing_anomaly + new_chunks)
            self._build_retriever_for_sources()
            return {"status": "success", "added": len(new_chunks), "skipped": len(enriched) - len(new_chunks)}

        return {"status": "success", "added": 0, "skipped": len(enriched)}

    def load_index(self):
        return self._load_existing_index()

    def query(self, question, top_k=None, stream=False):
        if not self.retriever.faiss_indices:
            loaded = self.load_index()
            if not loaded:
                return {"status": "error", "message": "向量索引未构建，请先构建分析语料库"}
        context, results = self.retriever.retrieve_context(question, top_k)
        if not context:
            return {
                "status": "warning",
                "message": "未检索到相关证据",
                "answer": "分析语料库中未找到与该问题相关的证据数据，无法进行分析。",
                "evidence": [],
            }
        if stream:
            answer_stream = self.analyzer.analyze(question, context, stream=True)
            return {
                "status": "success",
                "answer_stream": answer_stream,
                "evidence": results,
                "context": context,
            }
        answer = self.analyzer.analyze(question, context, stream=False)
        return {
            "status": "success",
            "answer": answer,
            "evidence": results,
            "context": context,
        }

    def get_stats(self):
        total_chunks = 0
        dimension = 0
        for idx in self.source_indices.values():
            if idx.is_loaded():
                s = idx.get_stats()
                total_chunks += s["total_chunks"]
                if dimension == 0:
                    dimension = s["dimension"]
        return {"total_chunks": total_chunks, "dimension": dimension}

    def get_stats_by_source(self):
        stats = {}
        for source_type in ["dns_json", "pcap_agg", "zeek_dns", "anomaly"]:
            idx = self.source_indices.get(source_type)
            if idx and idx.is_loaded():
                s = idx.get_stats()
                stats[source_type] = s["total_chunks"]
            else:
                stats[source_type] = 0
        return stats

    def get_indexed_sources(self):
        return FAISSIndex(self.embedder).get_indexed_sources()

    def get_manifest(self):
        return FAISSIndex(self.embedder).load_manifest()
