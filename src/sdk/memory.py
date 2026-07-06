"""
Vector Memory System
Long-term memory with semantic search using ChromaDB
Falls back to file-based memory if ChromaDB is not installed
"""

import json
import re
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from loguru import logger

try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    logger.info("ChromaDB not installed. Using file-based memory fallback.")

# â”€â”€ Improvement #6: Better embedding model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Uses all-mpnet-base-v2 (higher semantic quality than default MiniLM-L6-v2).
# Falls back gracefully if sentence-transformers is not installed.
# NOTE: SentenceTransformerEmbeddingFunction() is lazy â€” it can be instantiated
# without the package. We must do a REAL import test to confirm it's available.
_BETTER_EF = None
if CHROMA_AVAILABLE:
    try:
        import sentence_transformers as _st_check  # actual availability test
        del _st_check

        # Suppress HuggingFace Hub network checks and noisy output.
        # HF_HUB_OFFLINE=1  → use cached model weights; never ping HF Hub.
        # TOKENIZERS_PARALLELISM=false → silence tokenizer fork warnings.
        import os as _os
        _os.environ.setdefault("HF_HUB_OFFLINE", "1")
        _os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        _os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
        try:
            import huggingface_hub.utils as _hf_utils
            _hf_utils.disable_progress_bars()
        except Exception:
            pass
        try:
            import transformers.utils.logging as _tf_log
            _tf_log.set_verbosity_error()
        except Exception:
            pass

        from chromadb.utils import embedding_functions as _chroma_ef
        _BETTER_EF = _chroma_ef.SentenceTransformerEmbeddingFunction(
            model_name="all-mpnet-base-v2"
        )
        logger.info("RAG: using all-mpnet-base-v2 embeddings.")
    except (ImportError, Exception):
        logger.info("RAG: sentence-transformers unavailable, using default ChromaDB embeddings.")


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: str
    content: str
    metadata: Dict[str, Any]
    timestamp: str


class FileMemory:
    """
    Simple file-based memory fallback when ChromaDB is not available.
    Stores memories as JSON files for persistence.
    Also syncs to ChromaDB if it becomes available later.
    """
    
    def __init__(self, persist_dir: str = "./.memory"):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.memories_file = self.persist_dir / "memories.json"
        self.memories = self._load_memories()
        self._chroma_synced = False
    
    def _load_memories(self) -> Dict:
        """Load memories from file."""
        if self.memories_file.exists():
            try:
                with open(self.memories_file, 'r') as f:
                    return json.load(f)
            except:
                return {"global": [], "targets": {}}
        return {"global": [], "targets": {}}
    
    def _save_memories(self):
        """Save memories to file."""
        try:
            with open(self.memories_file, 'w') as f:
                json.dump(self.memories, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save memories: {e}")
    
    def _try_sync_to_chroma(self, target: str, content: str, category: str, metadata: Dict):
        """Try to sync entry to ChromaDB if available."""
        if self._chroma_synced:
            return
        
        global CHROMA_AVAILABLE
        if CHROMA_AVAILABLE:
            try:
                # Create a VectorMemory instance and store there too
                vector_mem = VectorMemory(str(self.persist_dir))
                vector_mem.store(target, content, category, metadata)
                logger.debug(f"Synced to ChromaDB: {category}")
            except Exception as e:
                logger.debug(f"Could not sync to ChromaDB: {e}")
    
    def store(self, target: str, content: str, category: str, metadata: Dict = None) -> str:
        """Store a memory entry."""
        entry_id = hashlib.md5(f"{content[:100]}:{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        entry = {
            "id": entry_id,
            "content": content[:5000],  # Limit content size
            "category": category,
            "metadata": metadata or {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Store in target-specific and global
        if target not in self.memories["targets"]:
            self.memories["targets"][target] = []
        
        self.memories["targets"][target].append(entry)
        self.memories["global"].append({**entry, "target": target})
        
        # Keep only last 500 entries per target
        if len(self.memories["targets"][target]) > 500:
            self.memories["targets"][target] = self.memories["targets"][target][-500:]
        if len(self.memories["global"]) > 2000:
            self.memories["global"] = self.memories["global"][-2000:]
        
        self._save_memories()
        
        # Try to sync to ChromaDB
        self._try_sync_to_chroma(target, content, category, metadata or {})
        
        logger.debug(f"Stored memory: {category} for {target}")
        return entry_id
    
    def search(self, query: str, target: str = None, category: str = None, limit: int = 10) -> List[Dict]:
        """Simple keyword-based search (no semantic search without ChromaDB)."""
        query_lower = query.lower()
        query_words = query_lower.split()
        
        # Get entries to search
        if target:
            entries = self.memories["targets"].get(target, [])
        else:
            entries = self.memories["global"]
        
        # Filter by category if specified
        if category:
            entries = [e for e in entries if e.get("category") == category]
        
        # Score entries by keyword matches
        scored = []
        for entry in entries:
            content_lower = entry.get("content", "").lower()
            score = sum(1 for word in query_words if word in content_lower)
            if score > 0:
                scored.append((score, entry))
        
        # Sort by score and return top results
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"content": e["content"], "metadata": e.get("metadata", {}), "id": e["id"]} 
                for _, e in scored[:limit]]
    
    def get_context(self, target: str, query: str = None, max_tokens: int = 4000) -> str:
        """Get context from memory."""
        if target not in self.memories["targets"]:
            return ""
        
        entries = self.memories["targets"][target]
        if not entries:
            return ""
        
        # Build context string
        context_lines = ["=== PREVIOUS FINDINGS ==="]
        char_count = 0
        max_chars = max_tokens * 4
        
        # Group by category
        by_category = {}
        for entry in entries[-50:]:  # Last 50 entries
            cat = entry.get("category", "other")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(entry)
        
        for category, cat_entries in by_category.items():
            context_lines.append(f"\n## {category.upper()}")
            for entry in cat_entries[-5:]:  # Last 5 per category
                content = entry.get("content", "")[:500]
                context_lines.append(f"- {content}")
                char_count += len(content)
                if char_count > max_chars:
                    break
            if char_count > max_chars:
                break
        
        context_lines.append("\n=== END PREVIOUS FINDINGS ===")
        return "\n".join(context_lines)
    
    def get_stats(self, target: str = None) -> Dict:
        """Get memory statistics."""
        stats = {"global_entries": len(self.memories["global"])}
        if target and target in self.memories["targets"]:
            stats["target_entries"] = len(self.memories["targets"][target])
        return stats
    
    def clear_target(self, target: str):
        """Clear memory for a target."""
        if target in self.memories["targets"]:
            del self.memories["targets"][target]
            self.memories["global"] = [e for e in self.memories["global"] if e.get("target") != target]
            self._save_memories()


# â”€â”€â”€ Module-level constants used by VectorMemory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Compiled regex patterns for security-relevant content extraction (#4)
_SUMMARY_PATTERNS = [
    re.compile(r"\d{1,5}/tcp\s+(open|filtered|closed)", re.IGNORECASE),
    re.compile(r"\d{1,5}/udp\s+(open|filtered|closed)", re.IGNORECASE),
    re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\s*[:â€“\-]", re.IGNORECASE),
    re.compile(r"\[.*?(critical|high|medium|low|vuln).*?\]", re.IGNORECASE),
    re.compile(r"(vulnerable|vulnerability|exploit|rce|xss|sqli|lfi|ssrf|ssti|idor)", re.IGNORECASE),
    re.compile(r"(username|password|hash|token|api.?key)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"https?://[^\s]{10,}"),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"(found|discovered|detected|confirmed|identified)\s+.{5,}", re.IGNORECASE),
    re.compile(r"subdomain\s+.{3,}|[a-z0-9\-]+\.[a-z]{2,}\s+alive", re.IGNORECASE),
]

# HyDE expansion map: short security keywords -> rich hypothetical documents (#7)
_HYDE_EXPANSIONS: Dict[str, str] = {
    "sqli":            "SQL injection vulnerability found in parameter. Error-based and blind. Payload: ' OR 1=1-- confirmed data leakage.",
    "sql":             "SQL injection vulnerability found in parameter. Error-based and blind. Payload: ' OR 1=1-- confirmed data leakage.",
    "xss":             "Cross-site scripting XSS reflected. Payload: <script>alert(1)</script> executed in victim browser.",
    "idor":            "Insecure direct object reference BOLA. Changed user ID in API exposed another user's sensitive records.",
    "bola":            "Insecure direct object reference BOLA. Changed user ID in API exposed another user's sensitive records.",
    "ssrf":            "Server-side request forgery SSRF confirmed via Burp Collaborator callback. AWS metadata endpoint accessible.",
    "rce":             "Remote code execution confirmed via command injection. `id` output returned in HTTP response.",
    "lfi":             "Local file inclusion confirmed. /etc/passwd contents returned in HTTP response body via path traversal.",
    "ssti":            "Server-side template injection confirmed. {{7*7}} evaluated to 49 in Jinja2/Twig/Freemarker.",
    "xxe":             "XML external entity injection confirmed. External entity resolved and /etc/passwd returned.",
    "csrf":            "Cross-site request forgery. Forged form executed authenticated state-changing action without CSRF token.",
    "jwt":             "JWT authentication bypass via algorithm confusion or weak secret. Forged token with alg:none accepted.",
    "deserialization": "Java deserialization gadget chain RCE via ysoserial payload. OS command executed on target.",
    "open port":       "Nmap scan revealed open port with service running. Port accessible from internet-facing interface.",
    "subdomain":       "Subdomain enumeration found live subdomains. Subfinder and amass discovered additional attack surface.",
    "credential":      "Credentials discovered: username and password extracted from tool output or HTTP response.",
    "cve":             "CVE vulnerability matched running service version. Nuclei or searchsploit confirmed exploitable.",
    "race":            "Race condition exploited. Concurrent requests caused double-spend via TOCTOU window.",
    "prototype":       "Prototype pollution confirmed. __proto__ injection affected application behaviour server-side.",
    "smuggling":       "HTTP request smuggling CL.TE desync confirmed. Front-end and back-end interpret body length differently.",
}


class VectorMemory:
    """
    Vector-based memory system for long-term context storage.
    
    Features:
    - Persistent storage across sessions
    - Semantic search (find by meaning, not keywords)
    - Per-target memory collections
    - Automatic summarization of long content
    - Cross-target intelligence search
    
    Uses ChromaDB for embedded vector storage (no server needed).
    """
    
    def __init__(self, persist_dir: str = "./.memory"):
        """
        Initialize vector memory.
        
        Args:
            persist_dir: Directory to store the vector database
        """
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        if not CHROMA_AVAILABLE:
            self.client = None
            self.collections = {}
            return
        
        # Initialize ChromaDB with persistence and auto-recovery
        max_retries = 2
        for attempt in range(max_retries):
            try:
                self.client = chromadb.PersistentClient(
                    path=str(self.persist_dir),
                    settings=Settings(anonymized_telemetry=False)
                )
                
                # Global collection for cross-target search
                self.global_collection = self.client.get_or_create_collection(
                    name="global_memory",
                    embedding_function=_BETTER_EF,
                    metadata={"description": "Cross-target intelligence"}
                )
                
                # Per-target collections cache
                self.collections: Dict[str, Any] = {}
                break  # Success!
                
            except BaseException as e:  # Catches Exception AND Rust panics
                error_msg = str(e)
                error_type = type(e).__name__
                
                # Detect ChromaDB corruption (Rust panic, index errors, SQLite issues)
                corruption_indicators = [
                    "range start index",
                    "PanicException",
                    "out of range for slice",
                    "corrupted",
                    "database disk image is malformed",
                    "pyo3_runtime",
                    "rust/sqlite"
                ]
                
                is_corrupted = any(indicator in error_msg or indicator in error_type for indicator in corruption_indicators)
                
                if is_corrupted and attempt < max_retries - 1:
                    # Corrupted database detected - auto-recover
                    print(f"\nâš ï¸  ChromaDB database corrupted: {error_type}")
                    print(f"    Error: {error_msg[:150]}")
                    print(f"ðŸ”„ Attempting automatic recovery (attempt {attempt + 1}/{max_retries})...\n")
                    
                    # Backup corrupted database
                    backup_dir = self.persist_dir.parent / f"{self.persist_dir.name}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    try:
                        if self.persist_dir.exists():
                            shutil.move(str(self.persist_dir), str(backup_dir))
                            print(f"ðŸ“¦ Backed up corrupted DB to: {backup_dir}")
                    except Exception as backup_error:
                        print(f"âš ï¸  Backup failed: {backup_error}")
                        # Force delete if backup fails
                        try:
                            shutil.rmtree(str(self.persist_dir), ignore_errors=True)
                            print("ðŸ—‘ï¸  Removed corrupted database")
                        except:
                            pass
                    
                    # Recreate directory
                    self.persist_dir.mkdir(parents=True, exist_ok=True)
                    print("âœ… Creating fresh database...\n")
                    continue  # Retry initialization
                else:
                    # Non-corruption error or final retry failed
                    print(f"\nâš ï¸  ChromaDB initialization failed: {error_type}")
                    print(f"    {error_msg[:200]}")
                    print("    Falling back to basic memory (no vector search)")
                    print(f"    Manual fix: rm -rf {self.persist_dir}\n")
                    self.client = None
                    self.collections = {}
                    self.global_collection = None
                    break
    
    def _get_target_collection(self, target: str):
        """Get or create a collection for a specific target."""
        if not self.client:
            return None
            
        # Sanitize target name for collection
        safe_name = target.replace(".", "_").replace("/", "_").replace(":", "_")[:50]
        
        if safe_name not in self.collections:
            self.collections[safe_name] = self.client.get_or_create_collection(
                name=f"target_{safe_name}",
                embedding_function=_BETTER_EF,
                metadata={"target": target}
            )
        
        return self.collections[safe_name]
    
    def _generate_id(self, content: str, category: str) -> str:
        """Generate a unique ID for content."""
        hash_input = f"{content[:500]}:{category}:{datetime.now().isoformat()}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]

    # â”€â”€ Improvement #1: Document Chunking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _chunk_content(self, content: str, chunk_size: int = 800, overlap: int = 150) -> List[str]:
        """
        Split long content into overlapping chunks.
        Smaller focused chunks produce much higher-quality embeddings than
        a single 5000-char blob.
        """
        if len(content) <= chunk_size:
            return [content]
        chunks: List[str] = []
        start = 0
        while start < len(content):
            end = min(start + chunk_size, len(content))
            chunks.append(content[start:end])
            if end == len(content):
                break
            start += chunk_size - overlap
        return chunks

    # â”€â”€ Improvement #3: Deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _is_duplicate(self, collection, content_hash: str) -> bool:
        """Return True if an entry with this content_hash already exists in the collection."""
        try:
            existing = collection.get(
                where={"content_hash": content_hash},
                limit=1,
                include=[]
            )
            return bool(existing and existing.get("ids"))
        except Exception:
            return False

    def store(self, target: str, content: str, category: str,
              metadata: Dict[str, Any] = None) -> str:
        """
        Store a memory entry.

        Improvements applied:
        - #1: Content chunked (800-char chunks, 150-char overlap) for better embeddings.
        - #3: Deduplication by content hash â€” identical outputs are not re-indexed.

        Args:
            target: Target domain/IP
            content: The content to store (will be embedded)
            category: Type of content (port_scan, vulnerability, credential, note, etc.)
            metadata: Additional metadata

        Returns:
            The ID of the first stored chunk, or empty string on failure
        """
        if not self.client:
            logger.warning("ChromaDB not available, memory not stored")
            return ""

        timestamp = datetime.now().isoformat()
        content_hash = hashlib.md5(content[:500].encode()).hexdigest()[:16]

        # Base metadata includes content_hash for dedup + recency reranking
        base_metadata: Dict[str, Any] = {
            "target": target,
            "category": category,
            "timestamp": timestamp,
            "content_hash": content_hash,
            **(metadata or {})
        }

        # Fast-path deduplication check before chunking
        target_collection = self._get_target_collection(target)
        if target_collection and self._is_duplicate(target_collection, content_hash):
            logger.debug(f"Duplicate skipped: {category} for {target}")
            return content_hash

        # Chunk long content for higher-quality per-chunk embeddings
        chunks = self._chunk_content(content)
        first_id: Optional[str] = None

        for idx, chunk in enumerate(chunks):
            chunk_id = hashlib.md5(
                f"{chunk[:200]}:{category}:{timestamp}:{idx}".encode()
            ).hexdigest()[:16]
            if first_id is None:
                first_id = chunk_id

            chunk_meta = {**base_metadata, "chunk_index": idx, "total_chunks": len(chunks)}

            if target_collection:
                for attempt in range(3):
                    try:
                        target_collection.add(
                            documents=[chunk],
                            metadatas=[chunk_meta],
                            ids=[chunk_id]
                        )
                        break
                    except Exception as e:
                        if attempt == 2:
                            logger.debug(f"Chunk store error (target) after 3 retries: {e}")
                        else:
                            import time; time.sleep(1)

            for attempt in range(3):
                try:
                    self.global_collection.add(
                        documents=[chunk],
                        metadatas=[chunk_meta],
                        ids=[f"global_{chunk_id}"]
                    )
                    break
                except Exception as e:
                    if attempt == 2:
                        logger.debug(f"Chunk store error (global) after 3 retries: {e}")
                    else:
                        import time; time.sleep(1)

        logger.debug(f"Stored {len(chunks)} chunk(s): {category} for {target}")
        return first_id or ""
    
    def store_tool_result(self, target: str, tool_name: str, 
                          result: str, summarize: bool = True) -> str:
        """
        Store a tool execution result with optional summarization.
        
        Args:
            target: Target domain/IP
            tool_name: Name of the tool that produced the result
            result: The tool output
            summarize: Whether to summarize long outputs
        
        Returns:
            The ID of the stored entry
        """
        content = result
        
        # Summarize long outputs
        if summarize and len(result) > 5000:
            content = self._summarize_content(result, tool_name)
        
        return self.store(
            target=target,
            content=content,
            category="tool_result",
            metadata={"tool": tool_name, "original_length": len(result)}
        )
    
    def store_finding(self, target: str, finding_type: str, 
                      description: str, severity: str = "info",
                      details: Dict = None) -> str:
        """
        Store a security finding.
        
        Args:
            target: Target domain/IP
            finding_type: Type (vulnerability, open_port, credential, subdomain, etc.)
            description: Description of the finding
            severity: Severity level (critical, high, medium, low, info)
            details: Additional details
        
        Returns:
            The ID of the stored entry
        """
        content = f"[{severity.upper()}] {finding_type}: {description}"
        
        if details:
            content += f"\nDetails: {json.dumps(details)}"
        
        return self.store(
            target=target,
            content=content,
            category=finding_type,
            metadata={
                "severity": severity,
                "finding_type": finding_type,
                **(details or {})
            }
        )

    def store_attack_chain(
        self,
        target: str,
        tech_stack: str,
        chain_summary: str,
        vuln_types: list = None,
        success: bool = True
    ) -> str:
        """
        Persist a completed attack chain for future cross-target learning.

        Args:
            target:        Target domain/IP
            tech_stack:    Comma-separated stack (e.g. "Apache 2.4, PHP 7.4, MySQL 5.7")
            chain_summary: Human-readable description of the attack chain
            vuln_types:    List of vulnerability types (e.g. ["sqli", "rce"])
            success:       Whether the chain achieved initial access / goal

        Returns:
            Memory entry ID or empty string on failure
        """
        vuln_types = vuln_types or []
        content = (
            f"[ATTACK CHAIN] Target: {target} | TechStack: {tech_stack} | "
            f"Success: {success}\n{chain_summary}"
        )
        metadata: Dict[str, Any] = {
            "tech_stack": tech_stack,
            "vuln_types": json.dumps(vuln_types),
            "success": str(success).lower(),
        }
        return self.store(target, content, "attack_chain", metadata)

    def recall_similar_attacks(
        self,
        tech_stack: str,
        vuln_type: str = "",
        limit: int = 5
    ) -> List[Dict]:
        """
        Retrieve stored attack chains that match a given tech stack / vuln type.

        Args:
            tech_stack: Technology stack to search for
            vuln_type:  Optional vulnerability type hint
            limit:      Maximum number of results

        Returns:
            List of matching memory entries with relevance scores
        """
        query = f"{tech_stack} {vuln_type}".strip()
        return self.search(query, category="attack_chain", limit=limit)

    def search(self, query: str, target: str = None, 
               category: str = None, limit: int = 10) -> List[Dict]:
        """
        Search memory using semantic similarity.
        
        Args:
            query: Search query (semantic search)
            target: Optional - limit to specific target
            category: Optional - filter by category
            limit: Maximum results to return
        
        Returns:
            List of matching entries with scores
        """
        if not self.client:
            return []
        
        # Build where filter
        where_filter = {}
        if category:
            where_filter["category"] = category
        if target:
            where_filter["target"] = target
        
        # Search appropriate collection
        if target:
            collection = self._get_target_collection(target)
        else:
            collection = self.global_collection
        
        if not collection:
            return []
        
        # HyDE: expand short query to richer hypothetical document (#7)
        search_text = self._generate_hypothetical_doc(query)

        # Fetch extra results so recency reranking has candidates to sort (#5)
        # Add retry loop for transient SSL/Network timeouts (e.g. huggingface model download).
        # Each attempt is wrapped in a 12-second thread timeout so a hung SSL handshake
        # (default ~60 s) doesn't stall the whole agent loop.
        import concurrent.futures as _cf
        results = None
        for attempt in range(3):
            try:
                _n = min(limit * 2, 40)
                _w = where_filter if where_filter else None
                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    _fut = _pool.submit(
                        collection.query,
                        query_texts=[search_text],
                        n_results=_n,
                        where=_w,
                    )
                    results = _fut.result(timeout=12)
                break
            except (_cf.TimeoutError, Exception) as e:
                err_str = str(e)
                is_network = (
                    isinstance(e, _cf.TimeoutError)
                    or "timeout" in err_str.lower()
                    or "ssl" in err_str.lower()
                )
                if is_network and attempt < 2:
                    logger.warning(f"RAG network timeout (attempt {attempt+1}/3), retrying...")
                    continue

                # Detect embedding dimension mismatch OR embedding function mismatch.
                # ChromaDB raises errors like:
                #   "Collection expecting embedding with dimension of 384, got 768"
                #   "embedding function" / "sentence_transformer" related messages
                _is_ef_mismatch = (
                    "dimension" in err_str.lower()
                    or "embedding function" in err_str.lower()
                    or "sentence_transformer" in err_str.lower()
                )
                if _is_ef_mismatch:
                    logger.warning(
                        "RAG: embedding dimension/EF mismatch detected â€” "
                        "rebuilding collection with current embedding function."
                    )
                    try:
                        coll_name = collection.name
                        self.client.delete_collection(coll_name)
                        if coll_name == "global_memory":
                            self.global_collection = self.client.get_or_create_collection(
                                name=coll_name,
                                embedding_function=_BETTER_EF,
                                metadata={"description": "Cross-target intelligence"}
                            )
                            logger.info("RAG: global_memory collection rebuilt.")
                        else:
                            target_key = coll_name.replace("target_", "", 1)
                            self.collections.pop(target_key, None)
                            # Recreate immediately so the cache is warm
                            self.collections[target_key] = self.client.get_or_create_collection(
                                name=coll_name,
                                embedding_function=_BETTER_EF,
                                metadata={"target": target_key}
                            )
                            logger.info(f"RAG: target collection '{coll_name}' rebuilt.")
                    except Exception as rec_err:
                        logger.error(f"RAG: collection rebuild failed: {rec_err}")
                else:
                    logger.error(f"Search error: {e}")
                return []


        # Format results
        formatted = []
        if results and results["documents"]:
            for i, doc in enumerate(results["documents"][0]):
                formatted.append({
                    "content": doc,
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "id": results["ids"][0][i] if results["ids"] else "",
                    "distance": results["distances"][0][i] if results.get("distances") else 0
                })

        # Recency-weighted re-ranking, trim to requested limit (#5)
        return self._rerank_by_recency(formatted)[:limit]
    
    def get_context(self, target: str, query: str = None, 
                    max_tokens: int = 4000) -> str:
        """
        Get relevant context for an agent query.
        
        Args:
            target: Target domain/IP
            query: Optional query to find relevant context
            max_tokens: Approximate max tokens for context
        
        Returns:
            Formatted context string
        """
        if not self.client:
            return ""
        
        collection = self._get_target_collection(target)
        if not collection:
            return ""
        
        # Get all entries or search by query
        if query:
            results = self.search(query, target=target, limit=20)
        else:
            # Get recent entries
            try:
                results_raw = collection.get(limit=50)
                results = []
                if results_raw and results_raw["documents"]:
                    for i, doc in enumerate(results_raw["documents"]):
                        results.append({
                            "content": doc,
                            "metadata": results_raw["metadatas"][i] if results_raw["metadatas"] else {}
                        })
            except:
                results = []
        
        if not results:
            return ""
        
        # Build context string
        context_lines = ["=== PREVIOUS FINDINGS ==="]
        char_count = 0
        max_chars = max_tokens * 4  # Rough estimate
        
        # Group by category
        by_category = {}
        for r in results:
            cat = r.get("metadata", {}).get("category", "other")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(r)
        
        for category, entries in by_category.items():
            context_lines.append(f"\n## {category.upper()}")
            for entry in entries[:5]:  # Max 5 per category
                content = entry.get("content", "")[:500]  # Truncate long entries
                context_lines.append(f"- {content}")
                char_count += len(content)
                
                if char_count > max_chars:
                    break
            
            if char_count > max_chars:
                break
        
        context_lines.append("\n=== END PREVIOUS FINDINGS ===")
        return "\n".join(context_lines)
    
    def _summarize_content(self, content: str, context: str = "") -> str:
        """
        Extract security-relevant lines using compiled regex patterns (Improvement #4).
        Covers: open ports, CVEs, severity labels, credentials, IPs, URLs,
        common finding keywords, and subdomain discovery lines.
        """
        lines = content.split("\n")
        summary_lines: List[str] = []

        for line in lines[:800]:  # Scan more lines for better coverage
            stripped = line.strip()
            if not stripped:
                continue
            if any(pat.search(stripped) for pat in _SUMMARY_PATTERNS):
                summary_lines.append(stripped)
                if len(summary_lines) >= 80:
                    break

        if summary_lines:
            return f"[SUMMARY of {context}]\n" + "\n".join(summary_lines)
        # Fallback: first 60 non-empty lines
        fallback = [l.strip() for l in lines[:200] if l.strip()][:60]
        return f"[SUMMARY of {context}]\n" + "\n".join(fallback)
    
    # â”€â”€ Improvement #5: Recency-weighted re-ranking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _rerank_by_recency(self, results: List[Dict], recency_weight: float = 0.3) -> List[Dict]:
        """
        Re-rank results by blending cosine similarity with a recency score.
        Entries decay to zero recency contribution after 7 days (168 hours).
        """
        now = datetime.now()
        for r in results:
            ts = r.get("metadata", {}).get("timestamp", "")
            try:
                age_hours = (now - datetime.fromisoformat(ts)).total_seconds() / 3600
                recency_score = max(0.0, 1.0 - (age_hours / 168.0))
            except Exception:
                recency_score = 0.0
            semantic_score = max(0.0, 1.0 - r.get("distance", 1.0))
            r["_final_score"] = (1.0 - recency_weight) * semantic_score + recency_weight * recency_score
        return sorted(results, key=lambda x: x.get("_final_score", 0.0), reverse=True)

    # â”€â”€ Improvement #7: HyDE (Hypothetical Document Embeddings) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def _generate_hypothetical_doc(self, query: str) -> str:
        """
        Expand a short security keyword query into a richer hypothetical document
        before embedding it, dramatically improving ChromaDB recall.
        Falls back to the original query when no expansion is available.
        """
        q_lower = query.lower()
        for key, expansion in _HYDE_EXPANSIONS.items():
            if key in q_lower:
                return expansion
        return query

    def get_stats(self, target: str = None) -> Dict:
        """Get memory statistics."""
        if not self.client:
            return {"error": "ChromaDB not available"}
        
        stats = {
            "global_entries": self.global_collection.count()
        }
        
        if target:
            collection = self._get_target_collection(target)
            if collection:
                stats["target_entries"] = collection.count()
        
        return stats
    
    def clear_target(self, target: str):
        """Clear all memory for a target."""
        if not self.client:
            return
        
        safe_name = target.replace(".", "_").replace("/", "_").replace(":", "_")[:50]
        
        try:
            self.client.delete_collection(f"target_{safe_name}")
            if safe_name in self.collections:
                del self.collections[safe_name]
            logger.info(f"Cleared memory for {target}")
        except:
            pass


# Global instance
_memory = None


def get_memory():
    """
    Get or create the global memory instance.
    Uses ChromaDB if available, otherwise falls back to file-based memory.
    """
    global _memory
    if _memory is None:
        if CHROMA_AVAILABLE:
            _memory = VectorMemory()
            logger.info("Using ChromaDB vector memory")
        else:
            _memory = FileMemory()
            logger.info("Using file-based memory (install chromadb for semantic search)")
    return _memory


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


# CROSS-SESSION MEMORY BRIDGE  (merged from session_memory.py)
# =============================================================================
# Bridges the profile system â†” vector/file memory system so the orchestrator
# can recall "what happened last time" across sessions.
#
# Usage:
#   from src.sdk.memory import get_session_memory, inject_history_into_task
#   enriched_task = inject_history_into_task(target, user_task)
#   get_session_memory().save_session_findings(target, findings, session_id)


_MEMORY_CONTEXT_MAX_CHARS = 3_000   # Injected into task prefix (token budget)
_MAX_SESSIONS_RECALLED    = 5       # How many past sessions to surface
_SIGNIFICANT_TOOLS = frozenset({
    # Recon
    "nmap_scan", "subfinder_enum", "amass_enum", "dnsrecon_enum",
    "dnsenum_scan", "httpx_probe", "whatweb_scan", "shodan_search",
    # Vuln scanning
    "nuclei_scan", "wpscan", "nikto_scan",
    # Exploitation
    "sqlmap_attack", "dalfox_scan", "tplmap_scan", "xsstrike",
    "nosqlmap_attack", "jwt_tool_attack", "hydra_bruteforce",
    # Post-exploitation
    "impacket_secretsdump", "evil_winrm", "crackmapexec",
    "mimikatz_dump", "dump_shadow",
})


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Core bridge class
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class SessionMemoryBridge:
    """
    Bridges the profile system â†” vector/file memory system.

    Responsibilities
    ----------------
    1. **persist_finding** â€” store a structured finding into the memory backend
       so it survives to future sessions.
    2. **save_session_findings** â€” bulk-save a session's findings + profile
       snapshot at the end of a run.
    3. **build_history_prefix** â€” serialise cross-session memory into a compact
       string that can be prepended to any agent task.
    """

    # Module-level cache shared across all SessionMemoryBridge instances.
    # Maps target → (prefix_string, expiry_timestamp).
    # Prevents multiple sub-agent delegations in one orchestrator turn from
    # each triggering a full ChromaDB semantic search.
    _PREFIX_CACHE: dict = {}
    _PREFIX_CACHE_TTL: float = 120.0  # seconds

    def __init__(self):
        self._memory = None      # lazy: avoid import-time ChromaDB init
        self._pm     = None      # lazy: profile manager

    # ------------------------------------------------------------------
    # Lazy accessors
    # ------------------------------------------------------------------

    def _get_memory(self):
        if self._memory is None:
            try:
                self._memory = get_memory()
            except Exception as e:
                logger.debug(f"SessionMemoryBridge: memory unavailable: {e}")
        return self._memory

    def _get_pm(self):
        if self._pm is None:
            try:
                from src.repl.profiles import get_profile_manager
                self._pm = get_profile_manager()
            except Exception as e:
                logger.debug(f"SessionMemoryBridge: profile manager unavailable: {e}")
        return self._pm

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def persist_finding(
        self,
        target: str,
        finding_type: str,
        description: str,
        severity: str = "info",
        tool_name: str = "",
        details: dict | None = None,
    ) -> None:
        """
        Persist a single finding to the memory backend.
        Called from the on_tool_end callback after notable results.
        """
        mem = self._get_memory()
        if mem is None:
            return
        try:
            metadata = {"tool": tool_name, **(details or {})}
            mem.store_finding(
                target=target,
                finding_type=finding_type,
                description=description,
                severity=severity,
                details=metadata,
            )
        except Exception as e:
            logger.debug(f"persist_finding failed: {e}")

    def save_session_findings(
        self,
        target: str,
        findings: list[str] = None,
        session_id: str = "",
    ) -> None:
        """
        Bulk-save a session's extracted findings to the memory backend,
        plus a snapshot of the current profile brief.

        Called once at the end of each agent run from target_manager.
        """
        findings = findings or []
        mem = self._get_memory()
        if mem is None:
            return

        timestamp = datetime.now().isoformat()
        sid = session_id or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # 1. Store each finding individually for semantic search
        for finding in findings:
            try:
                # Crude severity sniff from the finding string
                sev = "info"
                fl = finding.lower()
                if any(k in fl for k in ("critical", "rce", "injection confirmed", "access obtained")):
                    sev = "critical"
                elif any(k in fl for k in ("high", "xss", "sqli", "ssti", "hash")):
                    sev = "high"
                elif any(k in fl for k in ("medium", "open port", "cve")):
                    sev = "medium"

                mem.store(
                    target=target,
                    content=finding,
                    category="session_finding",
                    metadata={"session": sid, "timestamp": timestamp, "severity": sev},
                )
            except Exception as e:
                logger.debug(f"save_session_findings store error: {e}")

        # 2. Store a full profile snapshot for "recall from last session"
        pm = self._get_pm()
        if pm:
            try:
                brief = pm.get_context_brief(target)
                if brief:
                    mem.store(
                        target=target,
                        content=f"[SESSION SNAPSHOT â€” {timestamp}]\n{brief}",
                        category="profile_snapshot",
                        metadata={"session": sid, "timestamp": timestamp},
                    )
            except Exception as e:
                logger.debug(f"save_session_findings profile snapshot error: {e}")

        logger.info(f"Saved {len(findings)} findings to cross-session memory for {target}")

    def build_history_prefix(self, target: str, query: str = "") -> str:
        """
        Build a compact history block to prepend to a new agent task.

        Pulls:
          - The current profile brief (ports, subdomains, vulns, creds).
          - The most recent profile snapshot from memory.
          - Top relevant findings via semantic search (if ChromaDB available).

        Result is cached per-target for _PREFIX_CACHE_TTL seconds so that
        multiple sub-agent delegations within one orchestrator turn each reuse
        the same result rather than each triggering a separate ChromaDB query.

        Returns empty string if there is nothing meaningful to inject.
        """
        import time as _time
        cache_key = f"{target}||{(query or '')[:60]}"
        cached = SessionMemoryBridge._PREFIX_CACHE.get(cache_key)
        if cached is not None:
            prefix, expiry = cached
            if _time.monotonic() < expiry:
                logger.debug(f"SessionMemoryBridge: returning cached history prefix for {target}")
                return prefix

        sections: list[str] = []

        def _normalize(value: str) -> str:
            value = (value or "").strip().lower()
            if not value:
                return ""
            if "://" in value:
                try:
                    from urllib.parse import urlparse
                    return (urlparse(value).hostname or value).lower()
                except Exception:
                    return value
            if ":" in value and not value.startswith("["):
                return value.split(":", 1)[0].lower()
            return value

        def _same_target(candidate: str) -> bool:
            candidate_norm = _normalize(candidate)
            target_norm = _normalize(target)
            if not candidate_norm or candidate_norm == target_norm:
                return True
            pm_for_compare = self._get_pm()
            if pm_for_compare:
                try:
                    return pm_for_compare.targets_equivalent(target_norm, candidate_norm)
                except Exception:
                    return False
            return False

        def _brief_has_observed_target_data(brief: str) -> bool:
            data_markers = (
                "IPs:",
                "Open ports:",
                "Subdomains",
                "Known vulnerabilities:",
                "Credentials:",
                "Target Scope Details:",
                "Web stack:",
                "Discovered paths:",
                "API endpoints:",
                "Exposed dev/admin tooling:",
                "Candidate attack paths:",
                "Uploaded shells/artifacts:",
                "DNS:",
            )
            return any(marker in brief for marker in data_markers)

        def _redact_active_target_identifiers(text: str) -> str:
            identifiers = {_normalize(target)}
            pm_for_aliases = self._get_pm()
            if pm_for_aliases:
                try:
                    identifiers.update(_normalize(item) for item in pm_for_aliases.get_related_targets(target))
                except Exception:
                    pass
            for ident in sorted((i for i in identifiers if i), key=len, reverse=True):
                text = re.sub(
                    rf"(?<![\w.-]){re.escape(ident)}(?![\w.-])",
                    "[active-target]",
                    text,
                    flags=re.IGNORECASE,
                )
            return text

        # â”€â”€ 1. Live profile brief (always up-to-date) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        pm = self._get_pm()
        if pm:
            try:
                brief = pm.get_context_brief(target)
                if brief and _brief_has_observed_target_data(brief):
                    sections.append(brief)
            except Exception:
                pass

        # â”€â”€ 2. Prior-session memory search â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        mem = self._get_memory()
        if mem:
            try:
                q = query or f"security findings vulnerabilities for {target}"
                results = mem.search(q, target=target, limit=_MAX_SESSIONS_RECALLED)
                if results:
                    prior_lines: list[str] = []
                    for r in results:
                        content = r.get("content", "")
                        metadata = r.get("metadata", {}) or {}
                        result_target = metadata.get("target", "")
                        if result_target and not _same_target(result_target):
                            logger.debug(
                                "Skipping cross-target memory result: "
                                f"active={target} result_target={result_target}"
                            )
                            continue
                        if content and "[EXISTING RECON DATA" not in content:
                            # Deduplicate vs what's already in sections
                            if content[:80] not in "\n".join(sections):
                                prior_lines.append(f"  â€¢ {content[:200]}")
                    if prior_lines:
                        sections.append(
                            "[PRIOR SESSION FINDINGS â€” recall from memory]\n"
                            + "\n".join(prior_lines[:_MAX_SESSIONS_RECALLED])
                        )
            except Exception as e:
                logger.debug(f"build_history_prefix memory search failed: {e}")

        if not sections:
            SessionMemoryBridge._PREFIX_CACHE[cache_key] = (
                "",
                _time.monotonic() + SessionMemoryBridge._PREFIX_CACHE_TTL,
            )
            return ""

        # Build the prefix block
        header = (
            "[CROSS-SESSION CONTEXT]\n"
            "The following prior-session data may apply to the active target. "
            "Use it only as fallback context when live progress is blocked or the user asks for it. "
            "The active framework target remains authoritative.\n"
        )
        body = "\n\n".join(sections)

        combined = header + body
        combined = _redact_active_target_identifiers(combined)
        # Hard cap to protect context window
        if len(combined) > _MEMORY_CONTEXT_MAX_CHARS:
            combined = combined[:_MEMORY_CONTEXT_MAX_CHARS] + "\n... [truncated]"

        # Cache so subsequent delegations in the same orchestrator turn skip ChromaDB
        SessionMemoryBridge._PREFIX_CACHE[cache_key] = (
            combined,
            _time.monotonic() + SessionMemoryBridge._PREFIX_CACHE_TTL,
        )
        return combined

    def auto_persist_from_tool(
        self,
        target: str,
        tool_name: str,
        result: str,
        findings: list[str],
    ) -> None:
        """
        Lightweight hook called from main.py's on_tool_end_callback.
        Only persists results from tools that produce significant intelligence.
        Keeps overhead minimal for noisy/frequent tools.
        """
        if tool_name not in _SIGNIFICANT_TOOLS:
            return
        if not result or not target:
            return

        mem = self._get_memory()
        if mem is None:
            return

        try:
            # Summarize + store the raw tool output
            mem.store_tool_result(
                target=target,
                tool_name=tool_name,
                result=result,
                summarize=len(result) > 2_000,
            )
        except Exception as e:
            logger.debug(f"auto_persist_from_tool store failed: {e}")

        # Also store each extracted finding
        for f in findings:
            self.persist_finding(
                target=target,
                finding_type=tool_name,
                description=f,
                tool_name=tool_name,
            )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Module-level singleton + convenience helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_bridge: Optional[SessionMemoryBridge] = None


def get_session_memory() -> SessionMemoryBridge:
    """Get (or lazily create) the global SessionMemoryBridge instance."""
    global _bridge
    if _bridge is None:
        _bridge = SessionMemoryBridge()
    return _bridge


def inject_history_into_task(target: str, task: str, query: str = "") -> str:
    """
    Prepend cross-session context to a task string.

    If there is no prior data for the target the task is returned unchanged.

    Args:
        target: The target domain/IP being assessed.
        task:   The original user task / agent instruction string.
        query:  Optional semantic search query (defaults to generic finding search).

    Returns:
        Enriched task string with history prefix, or original task if nothing found.
    """
    try:
        prefix = get_session_memory().build_history_prefix(target, query)
        if prefix:
            return f"{prefix}\n\n{'â”€' * 60}\n\n{task}"
    except Exception as e:
        logger.debug(f"inject_history_into_task failed: {e}")
    return task

