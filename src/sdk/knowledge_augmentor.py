"""
Adversarial Knowledge Augmentor (RAG)

Uses ChromaDB to load a dataset of bug bounty reports and vulnerability methodologies,
and injects relevant adversarial patterns into agent prompts dynamically.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from loguru import logger

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

class KnowledgeAugmentor:
    """
    RAG Engine for Adversarial Cognitive Augmentation.
    """
    
    def __init__(self, db_path: str = ".knowledge_db", dataset_path: str = "data/bugbounty_dataset.json"):
        self.db_path = Path(db_path)
        self.dataset_path = Path(dataset_path)
        self.client = None
        self.collection = None
        self._initialized = False
        
        if HAS_CHROMA:
            try:
                self.client = chromadb.PersistentClient(path=str(self.db_path))
                self.collection = self.client.get_or_create_collection(
                    name="adversarial_knowledge",
                    metadata={"hnsw:space": "cosine"}
                )
                self._initialized = True
            except Exception as e:
                logger.error(f"[KnowledgeAugmentor] Failed to init ChromaDB: {e}")

    def index_dataset(self):
        """Load and index the JSON dataset into ChromaDB."""
        if not self._initialized or not self.collection:
            logger.warning("[KnowledgeAugmentor] Cannot index, engine not initialized.")
            return

        if not self.dataset_path.exists():
            logger.warning(f"[KnowledgeAugmentor] Dataset not found at {self.dataset_path}")
            return
            
        try:
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            documents = []
            metadatas = []
            ids = []
            
            for i, entry in enumerate(data):
                # We format the entry text to contain instruction + output methodology
                text = f"Context: {entry.get('instruction', '')}\nMethodology: {entry.get('output', '')}"
                documents.append(text)
                
                # Add basic metadata
                metadatas.append({"vuln_type": entry.get("vuln_type", "unknown")})
                ids.append(f"kb_{i}")
                
            if documents:
                # Upsert all into Chroma
                self.collection.upsert(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                logger.info(f"[KnowledgeAugmentor] Indexed {len(documents)} adversarial patterns.")
                
        except Exception as e:
            logger.error(f"[KnowledgeAugmentor] Indexing failed: {e}")

    def get_relevant_patterns(self, query: str, n_results: int = 3) -> str:
        """
        Query the RAG engine for relevant bypasses/methodologies based on the current attack context.
        """
        if not self._initialized or not self.collection:
            return ""
            
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results
            )
            
            if not results or not results['documents'] or not results['documents'][0]:
                return ""
                
            augmentation = (
                "\n\n=== ADVERSARIAL PATTERN CONTEXT (Bug Bounty Knowledge) ===\n"
                "These are REFERENCE PATTERNS for understanding attack vectors and methodology.\n"
                "ADAPT the approach to the current target. Do NOT replay exact exploits blindly.\n"
                "Use these as cognitive anchors for creative hypothesis generation.\n\n"
            )
            
            docs = results['documents'][0]
            for i, doc in enumerate(docs, 1):
                # truncate doc to avoid exploding context window
                truncated_doc = doc[:1500] + "..." if len(doc) > 1500 else doc
                augmentation += f"--- Pattern {i} ---\n{truncated_doc}\n\n"
                
            augmentation += "=== END ADVERSARIAL PATTERN CONTEXT ===\n"
            return augmentation
            
        except Exception as e:
            logger.error(f"[KnowledgeAugmentor] Retrieval failed: {e}")
            return ""

# Global instance
_augmentor = None

def get_augmentor() -> KnowledgeAugmentor:
    global _augmentor
    if _augmentor is None:
        _augmentor = KnowledgeAugmentor()
    return _augmentor
