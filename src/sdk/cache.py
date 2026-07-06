"""
Tool Result Caching System
Caches tool results to avoid redundant scans and improve performance.
"""

import atexit
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from loguru import logger


@dataclass
class CacheEntry:
    """A cached tool result."""
    tool_name: str
    args_hash: str
    result: str
    timestamp: float
    ttl_seconds: int
    hit_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() - self.timestamp > self.ttl_seconds


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_saved_seconds: float = 0.0


class ToolCache:
    """
    Caches tool execution results to avoid redundant operations.
    
    Features:
    - Configurable TTL per tool
    - Automatic eviction of expired entries
    - Persistent storage option
    - Cache statistics
    """
    
    # Default TTL in seconds for different tool types
    DEFAULT_TTLS = {
        # Long-lived results (rarely change)
        "whois_lookup": 86400,      # 24 hours
        "dig_lookup": 3600,          # 1 hour
        "shodan_search": 3600,       # 1 hour
        
        # Medium-lived results
        "nmap_scan": 1800,           # 30 minutes
        "subfinder_enum": 1800,      # 30 minutes
        "httpx_probe": 900,          # 15 minutes
        "whatweb_scan": 900,         # 15 minutes
        
        # Short-lived results (may change)
        "nuclei_scan": 600,          # 10 minutes
        "gobuster_scan": 600,        # 10 minutes
        "nikto_scan": 600,           # 10 minutes
        
        # Never cache (real-time or state-changing)
        "sqlmap_scan": 0,            # Don't cache exploitation
        "metasploit_run": 0,
        "http_request": 0,           # Dynamic
        "browser_visit": 0,
        "full_appsec_scan": 0,       # Stateful: registers finding candidates
        "validate_browser_xss": 0,   # Stateful: promotes finding lifecycle entries
        "validate_oast_ssrf": 0,     # Stateful: registers/promotes OAST validation
        "validate_oast_xxe": 0,      # Stateful: registers/promotes OAST validation
        "authenticated_app_mapper": 0,  # Stateful: records endpoint inventory
        "two_account_authz_engine": 0,  # Stateful: role/session comparison
        "managed_oast_ssrf_validation": 0,  # Stateful: unique OAST canaries
        "business_workflow_state_recorder": 0,  # Stateful: before/action/after capture
        "graphql_authz_replay_probe": 0,  # Stateful: registers resolver authz candidates
        "artifact_glob": 0,        # Filesystem state changes frequently
        "artifact_grep": 0,        # Filesystem state changes frequently
        "artifact_read": 0,        # Filesystem state changes frequently
        "artifact_write": 0,       # Stateful: writes session/workspace artifacts
        "long_task_start": 0,      # Stateful: launches tmux commands
        "long_task_status": 0,     # Stateful: polls live tmux state
        "long_task_list": 0,       # Stateful: reads live task table
        "long_task_resume": 0,     # Stateful: reads live task table
        "tcp_session_open": 0,     # Stateful: opens live TCP connection
        "tcp_session_send": 0,     # Stateful: mutates remote session state
        "tcp_session_read": 0,     # Stateful: reads live TCP stream
        "tcp_session_close": 0,    # Stateful: closes live TCP connection
        "ctf_command": 0,          # Stateful: shell commands must observe live filesystem/process state
        "execute_bash": 0,         # Stateful: shell commands must observe live filesystem/process state
        "curl_request": 0,           # Always live - stale error results must not be replayed
        "curl_exploit": 0,
        "dirsearch_scan": 300,       # 5 min - but error results are filtered out below
    }
    
    def __init__(self, cache_dir: str = "./.cache", max_size: int = 1000):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.stats = CacheStats()
        self.custom_ttls: Dict[str, int] = {}
        self._dirty = False  # True when in-memory state differs from disk
        self._load_cache()
        # Flush to disk on clean interpreter exit - avoids per-write I/O.
        atexit.register(self._flush_if_dirty)
    
    def _load_cache(self):
        """Load cache from disk."""
        cache_file = self.cache_dir / "tool_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    for key, entry_data in data.get("entries", {}).items():
                        entry = CacheEntry(**entry_data)
                        if not entry.is_expired():
                            self.cache[key] = entry
                    stats_data = data.get("stats", {})
                    self.stats = CacheStats(**stats_data)
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}. The file appears corrupted and will be reset.")
                self._dirty = True
                try:
                    if cache_file.exists():
                        cache_file.unlink()
                except Exception:
                    pass
    
    def _save_cache(self):
        """Mark cache as dirty.  Actual write happens via _flush_if_dirty().
        Call _flush_if_dirty() explicitly when an immediate write is required
        (e.g., after ``clear()``).
        """
        self._dirty = True

    def _flush_if_dirty(self):
        """Write cache to disk only when the state has changed since last flush."""
        if not self._dirty:
            return
        try:
            cache_file = self.cache_dir / "tool_cache.json"
            data = {
                "entries": {k: asdict(v) for k, v in self.cache.items()},
                "stats": asdict(self.stats)
            }
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            self._dirty = False
        except Exception as e:
            logger.error(f"Failed to flush cache to disk: {e}")
    
    def _generate_key(self, tool_name: str, args: dict) -> str:
        """Generate a unique cache key for tool + args (SHA-256)."""
        args_str = json.dumps(args, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode()).hexdigest()[:16]
        return f"{tool_name}:{args_hash}"
    
    def _get_ttl(self, tool_name: str) -> int:
        """Get TTL for a tool."""
        if tool_name in self.custom_ttls:
            return self.custom_ttls[tool_name]
        return self.DEFAULT_TTLS.get(tool_name, 300)  # Default 5 minutes
    
    def get(self, tool_name: str, args: dict) -> Optional[Tuple[str, float]]:
        """
        Get cached result if available.
        
        Returns:
            (result, age_seconds) or None if not cached
        """
        ttl = self._get_ttl(tool_name)
        if ttl == 0:
            return None  # Tool should not be cached
        
        key = self._generate_key(tool_name, args)
        
        if key in self.cache:
            entry = self.cache[key]
            if not entry.is_expired():
                entry.hit_count += 1
                self.stats.hits += 1
                age = time.time() - entry.timestamp
                logger.debug(f"Cache HIT: {tool_name} (age: {age:.1f}s)")
                return entry.result, age
            else:
                # Expired, remove it
                del self.cache[key]
                self.stats.evictions += 1
        
        self.stats.misses += 1
        return None
    
    def set(self, tool_name: str, args: dict, result: str, execution_time: float = 0):
        """
        Cache a tool result.
        
        Args:
            tool_name: Name of the tool
            args: Tool arguments
            result: Tool output
            execution_time: How long the tool took (for stats)
        """
        ttl = self._get_ttl(tool_name)
        if ttl == 0:
            return  # Don't cache this tool

        # Never persist error or empty responses - retries must hit the real tool
        _result_stripped = (result or "").strip()
        _ERROR_PREFIXES = (
            "Error:", "error:", "No response received", "No results", "Traceback",
            "ModuleNotFoundError", "ImportError", "FileNotFoundError",
            "timed out", "Connection refused", "Unable to connect",
        )
        if not _result_stripped or any(_result_stripped.startswith(p) for p in _ERROR_PREFIXES):
            logger.debug(f"Cache SKIP (error/empty result): {tool_name}")
            return

        key = self._generate_key(tool_name, args)

        # Evict old entries if at max size
        if len(self.cache) >= self.max_size:
            self._evict_oldest()

        self.cache[key] = CacheEntry(
            tool_name=tool_name,
            args_hash=key.split(":")[1],
            result=result,
            timestamp=time.time(),
            ttl_seconds=ttl
        )
        
        self.stats.total_saved_seconds += execution_time
        self._dirty = True  # _save_cache mark; will flush on exit
        logger.debug(f"Cache SET: {tool_name} (TTL: {ttl}s)")
    
    def _evict_oldest(self):
        """Evict the oldest cache entries."""
        if not self.cache:
            return
        
        # Sort by timestamp, remove oldest 10%
        sorted_keys = sorted(self.cache.keys(), key=lambda k: self.cache[k].timestamp)
        to_remove = max(1, len(sorted_keys) // 10)
        
        for key in sorted_keys[:to_remove]:
            del self.cache[key]
            self.stats.evictions += 1
    
    def invalidate(self, tool_name: str = None, target: str = None):
        """
        Invalidate cache entries.
        
        Args:
            tool_name: Invalidate specific tool (optional)
            target: Invalidate entries for specific target (optional)
        """
        keys_to_remove = []
        
        for key, entry in self.cache.items():
            if tool_name and entry.tool_name == tool_name:
                keys_to_remove.append(key)
            elif target and target in entry.result:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.cache[key]

        self._dirty = True
        return len(keys_to_remove)
    
    def clear(self):
        """Clear all cache entries and immediately flush to disk."""
        count = len(self.cache)
        self.cache.clear()
        self.stats = CacheStats()
        self._dirty = True
        self._flush_if_dirty()  # Immediate flush: user expects clean state now
        return count
    
    def set_ttl(self, tool_name: str, ttl_seconds: int):
        """Set custom TTL for a tool."""
        self.custom_ttls[tool_name] = ttl_seconds
    
    def get_status(self) -> str:
        """Get formatted cache status."""
        total = self.stats.hits + self.stats.misses
        hit_rate = (self.stats.hits / total * 100) if total > 0 else 0
        
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            "║ 💾 TOOL CACHE STATUS",
            "╠══════════════════════════════════════════════════════════════",
            f"║ Entries:     {len(self.cache)} / {self.max_size}",
            f"║ Hit Rate:    {hit_rate:.1f}% ({self.stats.hits} hits, {self.stats.misses} misses)",
            f"║ Evictions:   {self.stats.evictions}",
            f"║ Time Saved:  {self.stats.total_saved_seconds:.1f}s",
            "╠══════════════════════════════════════════════════════════════",
            "║ Cached Tools:"
        ]
        
        # Group by tool
        tool_counts = {}
        for entry in self.cache.values():
            tool_counts[entry.tool_name] = tool_counts.get(entry.tool_name, 0) + 1
        
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1])[:10]:
            ttl = self._get_ttl(tool)
            lines.append(f"║   {tool}: {count} entries (TTL: {ttl}s)")
        
        lines.append("╚══════════════════════════════════════════════════════════════")
        
        return "\n".join(lines)


# Global instance
_tool_cache: Optional[ToolCache] = None


def get_tool_cache() -> ToolCache:
    """Get or create the global tool cache."""
    global _tool_cache
    if _tool_cache is None:
        _tool_cache = ToolCache()
    return _tool_cache


def cached_tool_execution(tool_name: str, args: dict, executor) -> Tuple[str, bool]:
    """Execute tool with caching (sync version)."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # This is tricky if we're already in an event loop.
            # But sync tools shouldn't be called from async contexts.
            import nest_asyncio
            nest_asyncio.apply()
    except RuntimeError:
        pass
    return asyncio.run(cached_tool_execution_async(tool_name, args, executor))


async def cached_tool_execution_async(tool_name: str, args: dict, executor) -> Tuple[str, bool]:
    """
    Execute tool with caching (async version).
    
    Args:
        tool_name: Name of the tool
        args: Tool arguments
        executor: Function to call if cache miss (can be sync or async)
    
    Returns:
        (result, was_cached)
    """
    import inspect
    import asyncio
    cache = get_tool_cache()
    
    # Check cache
    cached = cache.get(tool_name, args)
    if cached:
        result, age = cached
        return f"[CACHED {age:.0f}s ago]\n{result}", True
    
    # Execute tool
    start = time.time()
    
    # Handle both sync and async executors
    if inspect.iscoroutinefunction(executor):
        result = await executor()
    else:
        # Run sync tools off the event loop. This is especially important for
        # Playwright's sync API, which raises if called inside an asyncio loop.
        potential_res = await asyncio.to_thread(executor)
        if inspect.iscoroutine(potential_res):
            result = await potential_res
        else:
            result = potential_res
            
    elapsed = time.time() - start
    
    # Cache result
    cache.set(tool_name, args, result, elapsed)
    
    return result, False
