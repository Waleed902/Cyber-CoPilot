"""
Asset Correlation System

Correlates discovered assets (domains, IPs, ports, services, technologies)
to build a complete attack surface map and prioritize high-value targets.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class Asset:
    """Represents a discovered asset"""
    asset_type: str  # subdomain, ip, port, service, technology, vulnerability
    value: str
    source: str  # Tool that discovered it
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)
    priority: int = 0  # 0-100, higher = more important
    

@dataclass
class AssetRelationship:
    """Relationship between two assets"""
    from_asset: Asset
    to_asset: Asset
    relationship_type: str  # resolves_to, runs_on, uses, exposes, vulnerable_to
    

class AssetCorrelator:
    """
    Correlates discovered assets to build attack surface map.
    
    Correlation Examples:
    - example.com → 192.168.1.1 (resolves_to)
    - 192.168.1.1:443 → nginx 1.18 (runs_on)
    - nginx 1.18 → CVE-2021-23017 (vulnerable_to)
    - admin.example.com → High Priority (exposes)
    """
    
    def __init__(self):
        self.assets: List[Asset] = []
        self.relationships: List[AssetRelationship] = []
        self._domain_to_ip: Dict[str, str] = {}
        self._ip_to_ports: Dict[str, List[int]] = {}
        self._port_to_service: Dict[tuple, str] = {}  # (ip, port) -> service
        self._service_to_tech: Dict[str, str] = {}  # service -> technology/version
        
    def add_subdomain(self, subdomain: str, source: str = "subfinder") -> Asset:
        """Add discovered subdomain"""
        asset = Asset(
            asset_type="subdomain",
            value=subdomain,
            source=source,
            priority=self._calculate_subdomain_priority(subdomain)
        )
        self.assets.append(asset)
        return asset
    
    def add_ip_resolution(self, subdomain: str, ip: str) -> Asset:
        """Add domain-to-IP resolution"""
        self._domain_to_ip[subdomain] = ip
        
        ip_asset = Asset(
            asset_type="ip",
            value=ip,
            source="dns",
            priority=50
        )
        self.assets.append(ip_asset)
        
        # Create relationship
        subdomain_asset = self._find_asset("subdomain", subdomain)
        if subdomain_asset:
            relationship = AssetRelationship(
                from_asset=subdomain_asset,
                to_asset=ip_asset,
                relationship_type="resolves_to"
            )
            self.relationships.append(relationship)
        
        return ip_asset
    
    def add_open_port(self, ip: str, port: int, service: str = "", version: str = "") -> Asset:
        """Add open port discovery"""
        if ip not in self._ip_to_ports:
            self._ip_to_ports[ip] = []
        self._ip_to_ports[ip].append(port)
        
        port_asset = Asset(
            asset_type="port",
            value=f"{ip}:{port}",
            source="nmap",
            metadata={"service": service, "version": version},
            priority=self._calculate_port_priority(port, service)
        )
        self.assets.append(port_asset)
        
        if service:
            self._port_to_service[(ip, port)] = service
        
        return port_asset
    
    def add_technology(self, target: str, technology: str, version: str = "", source: str = "whatweb") -> Asset:
        """Add technology detection"""
        tech_string = f"{technology} {version}".strip()
        
        tech_asset = Asset(
            asset_type="technology",
            value=tech_string,
            source=source,
            metadata={"technology": technology, "version": version, "target": target},
            priority=self._calculate_tech_priority(technology, version)
        )
        self.assets.append(tech_asset)
        self._service_to_tech[target] = tech_string
        
        return tech_asset
    
    def add_vulnerability(self, target: str, vuln_type: str, severity: str, confidence: int = 0) -> Asset:
        """Add discovered vulnerability"""
        vuln_asset = Asset(
            asset_type="vulnerability",
            value=vuln_type,
            source="scanner",
            metadata={"severity": severity, "confidence": confidence, "target": target},
            priority=self._calculate_vuln_priority(severity, confidence)
        )
        self.assets.append(vuln_asset)
        
        return vuln_asset
    
    def _calculate_subdomain_priority(self, subdomain: str) -> int:
        """Calculate priority for a subdomain (0-100)"""
        priority = 30  # Base priority
        
        subdomain_lower = subdomain.lower()
        
        # High-value prefixes
        high_value = ["admin", "api", "dev", "staging", "test", "internal", "vpn", "portal"]
        for keyword in high_value:
            if keyword in subdomain_lower:
                priority += 40
                break
        
        # Medium-value prefixes
        medium_value = ["mail", "ftp", "ssh", "dashboard", "panel", "manage"]
        for keyword in medium_value:
            if keyword in subdomain_lower:
                priority += 25
                break
        
        # Penalize common low-value
        low_value = ["www", "blog", "cdn", "static", "images"]
        for keyword in low_value:
            if subdomain_lower.startswith(keyword):
                priority -= 10
                break
        
        return min(100, max(0, priority))
    
    def _calculate_port_priority(self, port: int, service: str = "") -> int:
        """Calculate priority for an open port"""
        priority = 40  # Base priority
        
        # Critical ports
        critical_ports = {
            22: 30,    # SSH
            23: 35,    # Telnet (very high priority - insecure)
            445: 35,   # SMB
            3389: 35,  # RDP
            5432: 30,  # PostgreSQL
            3306: 30,  # MySQL
            27017: 30, # MongoDB
            6379: 30,  # Redis
            9200: 35,  # Elasticsearch
        }
        
        if port in critical_ports:
            priority += critical_ports[port]
        
        # Web ports (medium priority)
        if port in [80, 443, 8080, 8443, 8000, 8888]:
            priority += 20
        
        # Service-based priority
        if service:
            service_lower = service.lower()
            if "admin" in service_lower or "management" in service_lower:
                priority += 25
            if "outdated" in service_lower or "vulnerable" in service_lower:
                priority += 30
        
        return min(100, max(0, priority))
    
    def _calculate_tech_priority(self, technology: str, version: str) -> int:
        """Calculate priority based on technology"""
        priority = 35  # Base
        
        tech_lower = technology.lower()
        
        # High-value technologies
        databases = ["mysql", "postgres", "mongodb", "redis", "elasticsearch"]
        frameworks = ["laravel", "django", "spring", "rails"]
        cms = ["wordpress", "drupal", "joomla"]
        
        if any(db in tech_lower for db in databases):
            priority += 30
        elif any(fw in tech_lower for fw in frameworks):
            priority += 25
        elif any(c in tech_lower for c in cms):
            priority += 20
        
        # Version-based priority (outdated = higher priority)
        if version:
            # Simple heuristic: older versions have higher numbers
            version_match = re.match(r'(\d+)', version)
            if version_match:
                major_version = int(version_match.group(1))
                if major_version < 5:  # Likely outdated
                    priority += 20
        
        return min(100, max(0, priority))
    
    def _calculate_vuln_priority(self, severity: str, confidence: int) -> int:
        """Calculate priority for vulnerabilities"""
        priority_map = {
            "critical": 90,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        
        priority = priority_map.get(severity.lower(), 40)
        
        # Boost priority if high confidence
        if confidence >= 90:  # CONFIRMED
            priority = min(100, priority + 10)
        elif confidence < 50:  # LOW confidence
            priority = max(0, priority - 20)
        
        return priority
    
    def get_high_priority_targets(self, min_priority: int = 70) -> List[Asset]:
        """Get assets with priority >= min_priority"""
        return sorted(
            [a for a in self.assets if a.priority >= min_priority],
            key=lambda x: x.priority,
            reverse=True
        )
    
    def get_attack_surface_summary(self) -> str:
        """Generate attack surface summary"""
        lines = ["## 🎯 ATTACK SURFACE MAP\n"]
        
        # Count by type
        counts = {}
        for asset in self.assets:
            counts[asset.asset_type] = counts.get(asset.asset_type, 0) + 1
        
        lines.append("### Asset Inventory")
        for asset_type, count in sorted(counts.items()):
            lines.append(f"- {asset_type.title()}: {count}")
        
        # High-priority targets
        high_pri = self.get_high_priority_targets()
        if high_pri:
            lines.append(f"\n### 🔴 High-Priority Targets ({len(high_pri)})")
            for asset in high_pri[:10]:  # Top 10
                lines.append(f"- [{asset.priority}] {asset.asset_type}: {asset.value}")
                if asset.metadata:
                    meta_str = ", ".join([f"{k}={v}" for k, v in asset.metadata.items() if v])
                    if meta_str:
                        lines.append(f"  ({meta_str})")
        
        # Correlations
        lines.append(f"\n### 🔗 Correlations: {len(self.relationships)}")
        
        return "\n".join(lines)
    
    def get_attack_path(self, target_type: str = "vulnerability") -> List[List[Asset]]:
        """
        Find attack paths to a target type.
        
        Returns:
            List of attack chains (each chain is a list of assets)
        """
        paths = []
        
        # Find target assets
        targets = [a for a in self.assets if a.asset_type == target_type]
        
        for target in targets:
            # Build backward path to entry point
            path = [target]
            current = target
            
            # Follow relationships backward
            max_depth = 10
            while len(path) < max_depth:
                # Find asset that relates to current
                found = False
                for rel in self.relationships:
                    if rel.to_asset == current:
                        path.insert(0, rel.from_asset)
                        current = rel.from_asset
                        found = True
                        break
                
                if not found:
                    break
            
            if len(path) > 1:
                paths.append(path)
        
        return paths
    
    def _find_asset(self, asset_type: str, value: str) -> Optional[Asset]:
        """Find asset by type and value"""
        for asset in self.assets:
            if asset.asset_type == asset_type and asset.value == value:
                return asset
        return None


# Global correlator instance
_correlator: Optional[AssetCorrelator] = None


def get_correlator() -> AssetCorrelator:
    """Get or create global asset correlator"""
    global _correlator
    if _correlator is None:
        _correlator = AssetCorrelator()
    return _correlator


def reset_correlator():
    """Reset the global correlator"""
    global _correlator
    _correlator = AssetCorrelator()
