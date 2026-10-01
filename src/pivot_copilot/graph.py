"""
Network graph model.

Represents the state of an authorized lab engagement as discovered so far:
hosts, the services running on them, and credentials/access already
obtained. This is purely a data model fed by the user (e.g. exported from
recon tools in a lab) — this module does not perform any scanning,
exploitation, or network connections itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Service:
    name: str
    port: int
    version: Optional[str] = None
    vulnerable: bool = False
    notes: str = ""


@dataclass
class Credential:
    username: str
    cred_type: str  # "password", "hash", "ssh_key", "token"
    value_ref: str  # reference/label only, never store real secrets in sample data
    source_host: str
    privilege: str = "user"  # "user" or "admin"


@dataclass
class Host:
    hostname: str
    ip: str
    os: str
    compromised: bool = False
    services: list[Service] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # e.g. "domain-controller", "dmz"

    def has_service(self, name: str) -> bool:
        return any(s.name.lower() == name.lower() for s in self.services)


@dataclass
class NetworkGraph:
    hosts: dict[str, Host] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)  # (from_hostname, to_hostname) reachability

    def get_host(self, hostname: str) -> Host:
        return self.hosts[hostname]

    def compromised_hosts(self) -> list[Host]:
        return [h for h in self.hosts.values() if h.compromised]

    def uncompromised_reachable_hosts(self) -> list[Host]:
        """Hosts not yet compromised but reachable from a compromised host."""
        compromised_names = {h.hostname for h in self.compromised_hosts()}
        reachable = set()
        for src, dst in self.edges:
            if src in compromised_names and dst not in compromised_names:
                reachable.add(dst)
        return [self.hosts[name] for name in reachable if name in self.hosts]

    def credentials_for_host(self, hostname: str) -> list[Credential]:
        return [c for c in self.credentials if c.source_host == hostname]


def load_network_graph(path: str | Path) -> NetworkGraph:
    """Load a NetworkGraph from a JSON file describing engagement state."""
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

    hosts: dict[str, Host] = {}
    for h in data.get("hosts", []):
        services = [
            Service(
                name=s["name"],
                port=s["port"],
                version=s.get("version"),
                vulnerable=s.get("vulnerable", False),
                notes=s.get("notes", ""),
            )
            for s in h.get("services", [])
        ]
        hosts[h["hostname"]] = Host(
            hostname=h["hostname"],
            ip=h["ip"],
            os=h.get("os", "unknown"),
            compromised=h.get("compromised", False),
            services=services,
            tags=h.get("tags", []),
        )

    credentials = [
        Credential(
            username=c["username"],
            cred_type=c["cred_type"],
            value_ref=c.get("value_ref", "REDACTED"),
            source_host=c["source_host"],
            privilege=c.get("privilege", "user"),
        )
        for c in data.get("credentials", [])
    ]

    edges = [(e["from"], e["to"]) for e in data.get("edges", [])]

    return NetworkGraph(hosts=hosts, credentials=credentials, edges=edges)
