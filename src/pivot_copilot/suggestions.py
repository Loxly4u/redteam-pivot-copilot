"""
Suggestion engine.

Analyzes the current NetworkGraph state and proposes possible next steps
for a human red team operator to consider, each mapped to a MITRE ATT&CK
technique ID. This module ONLY reasons over data already provided — it
never scans, connects to, or executes anything against any host.

Every suggestion is advisory and must be explicitly approved by a human
before being considered "actioned" (see engagement_log.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pivot_copilot.graph import Credential, Host, NetworkGraph

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Suggestion:
    suggestion_id: str
    technique_id: str  # MITRE ATT&CK technique ID, e.g. "T1021.001"
    technique_name: str
    target_host: str
    rationale: str
    risk: str  # "low", "medium", "high" — risk/noise of the action, not severity
    requires_credential: bool = False


def _suggest_for_vulnerable_services(host: Host) -> list[Suggestion]:
    suggestions = []
    for svc in host.services:
        if svc.vulnerable:
            suggestions.append(
                Suggestion(
                    suggestion_id=f"{host.hostname}-exploit-{svc.name}-{svc.port}",
                    technique_id="T1210",
                    technique_name="Exploitation of Remote Services",
                    target_host=host.hostname,
                    rationale=(
                        f"Service '{svc.name}' on port {svc.port} "
                        f"(version: {svc.version or 'unknown'}) is flagged vulnerable. "
                        f"Notes: {svc.notes or 'none'}."
                    ),
                    risk="high",
                )
            )
    return suggestions


def _suggest_credential_reuse(host: Host, credentials: list[Credential]) -> list[Suggestion]:
    suggestions = []
    for cred in credentials:
        if host.has_service("smb") or host.has_service("rdp") or host.has_service("ssh"):
            protocol = "SMB" if host.has_service("smb") else ("RDP" if host.has_service("rdp") else "SSH")
            technique = {
                "SMB": ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
                "RDP": ("T1021.001", "Remote Services: Remote Desktop Protocol"),
                "SSH": ("T1021.004", "Remote Services: SSH"),
            }[protocol]
            suggestions.append(
                Suggestion(
                    suggestion_id=f"{host.hostname}-creduse-{cred.username}-{protocol.lower()}",
                    technique_id=technique[0],
                    technique_name=technique[1],
                    target_host=host.hostname,
                    rationale=(
                        f"Credential for user '{cred.username}' ({cred.privilege}) obtained from "
                        f"'{cred.source_host}' could be reused against {protocol} on this host."
                    ),
                    risk="medium" if cred.privilege == "user" else "high",
                    requires_credential=True,
                )
            )
    return suggestions


def _suggest_domain_controller_priority(host: Host) -> list[Suggestion]:
    if "domain-controller" in host.tags:
        return [
            Suggestion(
                suggestion_id=f"{host.hostname}-dc-priority",
                technique_id="T1018",
                technique_name="Remote System Discovery",
                target_host=host.hostname,
                rationale=(
                    "This host is tagged as a domain controller. High-value target for "
                    "further enumeration (e.g. domain trusts, group policy) before any "
                    "credential or exploitation attempts."
                ),
                risk="low",
            )
        ]
    return []


def generate_suggestions(graph: NetworkGraph) -> list[Suggestion]:
    """
    Generate a prioritized list of advisory next-step suggestions based on
    the current engagement state.

    Only considers hosts that are reachable from already-compromised hosts
    (or have no edges defined at all, e.g. a flat single-segment lab),
    reflecting realistic lateral movement constraints.
    """
    suggestions: list[Suggestion] = []

    reachable = graph.uncompromised_reachable_hosts()
    # If no edges were defined at all, fall back to considering every
    # uncompromised host (e.g. a simple flat lab network with no explicit
    # reachability graph).
    if not graph.edges:
        reachable = [h for h in graph.hosts.values() if not h.compromised]

    all_credentials = graph.credentials

    for host in reachable:
        suggestions.extend(_suggest_for_vulnerable_services(host))
        suggestions.extend(_suggest_credential_reuse(host, all_credentials))
        suggestions.extend(_suggest_domain_controller_priority(host))

    suggestions.sort(key=lambda s: _RISK_ORDER.get(s.risk, 0), reverse=True)
    return suggestions
