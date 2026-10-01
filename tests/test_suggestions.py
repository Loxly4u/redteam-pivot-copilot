from pivot_copilot.graph import Credential, Host, NetworkGraph, Service
from pivot_copilot.suggestions import generate_suggestions


def test_no_suggestions_when_no_hosts():
    graph = NetworkGraph()
    assert generate_suggestions(graph) == []


def test_vulnerable_service_generates_exploitation_suggestion():
    graph = NetworkGraph(hosts={
        "target": Host(
            hostname="target", ip="10.0.0.2", os="Windows",
            services=[Service(name="smb", port=445, vulnerable=True, notes="SMBv1")],
        )
    })
    suggestions = generate_suggestions(graph)
    assert any(s.technique_id == "T1210" for s in suggestions)
    assert all(s.target_host == "target" for s in suggestions if s.technique_id == "T1210")


def test_non_vulnerable_service_does_not_trigger_exploitation_suggestion():
    graph = NetworkGraph(hosts={
        "target": Host(
            hostname="target", ip="10.0.0.2", os="Windows",
            services=[Service(name="smb", port=445, vulnerable=False)],
        )
    })
    suggestions = generate_suggestions(graph)
    assert not any(s.technique_id == "T1210" for s in suggestions)


def test_credential_reuse_suggestion_for_rdp():
    graph = NetworkGraph(
        hosts={
            "a": Host(hostname="a", ip="1.1.1.1", os="Linux", compromised=True),
            "b": Host(hostname="b", ip="1.1.1.2", os="Windows",
                       services=[Service(name="rdp", port=3389)]),
        },
        credentials=[Credential(username="jdoe", cred_type="password", value_ref="x",
                                 source_host="a", privilege="admin")],
        edges=[("a", "b")],
    )
    suggestions = generate_suggestions(graph)
    rdp_suggestions = [s for s in suggestions if s.technique_id == "T1021.001"]
    assert len(rdp_suggestions) == 1
    assert rdp_suggestions[0].requires_credential is True
    assert rdp_suggestions[0].risk == "high"  # admin cred -> high risk


def test_domain_controller_tag_generates_discovery_suggestion():
    graph = NetworkGraph(hosts={
        "dc": Host(hostname="dc", ip="10.0.0.5", os="Windows", tags=["domain-controller"]),
    })
    suggestions = generate_suggestions(graph)
    assert any(s.technique_id == "T1018" for s in suggestions)


def test_compromised_hosts_are_excluded_from_suggestions():
    graph = NetworkGraph(hosts={
        "a": Host(hostname="a", ip="1.1.1.1", os="Linux", compromised=True,
                   services=[Service(name="smb", port=445, vulnerable=True)]),
    })
    # 'a' is already compromised and has no edges to anything else, and with
    # edges=[] fallback logic only applies to *uncompromised* hosts.
    suggestions = generate_suggestions(graph)
    assert suggestions == []


def test_suggestions_sorted_by_risk_descending():
    graph = NetworkGraph(hosts={
        "low_target": Host(hostname="low_target", ip="1.1.1.1", os="Linux", tags=["domain-controller"]),
        "high_target": Host(
            hostname="high_target", ip="1.1.1.2", os="Linux",
            services=[Service(name="smb", port=445, vulnerable=True)],
        ),
    })
    suggestions = generate_suggestions(graph)
    risks = [s.risk for s in suggestions]
    assert risks.index("high") < risks.index("low")


def test_flat_network_with_no_edges_considers_all_uncompromised_hosts():
    graph = NetworkGraph(hosts={
        "a": Host(hostname="a", ip="1.1.1.1", os="Linux",
                   services=[Service(name="smb", port=445, vulnerable=True)]),
        "b": Host(hostname="b", ip="1.1.1.2", os="Linux", compromised=True),
    })
    suggestions = generate_suggestions(graph)
    assert any(s.target_host == "a" for s in suggestions)
