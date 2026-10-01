import json

from pivot_copilot.graph import Credential, Host, NetworkGraph, Service, load_network_graph


def test_host_has_service_case_insensitive():
    host = Host(hostname="h1", ip="10.0.0.1", os="Linux",
                services=[Service(name="SMB", port=445)])
    assert host.has_service("smb")
    assert not host.has_service("rdp")


def test_compromised_hosts_filters_correctly():
    graph = NetworkGraph(hosts={
        "a": Host(hostname="a", ip="1.1.1.1", os="Linux", compromised=True),
        "b": Host(hostname="b", ip="1.1.1.2", os="Linux", compromised=False),
    })
    compromised = graph.compromised_hosts()
    assert len(compromised) == 1
    assert compromised[0].hostname == "a"


def test_uncompromised_reachable_hosts_follows_edges():
    graph = NetworkGraph(
        hosts={
            "a": Host(hostname="a", ip="1.1.1.1", os="Linux", compromised=True),
            "b": Host(hostname="b", ip="1.1.1.2", os="Linux", compromised=False),
            "c": Host(hostname="c", ip="1.1.1.3", os="Linux", compromised=False),
        },
        edges=[("a", "b")],
    )
    reachable = graph.uncompromised_reachable_hosts()
    assert [h.hostname for h in reachable] == ["b"]


def test_credentials_for_host_filters_by_source():
    graph = NetworkGraph(
        credentials=[
            Credential(username="u1", cred_type="password", value_ref="x", source_host="a"),
            Credential(username="u2", cred_type="hash", value_ref="y", source_host="b"),
        ]
    )
    assert len(graph.credentials_for_host("a")) == 1
    assert graph.credentials_for_host("a")[0].username == "u1"


def test_load_network_graph_from_sample_data():
    graph = load_network_graph("sample_data/engagement.json")
    assert "dc-01" in graph.hosts
    assert graph.hosts["dc-01"].tags == ["internal", "domain-controller"]
    assert len(graph.credentials) == 2
    assert ("ext-web-01", "fileserver-01") in graph.edges


def test_load_network_graph_from_minimal_json(tmp_path):
    data = {
        "hosts": [
            {"hostname": "h1", "ip": "10.0.0.1", "os": "Linux", "compromised": True, "services": []}
        ]
    }
    path = tmp_path / "min.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    graph = load_network_graph(path)
    assert graph.hosts["h1"].compromised is True
    assert graph.credentials == []
    assert graph.edges == []
