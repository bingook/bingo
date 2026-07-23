from bingo.core.intelligence import TaskGraph


def test_exhausted_recon_still_unlocks_crawl_frontier() -> None:
    graph = TaskGraph()
    graph.load_template("https://example.test sql injection admin webshell")

    ready = [node.node_id for node in graph.ready_nodes()]
    assert ready == ["recon"]

    graph.reconcile("recon", changed=False, summary="tech detected; no finding yet")

    ready = [node.node_id for node in graph.ready_nodes()]
    assert "crawl" in ready
    assert "sqli" not in ready


def test_downstream_attack_frontier_opens_after_low_signal_crawl() -> None:
    graph = TaskGraph()
    graph.load_template("https://example.test sql injection admin webshell")
    graph.reconcile("recon", changed=False, summary="headers only")
    graph.reconcile("crawl", changed=False, summary="homepage only")

    ready = {node.node_id for node in graph.ready_nodes()}

    assert {"sqli", "xss", "ssrf", "auth"}.issubset(ready)
    assert "exploit" not in ready


def test_exploit_frontier_opens_after_sqli_and_auth_attempts_even_without_findings() -> None:
    graph = TaskGraph()
    graph.load_template("https://example.test sql injection admin webshell")
    for node_id in ("recon", "crawl", "sqli", "auth"):
        graph.reconcile(node_id, changed=False, summary=f"{node_id} attempted")

    ready = {node.node_id for node in graph.ready_nodes()}

    assert "exploit" in ready
