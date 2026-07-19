"""Dashboard route and asset tests (no DB required)."""
import os


def test_dashboard_asset_exists_and_calls_real_endpoints():
    from avp_server import main

    assert os.path.isfile(main._DASHBOARD_PATH)
    with open(main._DASHBOARD_PATH, encoding="utf-8") as f:
        html = f.read()

    # The console must target endpoints that actually exist
    for path in ["/sessions", "/audit", "/secrets", "/agents", "/tokens",
                 "/secrets/versions", "/secrets/rollback", "/healthz"]:
        assert path in html, f"dashboard does not reference {path}"

    # Self-contained: a secrets console must not call out to CDNs
    assert "http://" not in html.replace("http://localhost", "")
    assert "https://" not in html


def test_dashboard_route_serves_html():
    from avp_server import main

    resp = main.dashboard()
    assert resp.status_code == 200
    assert b"Vault Console" in resp.body or b"vault console" in resp.body


def test_dashboard_route_registered():
    from avp_server.main import app

    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/dashboard" in paths
