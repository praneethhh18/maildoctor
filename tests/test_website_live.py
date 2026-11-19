"""check_website with fake HTTP (httpx.MockTransport) instead of the internet."""

import httpx
import pytest
from conftest import ctx_for

import maildoctor.tools.web_domain as wd
from maildoctor.tools import run_tool

DNS = {("site.com", "A"): ["35.171.173.49"], ("www.site.com", "CNAME"): ["site.com"], ("www.site.com", "A"): ["35.171.173.49"]}


def _ctx(handler, monkeypatch, cert=None):
    c = ctx_for(DNS)
    c.offline = False
    c.http = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    monkeypatch.setattr(wd, "_cert_info", lambda host, timeout: cert or {"valid": True, "days_left": 60, "issuer": "Let's Encrypt"})
    return c


def ids(r):
    return {f.id for f in r.findings}


def test_both_schemes_down_is_unreachable(monkeypatch):
    def handler(req):
        raise httpx.ConnectTimeout("timed out", request=req)
    r = run_tool(_ctx(handler, monkeypatch), "check_website", {"domain": "site.com"})
    assert "web.unreachable" in ids(r) and "web.https_unreachable" not in ids(r)
    assert "35.171.173.49" in next(f.title for f in r.findings if f.id == "web.unreachable")
    assert r.data["ssl"] == {"skipped": "port 443 not reachable"}   # no pointless SSL check


def test_https_down_http_up(monkeypatch):
    def handler(req):
        if req.url.scheme == "https":
            raise httpx.ConnectError("connection refused", request=req)
        return httpx.Response(200, text="hi")
    r = run_tool(_ctx(handler, monkeypatch), "check_website", {"domain": "site.com"})
    assert "web.https_unreachable" in ids(r) and "web.unreachable" not in ids(r)


def test_healthy_site_with_redirect(monkeypatch):
    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://site.com/"})
        return httpx.Response(200, text="ok")
    r = run_tool(_ctx(handler, monkeypatch), "check_website", {"domain": "site.com"})
    assert {"web.https_ok", "ssl.ok"} <= ids(r)
    assert "web.no_https_redirect" not in ids(r)


@pytest.mark.parametrize("status,fid", [(502, "web.server_error"), (403, "web.forbidden"), (404, "web.not_found")])
def test_error_statuses(monkeypatch, status, fid):
    r = run_tool(_ctx(lambda req: httpx.Response(status), monkeypatch), "check_website", {"domain": "site.com"})
    assert fid in ids(r)


def test_invalid_cert(monkeypatch):
    r = run_tool(_ctx(lambda req: httpx.Response(200), monkeypatch, cert={"valid": False, "error": "hostname mismatch"}),
                 "check_website", {"domain": "site.com"})
    assert "ssl.invalid" in ids(r)
