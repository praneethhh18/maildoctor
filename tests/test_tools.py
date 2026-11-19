from conftest import HEALTHY, ctx_for

from maildoctor.tools import run_tool


def ids(res):
    return {f.id for f in res.findings}


def test_healthy_domain_passes_core_checks(healthy_ctx):
    assert "mx.ok" in ids(run_tool(healthy_ctx, "check_mx", {"domain": "good.in"}))
    spf = run_tool(healthy_ctx, "check_spf", {"domain": "good.in"})
    assert "spf.ok" in ids(spf), spf.findings
    dkim = run_tool(healthy_ctx, "check_dkim", {"domain": "good.in"})
    assert "dkim.ok" in ids(dkim)
    assert dkim.data["selectors_found"]["zmail"]["bits"] == 1024
    assert "dmarc.ok" in ids(run_tool(healthy_ctx, "check_dmarc", {"domain": "good.in"}))


def test_overview_detects_providers(healthy_ctx):
    r = run_tool(healthy_ctx, "dns_overview", {"domain": "https://www.good.in/page"})
    assert r.target == "good.in"
    assert r.data["dns_provider"] == "Cloudflare"
    assert r.data["email_provider"] == "Zoho Mail"


def test_switched_provider_flags_spf_and_dkim(switched_ctx):
    spf = run_tool(switched_ctx, "check_spf", {"domain": "moved.com"})
    assert "spf.provider_missing" in ids(spf)
    dkim = run_tool(switched_ctx, "check_dkim", {"domain": "moved.com"})
    assert "dkim.provider_missing" in ids(dkim)
    assert "dmarc.missing" in ids(run_tool(switched_ctx, "check_dmarc", {"domain": "moved.com"}))


def test_multiple_spf_records_and_mixed_mx():
    c = ctx_for({("x.com", "MX"): ["10 mx.zoho.in", "20 mx1.improvmx.com"],
                 ("mx.zoho.in", "A"): ["1.1.1.1"], ("mx1.improvmx.com", "A"): ["2.2.2.2"],
                 ("x.com", "TXT"): ["v=spf1 include:zoho.in ~all", "v=spf1 include:spf.improvmx.com ~all"],
                 ("zoho.in", "TXT"): ["v=spf1 ip4:1.1.1.1 ~all"], ("spf.improvmx.com", "TXT"): ["v=spf1 ip4:2.2.2.2 ~all"]})
    assert "spf.multiple" in ids(run_tool(c, "check_spf", {"domain": "x.com"}))
    assert "mx.mixed_providers" in ids(run_tool(c, "check_mx", {"domain": "x.com"}))


def test_spf_lookup_limit():
    data = {("big.com", "TXT"): ["v=spf1 " + " ".join(f"include:s{i}.net" for i in range(6)) + " ~all"]}
    for i in range(6):
        data[(f"s{i}.net", "TXT")] = [f"v=spf1 include:t{i}.net ~all"]
        data[(f"t{i}.net", "TXT")] = ["v=spf1 ip4:1.2.3.4 ~all"]
    r = run_tool(ctx_for(data), "check_spf", {"domain": "big.com"})
    assert r.data["dns_lookups"] == 12
    assert "spf.too_many_lookups" in ids(r)


def test_spf_plus_all_and_syntax():
    r = run_tool(ctx_for({("a.com", "TXT"): ["v=spf1 incude:foo.com +all"]}), "check_spf", {"domain": "a.com"})
    assert {"spf.pass_all", "spf.syntax"} <= ids(r)


def test_mx_missing_and_lookup_error_is_unknown():
    c = ctx_for({("nomail.com", "A"): ["1.2.3.4"], ("err.com", "MX"): "error"})
    assert "mx.missing" in ids(run_tool(c, "check_mx", {"domain": "nomail.com"}))
    assert "mx.lookup_error" in ids(run_tool(c, "check_mx", {"domain": "err.com"}))  # never 'missing' on error


def test_nxdomain_overview():
    r = run_tool(ctx_for({}), "dns_overview", {"domain": "gone.com"})
    assert "domain.nxdomain" in ids(r)


def test_dkim_malformed_and_custom_selector():
    c = ctx_for({("d.com", "MX"): ["1 smtp.google.com"], ("smtp.google.com", "A"): ["1.1.1.1"],
                 ("google._domainkey.d.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGf\"MA0 broken!!"],
                 ("custom._domainkey.d.com", "TXT"): ["v=DKIM1; p="]})
    r = run_tool(c, "check_dkim", {"domain": "d.com", "selectors": ["custom"]})
    assert {"dkim.malformed", "dkim.revoked"} <= ids(r)


def test_dmarc_subdomain_falls_back_to_org():
    c = ctx_for({("_dmarc.shop.co.in", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@shop.co.in"]})
    r = run_tool(c, "check_dmarc", {"domain": "mail.shop.co.in"})
    assert r.data["policy_source"] == "shop.co.in"
    assert "dmarc.ok" in ids(r)


def test_blacklist_listing_and_refused_query():
    c = ctx_for({("bad.com", "MX"): ["10 mx.bad.com"], ("mx.bad.com", "A"): ["9.8.7.6"],
                 ("6.7.8.9.zen.spamhaus.org", "A"): ["127.0.0.2"],
                 ("6.7.8.9.b.barracudacentral.org", "A"): ["127.255.255.254"]})
    r = run_tool(c, "check_blacklists", {"domain": "bad.com"})
    assert "bl.listed" in ids(r) and "bl.inconclusive" in ids(r)
    assert r.data["listed"][0]["list"] == "zen.spamhaus.org"


def test_website_dns_findings_offline():
    c = ctx_for({("site.com", "NS"): ["ns1.x.com"], ("www.site.com", "A"): ["10.0.0.5"]})
    r = run_tool(c, "check_website", {"domain": "site.com"})
    assert {"web.apex_no_address", "web.private_ip", "web.http_skipped"} <= ids(r)


def test_unknown_tool_and_bad_args(healthy_ctx):
    assert run_tool(healthy_ctx, "nope", {}).error
    assert "bad arguments" in run_tool(healthy_ctx, "check_mx", {"domian": "x"}).error
