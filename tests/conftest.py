import pytest

from maildoctor.config import Settings
from maildoctor.dnsclient import FakeResolver
from maildoctor.tools import make_context

ZOHO_DKIM = ("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnfCjGEJWQ4Ow5OjNJA8aioTVoAa7NlUw8J0rmxcAbxD2rGdkr8rtvXTSgA/"
             "LsQ81wiZ8P0u3V1G03hrbRs4vXw0tPeZ7l8SLE6ZmpLov313uJxRpgt7G3Sd/hR3tr5NkQPQM3yRpGgv/Ld+2XAo0BbxUU32h294YTfcGEUuH65wIDAQAB")

HEALTHY = {
    ("good.in", "NS"): ["miki.ns.cloudflare.com", "santino.ns.cloudflare.com"],
    ("good.in", "SOA"): ["miki.ns.cloudflare.com. dns.cloudflare.com. 1 2 3 4 5"],
    ("good.in", "A"): ["35.171.173.49"],
    ("www.good.in", "CNAME"): ["good.in"],
    ("www.good.in", "A"): ["35.171.173.49"],
    ("good.in", "MX"): ["10 mx.zoho.in", "20 mx2.zoho.in", "50 mx3.zoho.in"],
    ("mx.zoho.in", "A"): ["204.141.33.44"], ("mx2.zoho.in", "A"): ["204.141.33.45"], ("mx3.zoho.in", "A"): ["204.141.33.46"],
    ("good.in", "TXT"): ["v=spf1 include:zohomail.in ~all", "zoho-verification=zb1.zmverify.zoho.in"],
    ("zohomail.in", "TXT"): ["v=spf1 ip4:204.141.32.0/23 ~all"],
    ("zmail._domainkey.good.in", "TXT"): [ZOHO_DKIM],
    ("_dmarc.good.in", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:dmarc@good.in"],
}

# Classic support case: moved mailboxes to Google, but DNS still has the old SPF, no DKIM, no DMARC
SWITCHED = {
    ("moved.com", "NS"): ["ns1.domaincontrol.com", "ns2.domaincontrol.com"],
    ("moved.com", "A"): ["198.185.159.144"],
    ("moved.com", "MX"): ["1 smtp.google.com"],
    ("smtp.google.com", "A"): ["142.250.1.27"],
    ("moved.com", "TXT"): ["v=spf1 include:secureserver.net ~all"],
    ("secureserver.net", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
}


@pytest.fixture
def settings():
    return Settings(llm_provider="offline", dns_mode="system", max_agent_steps=8)


@pytest.fixture
def healthy_ctx(settings):
    return make_context(FakeResolver(HEALTHY), settings, offline=True)


@pytest.fixture
def switched_ctx(settings):
    return make_context(FakeResolver(SWITCHED), settings, offline=True)


def ctx_for(data, settings=None):
    return make_context(FakeResolver(data), settings or Settings(llm_provider="offline"), offline=True)
