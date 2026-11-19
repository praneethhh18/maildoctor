from conftest import HEALTHY, ctx_for

from maildoctor.tools import run_tool

HEADERS = """Delivered-To: me@gmail.com
Received: by 2002:a05:6a10:1 with SMTP id x; Wed, 19 Nov 2026 10:30:10 +0000
Received: from mail.example.org (mail.example.org [1.2.3.4]) by mx.google.com with ESMTPS id y; Wed, 19 Nov 2026 10:29:59 +0000
Received: from app-server (unknown [10.0.0.2]) by mail.example.org with ESMTP id z; Wed, 19 Nov 2026 10:05:00 +0000
Authentication-Results: mx.google.com;
       dkim=pass header.i=@sendgrid.net header.s=s1;
       spf=softfail (google.com: domain of bounce@em.sendgrid.net) smtp.mailfrom=bounce@em.sendgrid.net;
       dmarc=fail (p=QUARANTINE) header.from=example.org
DKIM-Signature: v=1; a=rsa-sha256; d=sendgrid.net; s=s1; h=from:to; bh=abc; b=def
Return-Path: <bounce@em.sendgrid.net>
From: Shop <hello@example.org>
To: me@gmail.com
Subject: Your order
"""


def ids(r):
    return {f.id for f in r.findings}


def test_headers_alignment_and_delay():
    r = run_tool(ctx_for({}), "analyze_headers", {"raw_headers": HEADERS})
    assert r.data["verdicts"] == {"spf": "softfail", "dkim": "pass", "dmarc": "fail"}
    assert {"hdr.dmarc_fail", "hdr.dkim_unaligned", "hdr.spf_unaligned", "hdr.delay"} <= ids(r)
    assert r.data["dkim_signatures"][0] == {"d": "sendgrid.net", "s": "s1"}


def test_bounce_decoding():
    c = ctx_for({})
    cases = {
        "550 5.1.1 The email account that you tried to reach does not exist": "bounce.user_unknown",
        "552-5.2.2 The recipient's inbox is out of storage space": "bounce.mailbox_full",
        "550 5.7.26 Unauthenticated email from example.org is not accepted due to domain's DMARC policy": "bounce.dmarc",
        "554 5.7.1 Service unavailable; Client host [1.2.3.4] blocked using zen.spamhaus.org": "bounce.blocked",
        "535 5.7.8 Username and Password not accepted": "bounce.auth",
        "451 4.7.1 Greylisted, please try again later": "bounce.temporary",
    }
    for text, fid in cases.items():
        r = run_tool(c, "decode_bounce", {"text": text})
        assert fid in ids(r), (text, ids(r))


def test_client_settings_zoho_with_error():
    r = run_tool(ctx_for(HEALTHY), "email_client_settings",
                 {"email_or_domain": "me@good.in", "error_message": "Authentication failed for IMAP"})
    assert r.data["provider"] == "Zoho Mail"
    assert "imappro.zoho.in:993" in r.data["imap"]
    assert "client.error_explained" in ids(r)


def test_client_settings_forwarding_only():
    c = ctx_for({("f.com", "MX"): ["10 mx1.improvmx.com"], ("mx1.improvmx.com", "A"): ["1.1.1.1"]})
    assert "client.no_mailbox" in ids(run_tool(c, "email_client_settings", {"email_or_domain": "f.com"}))
