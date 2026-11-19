"""Knowledge base: recognise providers from DNS fingerprints.

Support agents do this in their heads ("MX ends in google.com, so it's Google
Workspace"). Encoding it as data lets tools reason the same way.
"""

from __future__ import annotations

# --- Email providers, matched against MX hostnames --------------------------
EMAIL_PROVIDERS = [
    # key, display name, MX substrings, SPF include, DKIM selectors to probe
    ("google", "Google Workspace", ["google.com", "googlemail.com"], "_spf.google.com", ["google", "google2"]),
    ("microsoft", "Microsoft 365", ["mail.protection.outlook.com", "outlook.com"], "spf.protection.outlook.com", ["selector1", "selector2"]),
    ("zoho", "Zoho Mail", ["zoho.com", "zoho.in", "zoho.eu", "zohomail"], "zoho.in", ["zmail", "zoho", "default"]),
    ("titan", "Titan Mail", ["titan.email"], "spf.titan.email", ["titan1", "titan"]),
    ("godaddy", "GoDaddy / Secureserver", ["secureserver.net"], "secureserver.net", ["default"]),
    ("netsol", "Network Solutions (Web.com)", ["netsolmail.net", "netsolhost.com", "networksolutions"], "netsolmail.net", ["default"]),
    ("hostinger", "Hostinger Mail", ["hostinger.com", "hostinger.in"], "_spf.mail.hostinger.com", ["hostingermail1", "hostingermail2", "default"]),
    ("protonmail", "Proton Mail", ["protonmail.ch"], "_spf.protonmail.ch", ["protonmail", "protonmail2", "protonmail3"]),
    ("fastmail", "Fastmail", ["messagingengine.com"], "spf.messagingengine.com", ["fm1", "fm2", "fm3"]),
    ("yahoo", "Yahoo Mail", ["yahoodns.net"], "_spf.mail.yahoo.com", ["s1024", "s2048"]),
    ("improvmx", "ImprovMX (forwarding only)", ["improvmx.com"], "spf.improvmx.com", []),
    ("cloudflare_routing", "Cloudflare Email Routing (forwarding only)", ["mx.cloudflare.net"], "_spf.mx.cloudflare.net", []),
    ("mxroute", "MXroute", ["mxrouting.net", "mxlogin.com"], "mxroute.com", ["x"]),
    ("purelymail", "Purelymail", ["purelymail.com"], "_spf.purelymail.com", ["purelymail1", "purelymail2", "purelymail3"]),
    ("amazon_workmail", "Amazon WorkMail", ["awsapps.com"], "amazonses.com", []),
]

# Common DKIM selectors used by sending services (marketing / transactional)
SENDER_SELECTORS = [
    "default", "dkim", "mail", "smtp", "k1", "k2", "k3",          # generic, Mailchimp k1
    "s1", "s2",                                                  # SendGrid
    "resend", "mandrill", "mte1", "mailjet", "brevo", "mail2",
    "sib",                                                       # Brevo/Sendinblue legacy
    "pm",                                                        # Postmark (pm._domainkey or date-based)
    "everlytickey1", "cm", "scph0123",
]

# --- DNS hosting, matched against NS hostnames -----------------------------
DNS_PROVIDERS = [
    ("cloudflare", "Cloudflare", ["ns.cloudflare.com"]),
    ("route53", "AWS Route 53", ["awsdns"]),
    ("godaddy", "GoDaddy", ["domaincontrol.com"]),
    ("hostinger", "Hostinger", ["dns-parking.com", "hostinger"]),
    ("netsol", "Network Solutions", ["worldnic.com"]),
    ("namecheap", "Namecheap", ["registrar-servers.com"]),
    ("google", "Google Cloud DNS / Squarespace", ["googledomains.com", "google.com", "squarespacedns"]),
    ("digitalocean", "DigitalOcean", ["digitalocean.com"]),
    ("vercel", "Vercel", ["vercel-dns.com"]),
    ("bigrock", "BigRock / ResellerClub", ["bigrock", "dnspark", "resellerclub"]),
    ("azure", "Azure DNS", ["azure-dns"]),
    ("wix", "Wix", ["wixdns.net"]),
    ("ionos", "IONOS", ["ui-dns"]),
    ("zoho", "Zoho DNS", ["zohodns"]),
]

# --- Website hosting, matched against CNAME / A ------------------------------
HOSTING_CNAME = [
    ("vercel", "Vercel", ["vercel-dns", "vercel.app"]),
    ("netlify", "Netlify", ["netlify"]),
    ("github", "GitHub Pages", ["github.io"]),
    ("shopify", "Shopify", ["myshopify.com", "shops.myshopify"]),
    ("wix", "Wix", ["wixdns", "wix.com"]),
    ("squarespace", "Squarespace", ["squarespace"]),
    ("cloudfront", "AWS CloudFront", ["cloudfront.net"]),
    ("herokudns", "Heroku", ["herokudns.com", "herokuapp.com"]),
    ("render", "Render", ["onrender.com"]),
    ("azure", "Azure", ["azurewebsites.net", "cloudapp"]),
    ("webflow", "Webflow", ["webflow"]),
]

# Known A-record IPs for site builders (partial; used only as hints)
HOSTING_IPS = {
    "76.76.21.21": "Vercel",
    "75.2.60.5": "Netlify",
    "185.199.108.153": "GitHub Pages", "185.199.109.153": "GitHub Pages",
    "185.199.110.153": "GitHub Pages", "185.199.111.153": "GitHub Pages",
    "198.185.159.144": "Squarespace", "198.185.159.145": "Squarespace",
    "23.227.38.65": "Shopify",
}

# --- Email client settings (IMAP / SMTP) ------------------------------------
CLIENT_SETTINGS = {
    "google": {"imap": ("imap.gmail.com", 993, "SSL"), "smtp": ("smtp.gmail.com", 465, "SSL"), "pop": ("pop.gmail.com", 995, "SSL"),
               "note": "Use an App Password if 2-Step Verification is on; enable IMAP in Gmail settings."},
    "microsoft": {"imap": ("outlook.office365.com", 993, "SSL"), "smtp": ("smtp.office365.com", 587, "STARTTLS"), "pop": ("outlook.office365.com", 995, "SSL"),
                  "note": "Basic auth is disabled for most tenants; use a client that supports Modern Auth (OAuth). SMTP AUTH may need enabling per mailbox."},
    "zoho": {"imap": ("imappro.zoho.in", 993, "SSL"), "smtp": ("smtppro.zoho.in", 465, "SSL"), "pop": ("poppro.zoho.in", 995, "SSL"),
             "note": "IMAP/POP is NOT available on the Zoho Forever Free plan. Use .com hosts (imappro.zoho.com) for US data-center accounts."},
    "titan": {"imap": ("imap.titan.email", 993, "SSL"), "smtp": ("smtp.titan.email", 465, "SSL"), "pop": ("pop.titan.email", 995, "SSL"), "note": ""},
    "godaddy": {"imap": ("imap.secureserver.net", 993, "SSL"), "smtp": ("smtpout.secureserver.net", 465, "SSL"), "pop": ("pop.secureserver.net", 995, "SSL"),
                "note": "Newer GoDaddy mailboxes are Microsoft 365; check the MX before using these."},
    "hostinger": {"imap": ("imap.hostinger.com", 993, "SSL"), "smtp": ("smtp.hostinger.com", 465, "SSL"), "pop": ("pop.hostinger.com", 995, "SSL"), "note": ""},
    "netsol": {"imap": ("mail.<domain>", 993, "SSL"), "smtp": ("mail.<domain>", 465, "SSL"), "pop": ("mail.<domain>", 995, "SSL"),
               "note": "Network Solutions legacy mail typically uses mail.<yourdomain>; newer plans may use Microsoft 365 or Titan."},
    "protonmail": {"imap": ("127.0.0.1 (Proton Bridge)", 1143, "STARTTLS"), "smtp": ("127.0.0.1 (Proton Bridge)", 1025, "STARTTLS"), "pop": None,
                   "note": "Desktop clients need Proton Mail Bridge (paid plans)."},
    "fastmail": {"imap": ("imap.fastmail.com", 993, "SSL"), "smtp": ("smtp.fastmail.com", 465, "SSL"), "pop": ("pop.fastmail.com", 995, "SSL"),
                 "note": "Use an app password."},
    "yahoo": {"imap": ("imap.mail.yahoo.com", 993, "SSL"), "smtp": ("smtp.mail.yahoo.com", 465, "SSL"), "pop": ("pop.mail.yahoo.com", 995, "SSL"),
              "note": "Requires an app password."},
    "purelymail": {"imap": ("imap.purelymail.com", 993, "SSL"), "smtp": ("smtp.purelymail.com", 465, "SSL"), "pop": ("pop.purelymail.com", 995, "SSL"), "note": ""},
}


def match_email_provider(mx_hosts: list[str]) -> tuple[str, str] | None:
    for key, name, pats, _spf, _sel in EMAIL_PROVIDERS:
        if any(p in h for h in mx_hosts for p in pats):
            return key, name
    return None


def email_provider_info(key: str) -> dict:
    for k, name, pats, spf, sel in EMAIL_PROVIDERS:
        if k == key:
            return {"key": k, "name": name, "mx_patterns": pats, "spf_include": spf, "dkim_selectors": sel}
    return {}


def match_dns_provider(ns_hosts: list[str]) -> tuple[str, str] | None:
    for key, name, pats in DNS_PROVIDERS:
        if any(p in h for h in ns_hosts for p in pats):
            return key, name
    return None


def match_hosting(cnames: list[str], ips: list[str]) -> str | None:
    for _k, name, pats in HOSTING_CNAME:
        if any(p in c for c in cnames for p in pats):
            return name
    for ip in ips:
        if ip in HOSTING_IPS:
            return HOSTING_IPS[ip]
    return None


# SPF includes that legitimately belong to providers (for "which services send for you")
SPF_INCLUDE_HINTS = {
    "_spf.google.com": "Google Workspace", "spf.protection.outlook.com": "Microsoft 365",
    "zoho.in": "Zoho Mail", "zoho.com": "Zoho Mail", "zohomail.in": "Zoho Mail", "zohomail.com": "Zoho Mail",
    "spf.titan.email": "Titan", "secureserver.net": "GoDaddy", "_spf.mail.hostinger.com": "Hostinger",
    "amazonses.com": "Amazon SES", "sendgrid.net": "SendGrid", "servers.mcsv.net": "Mailchimp",
    "spf.brevo.com": "Brevo", "spf.sendinblue.com": "Brevo", "mailgun.org": "Mailgun",
    "spf.improvmx.com": "ImprovMX", "_spf.mx.cloudflare.net": "Cloudflare Email Routing",
    "spf.mandrillapp.com": "Mandrill", "_spf.salesforce.com": "Salesforce", "spf.mtasv.net": "Postmark",
    "_spf.protonmail.ch": "Proton Mail", "spf.messagingengine.com": "Fastmail", "netsolmail.net": "Network Solutions",
}
