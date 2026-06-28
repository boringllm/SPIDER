"""Pentest target provider for SPAIDER — CUSTOMIZE THIS FILE.

At the start of every engagement the "Start engagement" flow asks this module for the list of targets
to offer the operator (``GET /api/targets`` calls ``list_targets()``).


Return a list of dicts. Recognised keys (all optional except ``target``):
  - ``id``           : stable identifier (defaults to the name/target).
  - ``name``         : label shown in the picker (defaults to ``target``).
  - ``target``       : the in-scope target string SPAIDER will attack (host, IP, CIDR, or URL).
  - ``instructions`` : rules of engagement / scope — becomes the engagement's initial prompt.
  - ``session_name`` : the session name a LIMITED run is forced to use.

Replace the dummy data below with your real source — e.g. read a CSV/JSON, query a CMDB or ticketing
system, call an internal API, filter by who is allowed, etc. Keep it fast (it runs per request) and
never raise: return ``[]`` on failure.
"""
from __future__ import annotations


def list_targets() -> list[dict]:
    """Return the list of selectable pentest targets. CUSTOMIZE — these are dummy examples."""
    # --- DUMMY EXAMPLES — replace with your real target source ---------------------------------
    return [
        {
            "id": "acme-web",
            "name": "ACME staging web app",
            "target": "https://staging.acme.example.com",
            "instructions": (
                "Authorised web-application assessment of the ACME staging portal. In scope: the "
                "single host staging.acme.example.com (HTTPS). Out of scope: production, payment "
                "providers, any third-party domain. No DoS, no destructive payloads, no data "
                "exfiltration beyond proof. Test window: business hours."
            ),
            "session_name": "ACME staging — web assessment",
        },
        {
            "id": "lab-net-10",
            "name": "Internal lab network 10.10.10.0/24",
            "target": "10.10.10.0/24",
            "instructions": (
                "Authorised internal network assessment of the isolated lab range 10.10.10.0/24. "
                "Enumerate hosts/services, identify weak credentials and vulnerable services. Do "
                "not pivot outside the range. No destructive actions."
            ),
            "session_name": "Lab 10.10.10.0/24 — network assessment",
        },
        {
            "id": "juiceshop",
            "name": "OWASP Juice Shop (training)",
            "target": "http://juiceshop.local:3000",
            "instructions": (
                "Training engagement against the local OWASP Juice Shop instance. Full web-app "
                "testing is authorised against this single host only."
            ),
            "session_name": "Juice Shop — training run",
        },

    ]
