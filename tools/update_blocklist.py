#!/usr/bin/env python3
"""Build the public filter list from curated domain sources."""

from __future__ import annotations

import datetime as dt
import re
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILTER_OUTPUT = ROOT / "mega-internet-safety-blocklist.txt"
DNS_OUTPUT = ROOT / "mega-internet-safety-domains.txt"
ALLOWLIST = ROOT / "sources" / "allowlist.txt"

SOURCES = [
    (
        "local recovered list",
        ROOT / "sources" / "recovered-user-filters.txt",
    ),
    (
        "HaGeZi safety/adult list",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt",
    ),
    (
        "OISD safety/adult-shock list",
        "https://nsfw.oisd.nl/",
    ),
    (
        "Block List Project adult list",
        "https://blocklistproject.github.io/Lists/adguard/porn-ags.txt",
    ),
]

HEADER = """! Title: Mega Internet Safety Blocklist
! Description: A broad uBlock Origin-compatible domain blocklist for stricter, safer browsing.
! Purpose: Domain names and filter syntax for user-controlled content filtering only.
! Notice: This list does not host, embed, mirror, or promote third-party media or services.
! Format: ||domain^
! Sources: see SOURCE-NOTICES.md
"""

DNS_HEADER = """# Title: Mega Internet Safety Blocklist - DNS domain export
# Description: Plain domain export for DNS sinkholes and network-level filters.
# Purpose: Domain names for user-controlled content filtering only.
# Notice: This list does not host, embed, mirror, or promote third-party media or services.
# Format: domain
# Sources: see SOURCE-NOTICES.md
"""

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

OUT_OF_SCOPE_RE = re.compile(
    r"betting|blackjack|casino|gambl|poker|roulette|sportsbook"
)


def fetch(source: str | Path) -> str:
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8", errors="ignore")

    req = urllib.request.Request(source, headers={"User-Agent": "mega-internet-safety-blocklist/1.0"})
    with urllib.request.urlopen(req, timeout=90) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_domain(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(("#", "!", "[", "@@")):
        return None

    if line.startswith("||"):
        domain = line[2:].split("^", 1)[0].split("/", 1)[0]
    elif line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
        parts = line.split()
        domain = parts[1] if len(parts) > 1 else ""
    elif line.startswith("address=/"):
        domain = line.split("/", 2)[1]
    else:
        domain = line.split()[0]

    domain = domain.strip().strip(".").lower()
    if domain.startswith("*."):
        domain = domain[2:]
    if DOMAIN_RE.fullmatch(domain):
        return domain
    return None


def is_out_of_scope(domain: str) -> bool:
    return bool(OUT_OF_SCOPE_RE.search(domain))


def main() -> int:
    allowlist = set()
    if ALLOWLIST.exists():
        for line in ALLOWLIST.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain = extract_domain(line)
            if domain:
                allowlist.add(domain)

    domains: set[str] = set()
    source_counts: list[tuple[str, int]] = []

    for name, source in SOURCES:
        text = fetch(source)
        before = len(domains)
        for line in text.splitlines():
            domain = extract_domain(line)
            if domain and not is_out_of_scope(domain):
                domains.add(domain)
        source_counts.append((name, len(domains) - before))

    domains.difference_update(allowlist)

    today = dt.date.today().isoformat()
    sorted_domains = sorted(domains)

    filter_lines = [
        HEADER.rstrip(),
        f"! Last generated: {today}",
        f"! Total unique domain rules: {len(domains)}",
        "",
    ]
    filter_lines.extend(f"||{domain}^" for domain in sorted_domains)
    FILTER_OUTPUT.write_text("\n".join(filter_lines) + "\n", encoding="utf-8", newline="\n")

    dns_lines = [
        DNS_HEADER.rstrip(),
        f"# Last generated: {today}",
        f"# Total unique domains: {len(domains)}",
        "",
    ]
    dns_lines.extend(sorted_domains)
    DNS_OUTPUT.write_text("\n".join(dns_lines) + "\n", encoding="utf-8", newline="\n")

    print(f"Wrote {FILTER_OUTPUT}")
    print(f"Wrote {DNS_OUTPUT}")
    print(f"Total unique domain rules: {len(domains)}")
    for name, count in source_counts:
        print(f"{name}: +{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
