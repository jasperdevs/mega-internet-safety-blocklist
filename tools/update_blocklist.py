#!/usr/bin/env python3
"""Build the public filter list from curated domain sources."""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILTER_OUTPUT = ROOT / "mega-internet-safety-blocklist.txt"
DNS_OUTPUT = ROOT / "mega-internet-safety-domains.txt"
BADGE_OUTPUT = ROOT / "badges" / "domain-count.json"

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

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

OUT_OF_SCOPE_RE = re.compile(
    r"alcohol|antivirus|beer|betting|bingo|blackjack|cannabis|casino|cocaine|drug|"
    r"firearm|gambl|gunshop|heroin|liquor|lottery|malware|marijuana|phishing|"
    r"poker|roulette|slots?|sportsbook|spyware|tobacco|trojan|vape|virus|weapon|"
    r"weed|wine"
)

CONDITIONAL_OUT_OF_SCOPE_RE = re.compile(
    r"academy|airline|airport|bank|booking|business|calendar|clickbank|college|"
    r"coupon|crypto|education|financ|government|hotel|insurance|jobs|library|"
    r"museum|news|newspaper|pharmacy|religion|restaurant|school|shopping|"
    r"student|taxi|teacher|training|travel|university"
)

SCOPE_RE = re.compile(
    r"adult|anal|bdsm|bigass|blowjob|boob|bondage|camgirl|cams?|chaturbate|"
    r"cock|cumshot|eporner|erome|escort|erotic|faphouse|fuck|gay|gore|hentai|"
    r"jasmin|lesbian|milf|naked|nude|onlyfans|porn|pussy|redgifs|sex|shock|"
    r"spankbang|stripchat|teen|tnaflix|wank|xham|xnxx|xvideo|xxx"
)

FALSE_SCOPE_RE = re.compile(r"essex|middlesex|sussex|wessex")
FALSE_SCOPE_CONTEXT_RE = re.compile(
    r"adult[-.]?education|adult[-.]?school|adult[-.]?student|adult[-.]?training"
)

BROAD_NON_SCOPE_DOMAINS = {
    "adidascampus.fr",
    "adult-ed.school",
    "adult-education-courses01.sbs",
    "adult-education-hub.online",
    "adulteducation.online",
    "adulteducation2.blogspot.com",
    "alameda-adult-school.org",
    "aliexpresscouponbestproduct.blogspot.com",
    "ambitionbox.com",
    "b-cdn.net",
    "badoo.com",
    "camscanner.com",
    "candy.ai",
    "character.ai",
    "chicagoreader.com",
    "coding-resources.com",
    "cosmopolitan.com",
    "dmm.co.jp",
    "dmm.com",
    "dramaboxdb.com",
    "evt.mxplay.com",
    "fc2.com",
    "fetlife.com",
    "fishki.net",
    "flirtify.com",
    "gotinder.com",
    "gptgirlfriend.online",
    "grindr.com",
    "grindr.mobi",
    "hemsida.eu",
    "imgbox.com",
    "kinopoisk.ru",
    "konimbo.co.il",
    "joyreactor.cc",
    "likee.video",
    "lovense.com",
    "m.vk.com",
    "match.com",
    "meusitehostgator.com.br",
    "mixh.jp",
    "nicovideo.jp",
    "okcupid.com",
    "ourdream.ai",
    "political-resources.com",
    "popcash.net",
    "prv.pl",
    "sdk-push.hiaiabc.com",
    "sniffies.com",
    "spicychat.ai",
    "super.cz",
    "temporary.site",
    "transip.me",
    "use-application-dns.net",
    "via.placeholder.com",
    "video-preview.s3.yandex.net",
    "xiaohongshu.com",
    "yourtango.com",
}


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
    if is_broad_non_scope_domain(domain):
        return True
    if OUT_OF_SCOPE_RE.search(domain):
        return True
    if FALSE_SCOPE_CONTEXT_RE.search(domain):
        return True
    scope_domain = FALSE_SCOPE_RE.sub("", domain)
    if CONDITIONAL_OUT_OF_SCOPE_RE.search(domain) and not SCOPE_RE.search(scope_domain):
        return True
    return False


def is_broad_non_scope_domain(domain: str) -> bool:
    return any(
        domain == broad_domain or domain.endswith(f".{broad_domain}")
        for broad_domain in BROAD_NON_SCOPE_DOMAINS
    )


def is_likely_in_scope(domain: str) -> bool:
    return bool(SCOPE_RE.search(FALSE_SCOPE_RE.sub("", domain)))


def main() -> int:
    domain_sources: dict[str, set[str]] = {}
    source_counts: list[tuple[str, int]] = []

    for name, source in SOURCES:
        text = fetch(source)
        before = len(domain_sources)
        for line in text.splitlines():
            domain = extract_domain(line)
            if domain and not is_out_of_scope(domain):
                domain_sources.setdefault(domain, set()).add(name)
        source_counts.append((name, len(domain_sources) - before))

    domains = {
        domain
        for domain, sources in domain_sources.items()
        if is_likely_in_scope(domain) or len(sources) >= 2
    }

    sorted_domains = sorted(domains)

    filter_lines = [f"||{domain}^" for domain in sorted_domains]
    FILTER_OUTPUT.write_text("\n".join(filter_lines) + "\n", encoding="utf-8", newline="\n")

    DNS_OUTPUT.write_text("\n".join(sorted_domains) + "\n", encoding="utf-8", newline="\n")

    BADGE_OUTPUT.parent.mkdir(exist_ok=True)
    BADGE_OUTPUT.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "label": "domains",
                "message": f"{len(domains):,}",
                "color": "blue",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"Wrote {FILTER_OUTPUT}")
    print(f"Wrote {DNS_OUTPUT}")
    print(f"Wrote {BADGE_OUTPUT}")
    print(f"Total unique domain rules: {len(domains)}")
    for name, count in source_counts:
        print(f"{name}: +{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
