#!/usr/bin/env python3
"""Audit generated lists for formatting, scope, and broad false positives."""

from __future__ import annotations

import argparse
import csv
import io
import re
import urllib.request
import zipfile
from pathlib import Path

import update_blocklist


ROOT = Path(__file__).resolve().parents[1]
FILTER_OUTPUT = ROOT / "mega-internet-safety-blocklist.txt"
DNS_OUTPUT = ROOT / "mega-internet-safety-domains.txt"
BADGE_OUTPUT = ROOT / "badges" / "domain-count.json"
UMBRELLA_TOP_1M = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

KNOWN_SAFE_DOMAINS = {
    "adobe.com",
    "amazon.com",
    "apple.com",
    "bankofamerica.com",
    "bbc.com",
    "bing.com",
    "chase.com",
    "chicagoreader.com",
    "cloudflare.com",
    "coding-resources.com",
    "discord.com",
    "duckduckgo.com",
    "epicgames.com",
    "facebook.com",
    "gmail.com",
    "github.com",
    "google.com",
    "instagram.com",
    "microsoft.com",
    "minecraft.net",
    "mozilla.org",
    "netflix.com",
    "nintendo.com",
    "nytimes.com",
    "openai.com",
    "outlook.com",
    "paypal.com",
    "political-resources.com",
    "reddit.com",
    "roblox.com",
    "spotify.com",
    "stackexchange.com",
    "stackoverflow.com",
    "steamcommunity.com",
    "steampowered.com",
    "stripe.com",
    "tiktok.com",
    "twitch.tv",
    "vivaldi.com",
    "weather.com",
    "wikipedia.org",
    "x.com",
    "yahoo.com",
    "youtube.com",
    "zen-browser.app",
}

ADULT_OR_SHOCK_RE = re.compile(
    r"adult|anal|bdsm|bigass|blowjob|boob|bondage|camgirl|cams?|chaturbate|cock|"
    r"cumshot|escort|erome|erotic|faphouse|fuck|gay|gore|hentai|jasmin|lesbian|"
    r"milf|naked|nude|onlyfans|phncdn|porn|pussy|redgifs|sex|shock|spankbang|"
    r"strip|teen|tnaflix|wank|xham|xnxx|xvideo|xxx"
)

ADULT_INFRA_RE = re.compile(
    r"ahcdn|blcdog|dditsadn|exoclick|explicit\.bing\.net|flixcdn|highwebmedia|"
    r"juicyads|martted|pemsrv|realsrv|strpst|trafficjunky|tsyndicate|ttcache|"
    r"txnhh|xhcdn|xhpingcdn|xlivrdr|xlviiirdr|ypncdn"
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_filter_lines() -> list[str]:
    return FILTER_OUTPUT.read_text(encoding="utf-8").splitlines()


def read_dns_lines() -> list[str]:
    return DNS_OUTPUT.read_text(encoding="utf-8").splitlines()


def read_filter_domains(lines: list[str]) -> list[str]:
    domains = []
    bad_lines = []
    for index, line in enumerate(lines, start=1):
        if not line.startswith("||") or not line.endswith("^"):
            bad_lines.append(f"{index}:{line}")
        else:
            domains.append(line[2:-1])
    if bad_lines:
        fail("uBlock list has non-rule lines: " + ", ".join(bad_lines[:20]))
    return domains


def read_dns_domains(lines: list[str]) -> list[str]:
    bad_lines = []
    for index, line in enumerate(lines, start=1):
        if not update_blocklist.DOMAIN_RE.fullmatch(line):
            bad_lines.append(f"{index}:{line}")
    if bad_lines:
        fail("DNS list has invalid domain lines: " + ", ".join(bad_lines[:20]))
    return lines


def audit_core() -> list[str]:
    filter_lines = read_filter_lines()
    dns_lines = read_dns_lines()

    if not filter_lines:
        fail("uBlock list is empty")
    if not dns_lines:
        fail("DNS list is empty")

    filter_domains = read_filter_domains(filter_lines)
    dns_domains = read_dns_domains(dns_lines)

    if len(filter_domains) != len(set(filter_domains)):
        fail("uBlock list has duplicate domains")
    if len(dns_domains) != len(set(dns_domains)):
        fail("DNS list has duplicate domains")
    if filter_domains != dns_domains:
        fail("uBlock and DNS exports do not contain the same domains in the same order")
    if filter_domains != sorted(filter_domains):
        fail("generated domains are not sorted")

    generated = set(filter_domains)

    false_positives = sorted(KNOWN_SAFE_DOMAINS & generated)
    if false_positives:
        fail("known safe domains are blocked: " + ", ".join(false_positives))

    non_scope_but_blocked = sorted(
        domain for domain in filter_domains if update_blocklist.is_broad_non_scope_domain(domain)
    )
    if non_scope_but_blocked:
        fail("broad non-scope domains are still blocked: " + ", ".join(non_scope_but_blocked[:20]))

    out_of_scope = [domain for domain in filter_domains if update_blocklist.is_out_of_scope(domain)]
    if out_of_scope:
        fail("out-of-scope category domains are blocked: " + ", ".join(out_of_scope[:20]))

    if BADGE_OUTPUT.exists():
        badge_text = BADGE_OUTPUT.read_text(encoding="utf-8")
        if f"{len(filter_domains):,}" not in badge_text:
            fail("domain-count badge does not match generated list count")

    return filter_domains


def fetch_umbrella_domains(limit: int) -> list[tuple[int, str]]:
    req = urllib.request.Request(
        UMBRELLA_TOP_1M,
        headers={"User-Agent": "mega-internet-safety-blocklist-audit/1.0"},
    )
    data = urllib.request.urlopen(req, timeout=60).read()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        csv_name = archive.namelist()[0]
        rows = archive.read(csv_name).decode("utf-8", errors="ignore").splitlines()

    domains: list[tuple[int, str]] = []
    for row in csv.reader(rows):
        if len(row) < 2:
            continue
        rank = int(row[0])
        if rank > limit:
            break
        domains.append((rank, row[1].strip().lower().rstrip(".")))
    return domains


def build_source_counts(blocked_domains: set[str]) -> dict[str, int]:
    source_counts = {domain: 0 for domain in blocked_domains}
    for _name, source in update_blocklist.SOURCES:
        seen_in_source = set()
        for line in update_blocklist.fetch(source).splitlines():
            domain = update_blocklist.extract_domain(line)
            if domain in blocked_domains and domain not in seen_in_source:
                source_counts[domain] += 1
                seen_in_source.add(domain)
    return source_counts


def audit_top_domains(blocked_domains: set[str], limit: int) -> None:
    suspicious: list[tuple[int, str]] = []
    intersections = 0
    source_counts = build_source_counts(blocked_domains)

    for rank, domain in fetch_umbrella_domains(limit):
        if domain not in blocked_domains:
            continue
        intersections += 1
        if (
            not ADULT_OR_SHOCK_RE.search(domain)
            and not ADULT_INFRA_RE.search(domain)
            and source_counts.get(domain, 0) < 2
        ):
            suspicious.append((rank, domain))
            if len(suspicious) >= 50:
                break

    if suspicious:
        sample = ", ".join(f"{rank}:{domain}" for rank, domain in suspicious[:20])
        fail(f"suspicious popular-domain intersections: {sample}")

    print(f"top-domain scan: {intersections} blocked intersections checked within top {limit:,}")
    print("top-domain suspicious intersections: 0")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--top-domains",
        type=int,
        default=0,
        metavar="N",
        help="also scan the Cisco Umbrella top N domains for suspicious intersections",
    )
    args = parser.parse_args()

    filter_domains = audit_core()

    print(f"domains: {len(filter_domains)}")
    print("duplicates: 0")
    print("metadata lines: 0")
    print("known false positives: 0")
    print("out-of-scope category hits: 0")

    if args.top_domains:
        audit_top_domains(set(filter_domains), args.top_domains)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
