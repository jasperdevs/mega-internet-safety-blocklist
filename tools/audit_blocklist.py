#!/usr/bin/env python3
"""Check generated lists for duplicates, bad formatting, and obvious false positives."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FILTER_OUTPUT = ROOT / "mega-internet-safety-blocklist.txt"
DNS_OUTPUT = ROOT / "mega-internet-safety-domains.txt"
ALLOWLIST = ROOT / "sources" / "allowlist.txt"

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

OUT_OF_SCOPE_RE = re.compile(
    r"alcohol|antivirus|beer|betting|bingo|blackjack|cannabis|casino|cocaine|drug|"
    r"firearm|gambl|gunshop|heroin|liquor|lottery|malware|marijuana|phishing|"
    r"poker|roulette|slots?|sportsbook|tobacco|vape|virus|weapon|weed|wine"
)


def read_filter_domains() -> list[str]:
    domains = []
    for line in FILTER_OUTPUT.read_text(encoding="utf-8").splitlines():
        if line.startswith("||") and line.endswith("^"):
            domains.append(line[2:-1])
    return domains


def read_dns_domains() -> list[str]:
    domains = []
    for line in DNS_OUTPUT.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def read_allowlist() -> set[str]:
    domains = set()
    for line in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> int:
    filter_domains = read_filter_domains()
    dns_domains = read_dns_domains()

    if len(filter_domains) != len(set(filter_domains)):
        fail("uBlock list has duplicate domains")
    if len(dns_domains) != len(set(dns_domains)):
        fail("DNS list has duplicate domains")
    if filter_domains != dns_domains:
        fail("uBlock and DNS exports do not contain the same domains in the same order")

    generated = set(filter_domains)
    false_positives = sorted(KNOWN_SAFE_DOMAINS & generated)
    if false_positives:
        fail("obvious safe domains are blocked: " + ", ".join(false_positives))

    out_of_scope = [domain for domain in filter_domains if OUT_OF_SCOPE_RE.search(domain)]
    if out_of_scope:
        fail("out-of-scope category domains are blocked: " + ", ".join(out_of_scope[:20]))

    allowed_but_blocked = sorted(read_allowlist() & generated)
    if allowed_but_blocked:
        fail("allowlisted domains are still blocked: " + ", ".join(allowed_but_blocked))

    print(f"domains: {len(filter_domains)}")
    print("duplicates: 0")
    print("obvious false positives: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
