# ⚡ Mega Internet Safety Blocklist

![domains](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/badges/domain-count.json)
![format](https://img.shields.io/badge/formats-uBlock%20%2B%20DNS-2ea44f)
![license](https://img.shields.io/badge/license-GPL--3.0-lightgrey)

A broad uBlock Origin-compatible domain blocklist for stricter, safer browsing.

This repository contains domain names and filter syntax for user-controlled content filtering only. It does not host, embed, mirror, or promote third-party media or services.

## Lists

| List | Raw URL | Format |
| --- | --- | --- |
| Browser filter list | `https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/mega-internet-safety-blocklist.txt` | `||domain^` |
| DNS domain export | `https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/mega-internet-safety-domains.txt` | `domain.com` |

## Use with uBlock Origin

1. Open the uBlock Origin dashboard.
2. Go to **My filters**.
3. Enable **My custom filters**.
4. Paste the browser filter list URL into the textbox.
5. Click **Apply changes**.

## Use with DNS blockers

Use the DNS domain export for network-level blockers that accept domain list URLs, such as Pi-hole or AdGuard Home.

This list is very large. If your DNS blocker becomes slow, use the uBlock Origin list in the browser first and keep DNS filtering for smaller lists.

## Scope

- Generated from the recovered local list plus maintained public sources.
- Focused on adult and graphic shock-content domains.
- Keeps domains with direct scope signals or confirmation across multiple source lists.
- Excludes known non-scope categories such as gambling, drugs, alcohol, weapons, and generic security feeds.
- Deduplicated on every build.
- Intentionally broad, so false positives are still possible.

If a site breaks, disable this list temporarily or add a local exception in your blocker. Issues and pull requests should be limited to list accuracy, false positives, and filter compatibility.

## License

GPL-3.0. See [LICENSE](LICENSE) and [SOURCE-NOTICES.md](SOURCE-NOTICES.md).
