# ⚡ Mega Internet Safety Blocklist

![rules](https://img.shields.io/badge/rules-868k%2B-blue)
![format](https://img.shields.io/badge/formats-uBlock%20%2B%20DNS-2ea44f)
![license](https://img.shields.io/badge/license-GPL--3.0-lightgrey)

A broad uBlock Origin-compatible domain blocklist for stricter, safer browsing.

This repository contains domain names and filter syntax for user-controlled content filtering only. It does not host, embed, mirror, or promote third-party media or services.

## Contents

1. [Lists](#lists)
2. [Use with uBlock Origin](#use-with-ublock-origin)
3. [Use with DNS blockers](#use-with-dns-blockers)
4. [Scope](#scope)
5. [Updating](#updating)
6. [License](#license)

## Lists

| List | Raw URL | Format |
| --- | --- | --- |
| Browser filter list | `https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/mega-internet-safety-blocklist.txt` | `||domain^` |
| DNS domain export | `https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/mega-internet-safety-domains.txt` | `domain.com` |

## Use with uBlock Origin

1. Open the uBlock Origin dashboard.
2. Go to **Filter lists**.
3. Expand **Custom**.
4. Paste the browser filter list URL into **Import**.
5. Click **Apply changes**.

## Use with DNS blockers

Use the DNS domain export for network-level blockers that accept domain list URLs, such as Pi-hole or AdGuard Home.

This list is very large. If your DNS blocker becomes slow, use the uBlock Origin list in the browser first and keep DNS filtering for smaller lists.

## Scope

- Generated from the recovered local list plus maintained public sources.
- Focused on adult and graphic shock-content domains.
- Excludes known non-scope categories such as gambling, drugs, alcohol, weapons, and generic security feeds.
- Deduplicated on every build.
- Checked against an allowlist and a small obvious-safe-domain audit.
- Intentionally broad, so false positives are still possible.

If a site breaks, disable this list temporarily or add a local exception in your blocker. Issues and pull requests should be limited to list accuracy, false positives, and filter compatibility.

## Updating

Regenerate both list files:

```sh
python tools/update_blocklist.py
python tools/audit_blocklist.py
```

## License

GPL-3.0. See [LICENSE](LICENSE) and [SOURCE-NOTICES.md](SOURCE-NOTICES.md).
