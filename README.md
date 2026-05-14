# Mega Internet Safety Blocklist

A broad uBlock Origin-compatible domain blocklist for stricter, safer browsing.

This repository contains domain names and filter syntax for user-controlled content filtering only. It does not host, embed, mirror, or promote third-party media or services.

Use the raw list URL:

```text
https://raw.githubusercontent.com/jasperdevs/mega-internet-safety-blocklist/main/mega-internet-safety-blocklist.txt
```

## Use

In uBlock Origin:

1. Open the uBlock Origin dashboard.
2. Go to **Filter lists**.
3. Expand **Custom**.
4. Paste the raw URL above into **Import**.
5. Click **Apply changes**.

The list is also plain filter syntax, so other blockers that support uBlock-style or Adblock Plus-style filter lists may be able to import the same URL.

## Notes

- The list currently contains 67k+ domain rules.
- It is intentionally broad and may block more than a default browser setup.
- If a site breaks, disable this list temporarily or add a local exception in your blocker.
- Issues and pull requests should be limited to list accuracy, false positives, and filter compatibility.
