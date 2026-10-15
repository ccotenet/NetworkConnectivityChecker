# Network Check

A small, static dashboard that shows what the internet can see about your connection, tests reachability and speed, and lets you dig into every raw response. No backend, no database, no build step. It's plain HTML, CSS and JavaScript, so any static host works (GitHub Pages, Azure Static Web Apps, S3, Netlify, or a local folder).

## What it shows

| Section | What it does |
|---|---|
| **Headline** | A one-sentence summary: provider, approximate city, public IP. |
| **What the internet sees** | Cards for public IPv4/IPv6, location, ISP/ASN, time zone, device, the browser's connection estimate, Cloudflare edge, and server-measured RTT. |
| **Privacy & consistency signals** | Cross-checks that hint at VPNs, proxies or leaks: IP agreement across services, time zone vs IP location, WebRTC public/local IP exposure, WARP/Gateway, HTTP/3 support, hosting/VPN flags. |
| **Reachability & latency** | Cold + warm round trips to Cloudflare, Google, Microsoft, AWS, Apple, GitHub, Wikipedia and Google DNS, with jitter. |
| **Speed test** | On demand. Idle latency, download (~36 MB) and upload (~8 MB) against `speed.cloudflare.com`. |
| **DNS lookup** | DNS-over-HTTPS against Google and Cloudflare side by side, with DNSSEC (AD) status. |
| **Deep dive** | Every request: overview, a DNS/TCP/TLS/TTFB waterfall (when the server allows it), visible headers, a collapsible JSON tree, and the raw body. |

**Export JSON** downloads the full report (every request, timing, environment and test result).

## Run locally

It's a flat site: double-click `index.html` and it runs straight from disk. No Python, Node or other runtime is needed.

If you'd rather serve it over `http://localhost`, there's an optional zero-dependency PowerShell server:

```powershell
powershell -ExecutionPolicy Bypass -File serve.ps1
```

Then browse to http://localhost:8765. Any other static server works too.

## Deploy

Copy `index.html`, `css/` and `js/` to any static host. There is nothing to configure.

## Data sources

All keyless and CORS-enabled, called directly from the browser:

- `api.ipify.org` / `api6.ipify.org`: public IPv4 / IPv6
- `ipwho.is`: geolocation, ISP, time zone
- `api.ipapi.is`: second geolocation opinion (plus VPN/datacenter flags when the free tier includes them)
- `1.1.1.1/cdn-cgi/trace`: Cloudflare edge, HTTP/TLS version, WARP status
- `speed.cloudflare.com`: edge metadata, server-side TCP RTT, speed test
- `dns.google` / `cloudflare-dns.com`: DNS-over-HTTPS
- `stun.l.google.com`, `stun.cloudflare.com`: WebRTC STUN

Free tiers have rate limits. If a source fails, the rest of the page keeps working and the Deep dive shows the error.

## Browser limits worth knowing

- **Cross-origin headers**: browsers only expose CORS-safelisted headers, plus whatever the server lists in `Access-Control-Expose-Headers`.
- **Timing breakdown**: DNS/TCP/TLS phases are only visible when the server sends `Timing-Allow-Origin`. Cloudflare's speed endpoint does; most others don't.
- **Reachability probes** use `no-cors` requests. They prove the network path works but can't read HTTP status codes.
- **IP geolocation** is approximate, and providers often disagree. The page shows each one's answer.
