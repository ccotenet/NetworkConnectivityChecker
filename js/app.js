/* Network Check — a static, backend-free connectivity dashboard.
 * Every check runs in the browser against public, keyless, CORS-enabled endpoints. */
(() => {
  'use strict';

  // ---------------------------------------------------------------- config

  // Sources that tell us who we look like from the outside.
  const SOURCES = [
    { id: 'ipv4', label: 'Public IPv4 (ipify)', url: 'https://api.ipify.org?format=json', parse: 'json',
      purpose: 'Asks an IPv4-only server which address your request came from.' },
    { id: 'ipv6', label: 'Public IPv6 (ipify)', url: 'https://api6.ipify.org?format=json', parse: 'json', timeout: 5000,
      purpose: 'Same question over IPv6 only. Failing here just means you have no working IPv6 path.' },
    { id: 'ipwho', label: 'Geolocation (ipwho.is)', url: 'https://ipwho.is/', parse: 'json',
      purpose: 'Looks up location, provider and time zone for your IP in a geolocation database.' },
    { id: 'ipapiis', label: 'IP intelligence (ipapi.is)', url: 'https://api.ipapi.is/', parse: 'json',
      purpose: 'A second geolocation database, plus hosting/VPN/proxy flags when the free tier provides them.' },
    { id: 'trace', label: 'Cloudflare trace', url: 'https://1.1.1.1/cdn-cgi/trace', parse: 'trace',
      purpose: 'Cloudflare echoes how your request arrived: edge location, HTTP and TLS versions, WARP status.' },
    { id: 'cfmeta', label: 'Cloudflare edge metadata', url: 'https://speed.cloudflare.com/__down?bytes=0', parse: 'cfmeta',
      purpose: 'A zero-byte download whose response headers carry Cloudflare\'s view of you, and whose Server-Timing exposes the TCP round-trip time measured by the server.' },
  ];

  // Well-known endpoints for reachability. Fetched in no-cors mode: we can't read the reply, but
  // a resolved promise proves DNS, TCP, TLS and HTTP all worked.
  const PROBES = [
    { name: 'Cloudflare', url: 'https://1.1.1.1/cdn-cgi/trace' },
    { name: 'Google', url: 'https://www.google.com/generate_204' },
    { name: 'Microsoft', url: 'https://www.microsoft.com/favicon.ico' },
    { name: 'Amazon AWS', url: 'https://aws.amazon.com/favicon.ico' },
    { name: 'Apple', url: 'https://www.apple.com/favicon.ico' },
    { name: 'GitHub', url: 'https://github.com/favicon.ico' },
    { name: 'Wikipedia', url: 'https://www.wikipedia.org/static/favicon/wikipedia.ico' },
    { name: 'Google Public DNS', url: 'https://dns.google/resolve?name=example.com' },
  ];

  const STUN_SERVERS = ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'];
  const SPEED = 'https://speed.cloudflare.com';

  // ---------------------------------------------------------------- state

  let state;
  let runId = 0;
  const deepEls = new Map();

  function freshState() {
    return { startedAt: new Date().toISOString(), sources: {}, env: null, webrtc: null, probes: null, speed: null, requests: [] };
  }

  try { performance.setResourceTimingBufferSize(2000); } catch { /* not supported */ }

  // ---------------------------------------------------------------- helpers

  const $ = (sel) => document.querySelector(sel);

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class') e.className = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      e.append(k instanceof Node ? k : String(k));
    }
    return e;
  }

  const fmtMs = (ms) => (ms == null || !isFinite(ms)) ? '—' : `${ms < 10 ? ms.toFixed(1) : Math.round(ms)} ms`;
  const fmtBytes = (n) => n == null ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
  const median = (xs) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
  const bust = (url) => url + (url.includes('?') ? '&' : '?') + '_=' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  // Windows has no flag glyphs and would render bare letters, so skip flags there.
  const flag = (cc) => (cc && /^[a-z]{2}$/i.test(cc) && !/Windows/.test(navigator.userAgent)) ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0))) : '';
  const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
  // Sources mix ISO codes and names ("CA" vs "Canada"); normalize to an English name for comparison.
  const countryName = (cc, name) => {
    try { if (cc && /^[a-z]{2}$/i.test(cc)) return new Intl.DisplayNames(['en'], { type: 'region' }).of(cc.toUpperCase()); } catch { /* old browser */ }
    return name || cc || '';
  };

  function parseTrace(text) {
    const out = {};
    for (const line of text.split('\n')) {
      const i = line.indexOf('=');
      if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return out;
  }

  // "cfL4;desc=\"?proto=TCP&rtt=3191...\", cfSpeedEdge;dur=3" -> [{name, dur, desc, params}]
  function parseServerTiming(header) {
    if (!header) return [];
    return header.split(/,(?=\s*[A-Za-z][\w-]*\s*(?:;|,|$))/).map(part => {
      const [name, ...attrs] = part.trim().split(';');
      const item = { name: name.trim() };
      for (const a of attrs) {
        const i = a.indexOf('=');
        const k = a.slice(0, i).trim(); let v = a.slice(i + 1).trim().replace(/^"|"$/g, '');
        item[k] = k === 'dur' ? Number(v) : v;
        if (k === 'desc' && v.startsWith('?')) item.params = Object.fromEntries(new URLSearchParams(v.slice(1)));
      }
      return item;
    }).filter(x => x.name);
  }

  function tzOffsetMinutes(tz, when = new Date()) {
    try {
      const name = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' })
        .formatToParts(when).find(p => p.type === 'timeZoneName').value;
      const m = name.match(/GMT([+-])(\d{1,2}):?(\d{2})?/);
      return m ? (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3] || 0)) : 0;
    } catch { return null; }
  }
  const fmtOffset = (min) => min == null ? '?' : `UTC${min < 0 ? '−' : '+'}${String(Math.floor(Math.abs(min) / 60)).padStart(2, '0')}:${String(Math.abs(min) % 60).padStart(2, '0')}`;

  function isPrivateIp(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip)
      || /^(fe80:|fc|fd|::1$)/i.test(ip);
  }

  // Pull the browser's ResourceTiming entry for a URL and turn it into phases.
  function resourceTiming(url) {
    const entries = performance.getEntriesByName(url, 'resource');
    const e = entries[entries.length - 1];
    if (!e) return null;
    const t = {
      protocol: e.nextHopProtocol || null,
      startTime: e.startTime, duration: e.duration,
      transferSize: e.transferSize, encodedBodySize: e.encodedBodySize, decodedBodySize: e.decodedBodySize,
      serverTiming: (e.serverTiming || []).map(s => ({ name: s.name, duration: s.duration, description: s.description })),
      restricted: !e.requestStart,
    };
    if (!t.restricted) {
      const rel = (x) => x ? x - e.startTime : 0;
      t.phases = [
        ['Redirect', rel(e.redirectStart), e.redirectEnd - e.redirectStart],
        ['DNS lookup', rel(e.domainLookupStart), e.domainLookupEnd - e.domainLookupStart],
        ['TCP connect', rel(e.connectStart), (e.secureConnectionStart || e.connectEnd) - e.connectStart],
        ['TLS handshake', rel(e.secureConnectionStart), e.secureConnectionStart ? e.connectEnd - e.secureConnectionStart : 0],
        ['Waiting (TTFB)', rel(e.requestStart), e.responseStart - e.requestStart],
        ['Download', rel(e.responseStart), e.responseEnd - e.responseStart],
      ].map(([name, start, dur]) => ({ name, start: Math.max(0, start), duration: Math.max(0, dur || 0) }));
      t.connectionReused = (e.connectEnd - e.connectStart) === 0 && (e.domainLookupEnd - e.domainLookupStart) === 0;
    }
    return t;
  }

  // Fetch a URL and record everything the browser lets us see about it.
  async function tracked(src, myRun) {
    const url = src.bust === false ? src.url : bust(src.url);
    const rec = {
      id: src.id, label: src.label, purpose: src.purpose, url, method: src.method || 'GET',
      startedAt: new Date().toISOString(), status: null, statusText: null, ok: false,
      durationMs: null, headers: null, body: null, bodyText: null, error: null, timing: null,
    };
    const t0 = performance.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), src.timeout || 9000);
    try {
      const res = await fetch(url, { cache: 'no-store', signal: ctrl.signal, ...(src.init || {}) });
      rec.status = res.status; rec.statusText = res.statusText; rec.responseType = res.type;
      rec.redirected = res.redirected; rec.finalUrl = res.url;
      rec.headers = {}; res.headers.forEach((v, k) => { rec.headers[k] = v; });
      const text = await res.text();
      rec.durationMs = performance.now() - t0;
      rec.bodyText = text;
      rec.bodyBytes = new Blob([text]).size;
      if (src.parse === 'json') rec.body = JSON.parse(text);
      else if (src.parse === 'trace') rec.body = parseTrace(text);
      else if (src.parse === 'cfmeta') {
        rec.body = {};
        for (const [k, v] of Object.entries(rec.headers)) if (k.startsWith('cf-meta-')) rec.body[k.slice(8)] = v;
        rec.body.serverTiming = parseServerTiming(rec.headers['server-timing']);
      } else rec.body = text;
      rec.ok = res.ok;
    } catch (e) {
      rec.durationMs = performance.now() - t0;
      rec.error = e.name === 'AbortError' ? `Timed out after ${(src.timeout || 9000) / 1000}s` : (e.message || String(e));
    } finally {
      clearTimeout(timer);
    }
    rec.timing = resourceTiming(url);
    if (myRun === runId) addRecord(rec);
    return rec;
  }

  // Non-network findings (browser environment, WebRTC…) go in the deep dive too.
  function addData(id, label, purpose, body) {
    addRecord({ id, label, purpose, kind: 'data', ok: true, body, bodyText: JSON.stringify(body, null, 2) });
  }

  // ---------------------------------------------------------------- gatherers

  async function gatherEnv() {
    const n = navigator;
    const c = n.connection || n.mozConnection || n.webkitConnection;
    let uaData = null;
    if (n.userAgentData) {
      uaData = { brands: n.userAgentData.brands, mobile: n.userAgentData.mobile, platform: n.userAgentData.platform };
      try {
        Object.assign(uaData, await n.userAgentData.getHighEntropyValues(['platformVersion', 'architecture', 'bitness', 'model', 'fullVersionList']));
      } catch { /* denied */ }
    }
    let storage = null;
    try { storage = n.storage && await n.storage.estimate(); } catch { /* unavailable */ }
    const ro = Intl.DateTimeFormat().resolvedOptions();
    const mq = (q) => window.matchMedia && matchMedia(q).matches;
    return {
      browser: describeBrowser(n.userAgent, uaData),
      userAgent: n.userAgent,
      userAgentData: uaData,
      languages: n.languages ? [...n.languages] : [n.language],
      timeZone: ro.timeZone,
      locale: ro.locale,
      utcOffsetMinutes: -new Date().getTimezoneOffset(),
      localTime: new Date().toString(),
      screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, devicePixelRatio: window.devicePixelRatio },
      viewport: { width: innerWidth, height: innerHeight },
      hardware: { logicalCores: n.hardwareConcurrency ?? null, deviceMemoryGB: n.deviceMemory ?? null, maxTouchPoints: n.maxTouchPoints ?? null },
      connection: c ? { type: c.type ?? null, effectiveType: c.effectiveType ?? null, downlinkMbps: c.downlink ?? null, rttMs: c.rtt ?? null, saveData: c.saveData ?? null } : null,
      privacy: { cookiesEnabled: n.cookieEnabled, doNotTrack: n.doNotTrack ?? null, globalPrivacyControl: n.globalPrivacyControl ?? null, webdriver: n.webdriver ?? null },
      page: { online: n.onLine, secureContext: window.isSecureContext, protocol: location.protocol, origin: location.origin },
      preferences: { colorScheme: mq('(prefers-color-scheme: dark)') ? 'dark' : 'light', reducedMotion: !!mq('(prefers-reduced-motion: reduce)') },
      storageEstimate: storage ? { quotaBytes: storage.quota, usageBytes: storage.usage } : null,
    };
  }

  function describeBrowser(ua, uaData) {
    let name = null, version = null, os = null;
    if (uaData && uaData.brands) {
      const list = uaData.fullVersionList || uaData.brands;
      const real = list.filter(b => !/not.?a.?brand/i.test(b.brand));
      const pick = real.find(b => b.brand !== 'Chromium') || real[0];
      if (pick) { name = pick.brand.replace('Google ', '').replace('Microsoft ', ''); version = pick.version; }
      const p = uaData.platform, pv = uaData.platformVersion;
      if (p === 'Windows' && pv) os = Number(pv.split('.')[0]) >= 13 ? 'Windows 11' : 'Windows 10';
      else if (p === 'macOS' && pv) os = `macOS ${pv.split('.').slice(0, 2).join('.')}`;
      else if (p === 'Android' && pv) os = `Android ${pv.split('.')[0]}`;
      else if (p) os = p;
    }
    if (!name) {
      const rules = [[/Edg\/([\d.]+)/, 'Edge'], [/OPR\/([\d.]+)/, 'Opera'], [/Firefox\/([\d.]+)/, 'Firefox'],
        [/Chrome\/([\d.]+)/, 'Chrome'], [/Version\/([\d.]+).*Safari/, 'Safari']];
      for (const [re, n] of rules) { const m = ua.match(re); if (m) { name = n; version = m[1]; break; } }
    }
    if (!os) {
      if (/Windows NT 10/.test(ua)) os = 'Windows 10 or 11';
      else if (/Windows/.test(ua)) os = 'Windows';
      else if (/iPhone|iPad/.test(ua)) os = `iOS ${(ua.match(/OS (\d+)_/) || [])[1] || ''}`.trim();
      else if (/Mac OS X/.test(ua)) os = 'macOS';
      else if (/Android/.test(ua)) os = `Android ${(ua.match(/Android (\d+)/) || [])[1] || ''}`.trim();
      else if (/CrOS/.test(ua)) os = 'ChromeOS';
      else if (/Linux/.test(ua)) os = 'Linux';
    }
    const major = version ? version.split('.')[0] : '';
    return { name: name || 'Unknown browser', version: version || null, os: os || 'unknown OS', summary: `${name || 'Unknown browser'} ${major} on ${os || 'an unknown OS'}`.replace(/\s+/g, ' ') };
  }

  async function gatherWebRTC() {
    if (!window.RTCPeerConnection) return { supported: false, candidates: [] };
    const candidates = [];
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: STUN_SERVERS.map(urls => ({ urls })) });
      pc.createDataChannel('probe');
      pc.onicecandidate = (e) => {
        if (!e.candidate || !e.candidate.candidate) return;
        const raw = e.candidate.candidate;
        const parts = raw.split(' ');
        candidates.push({
          type: e.candidate.type || parts[7],
          protocol: e.candidate.protocol || parts[2],
          address: e.candidate.address || parts[4],
          port: e.candidate.port || Number(parts[5]),
          relatedAddress: e.candidate.relatedAddress || null,
          raw,
        });
      };
      const done = new Promise(resolve => {
        const t = setTimeout(resolve, 4000);
        pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); resolve(); } };
      });
      await pc.setLocalDescription(await pc.createOffer());
      await done;
    } catch (e) {
      return { supported: true, error: e.message || String(e), candidates };
    } finally {
      try { pc && pc.close(); } catch { /* ignore */ }
    }
    return { supported: true, stunServers: STUN_SERVERS, candidates };
  }

  async function probeOnce(url, timeout) {
    const u = bust(url);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    const t0 = performance.now();
    try {
      await fetch(u, { mode: 'no-cors', cache: 'no-store', signal: ctrl.signal });
      return { ok: true, ms: performance.now() - t0, timing: resourceTiming(u) };
    } catch (e) {
      return { ok: false, ms: performance.now() - t0, error: e.name === 'AbortError' ? 'timeout' : (e.message || 'network error') };
    } finally {
      clearTimeout(timer);
    }
  }

  async function runProbe(p) {
    const cold = await probeOnce(p.url, 7000);
    const warm = [];
    if (cold.ok) for (let i = 0; i < 3; i++) warm.push(await probeOnce(p.url, 5000));
    const warmMs = warm.filter(w => w.ok).map(w => w.ms);
    const jitter = warmMs.length > 1 ? warmMs.slice(1).reduce((a, x, i) => a + Math.abs(x - warmMs[i]), 0) / (warmMs.length - 1) : null;
    return {
      name: p.name, url: p.url, host: hostOf(p.url),
      reachable: cold.ok, error: cold.error || null,
      coldMs: cold.ms, warmMedianMs: median(warmMs), jitterMs: jitter,
      samples: [cold, ...warm].map((s, i) => ({ attempt: i === 0 ? 'cold' : `warm ${i}`, ok: s.ok, ms: Math.round(s.ms * 10) / 10, error: s.error })),
    };
  }

  // ---------------------------------------------------------------- derived view

  function derive() {
    const s = state.sources;
    const b = (id) => s[id] && s[id].ok ? s[id].body : null;
    const ipv4 = b('ipv4'), ipv6 = b('ipv6'), who = b('ipwho'), iis = b('ipapiis'), trace = b('trace'), meta = b('cfmeta');
    const whoOk = who && who.success !== false ? who : null;

    const geo = [];
    if (whoOk) geo.push({ source: 'ipwho.is', city: whoOk.city, region: whoOk.region, country: whoOk.country, cc: whoOk.country_code, lat: whoOk.latitude, lon: whoOk.longitude, tz: whoOk.timezone && whoOk.timezone.id });
    if (iis) {
      const loc = iis.location || iis;
      geo.push({ source: 'ipapi.is', city: loc.city, region: loc.state || loc.region, country: loc.country, cc: loc.country_code, lat: loc.latitude ?? loc.lat, lon: loc.longitude ?? loc.lon, tz: loc.timezone });
    }
    if (meta && (meta.city || meta.country)) geo.push({ source: 'Cloudflare', city: meta.city, region: meta.region, country: meta.country, cc: meta.country, lat: meta.latitude, lon: meta.longitude, tz: meta.timezone });
    const primary = geo.find(g => g.city) || geo[0] || null;

    const asnStr = (() => {
      if (whoOk && whoOk.connection && whoOk.connection.asn) return `AS${whoOk.connection.asn}`;
      if (iis && iis.asn) return typeof iis.asn === 'object' ? `AS${iis.asn.asn}` : String(iis.asn).split(' ')[0];
      if (meta && meta.asn) return `AS${meta.asn}`;
      return null;
    })();
    const isp = (whoOk && whoOk.connection && (whoOk.connection.isp || whoOk.connection.org))
      || (iis && typeof iis.asn === 'object' && iis.asn.org)
      || (iis && typeof iis.asn === 'string' && iis.asn.replace(/^AS\d+\s*/, ''))
      || (iis && (typeof iis.company === 'object' ? iis.company.name : iis.company)) || null;

    const seenIps = {};
    const addIp = (src, ip) => { if (ip) (seenIps[ip] = seenIps[ip] || []).push(src); };
    addIp('ipify', ipv4 && ipv4.ip); addIp('ipwho.is', whoOk && whoOk.ip); addIp('ipapi.is', iis && iis.ip);
    addIp('Cloudflare trace', trace && trace.ip); addIp('Cloudflare speed', meta && meta.ip);

    const publicV4 = (ipv4 && ipv4.ip) || Object.keys(seenIps).find(ip => ip.includes('.')) || null;
    const publicV6 = (ipv6 && ipv6.ip) || Object.keys(seenIps).find(ip => ip.includes(':')) || null;

    const l4 = meta && meta.serverTiming && meta.serverTiming.find(x => x.name === 'cfL4');
    const serverRttMs = l4 && l4.params && l4.params.rtt ? Number(l4.params.rtt) / 1000 : null;

    return { ipv4, ipv6, who: whoOk, iis, trace, meta, geo, primary, asnStr, isp, seenIps, publicV4, publicV6, serverRttMs };
  }

  // ---------------------------------------------------------------- rendering: summary

  function card(label, value, note, opts = {}) {
    return el('div', { class: 'card' },
      el('div', { class: 'card-label' }, label),
      el('div', { class: 'card-value' + (opts.mono ? ' mono' : '') + (opts.ip ? ' ip' : '') }, value ?? el('span', { class: 'skeleton' })),
      note ? el('div', { class: 'card-note' }, note) : null);
  }

  const settled = (id) => !!state.sources[id];

  function renderSummary() {
    const d = derive();
    const env = state.env;
    const probes = state.probes;

    // Headline
    const headline = $('#headline');
    const sub = $('#subline');
    headline.replaceChildren();
    const allSourcesDone = SOURCES.every(s => settled(s.id));
    if (!d.publicV4 && !d.publicV6 && allSourcesDone) {
      headline.append('We couldn\'t reach any of the lookup services. You may be offline, or something (a firewall, captive portal or content blocker) is stopping these requests.');
    } else if (!d.publicV4 && !d.publicV6) {
      headline.append('Checking your connection…');
    } else {
      headline.append('You\'re online');
      if (d.isp) headline.append(' via ', el('strong', null, d.isp));
      if (d.primary && d.primary.city) headline.append(' from around ', el('strong', null, [d.primary.city, d.primary.region, d.primary.country].filter(Boolean).join(', ')));
      headline.append('. Your public IP address is ', el('strong', { class: 'ip' }, d.publicV4 || d.publicV6), '.');
    }
    const bits = [];
    if (probes) {
      const ok = probes.filter(p => p.reachable).length;
      bits.push(`${ok} of ${probes.length} services reachable`);
      const med = median(probes.filter(p => p.warmMedianMs != null).map(p => p.warmMedianMs));
      if (med != null) bits.push(`typical latency ${fmtMs(med)}`);
    } else bits.push('testing reachability…');
    if (settled('ipv6')) bits.push(d.publicV6 ? 'IPv6 working' : 'no IPv6');
    sub.textContent = bits.join(' · ');

    const dot = document.querySelector('.brand-dot');
    dot.className = 'brand-dot';
    if (probes) {
      const ok = probes.filter(p => p.reachable).length;
      dot.classList.add(ok === probes.length ? 'ok' : ok === 0 ? 'bad' : 'warn');
    }

    // Cards
    const g = $('#glance');
    const cards = [];

    cards.push(card('Public IP address', d.publicV4 || d.publicV6 || (settled('ipv4') && settled('trace') ? 'Unknown' : null),
      settled('ipv6') ? (d.publicV6 && d.publicV4 ? `IPv6: ${d.publicV6}` : d.publicV6 ? 'IPv6 only' : 'No IPv6 connectivity detected') : 'Checking IPv6…', { mono: true, ip: true }));

    const p = d.primary;
    const others = d.geo.filter(x => x !== p && x.city).map(x => `${x.source}: ${x.city}`);
    let locNote = null;
    if (p) {
      locNote = el('span', null,
        others.length ? `Other sources: ${others.join(' · ')}. ` : `Source: ${p.source}. `,
        p.lat != null && p.lon != null ? el('a', { href: `https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=11/${p.lat}/${p.lon}`, target: '_blank', rel: 'noopener' }, 'View on map') : null);
    }
    cards.push(card('Approximate location',
      p ? `${flag(p.cc)} ${[p.city, p.region].filter(Boolean).join(', ') || p.country}`.trim() : (settled('ipwho') && settled('ipapiis') ? 'Unknown' : null),
      p ? el('span', null, p.country ? `${p.country}. ` : '', locNote) : 'Based on your IP, not GPS — usually city-level at best.'));

    const domain = d.who && d.who.connection && d.who.connection.domain;
    cards.push(card('Internet provider', d.isp || (settled('ipwho') && settled('ipapiis') ? 'Unknown' : null),
      [d.asnStr, domain].filter(Boolean).join(' · ') || null));

    if (env) {
      const ipTz = d.primary && d.primary.tz;
      cards.push(card('Time zone', env.timeZone,
        ipTz ? (ipTz === env.timeZone ? `Matches your IP's location (${fmtOffset(env.utcOffsetMinutes)}).` : `Your IP suggests ${ipTz} (${fmtOffset(tzOffsetMinutes(ipTz))}); your device says ${fmtOffset(env.utcOffsetMinutes)}.`) : fmtOffset(env.utcOffsetMinutes)));
      cards.push(card('Device', env.browser.summary,
        `${env.languages.slice(0, 3).join(', ')} · ${env.screen.width}×${env.screen.height} @${env.screen.devicePixelRatio}x`));
      const c = env.connection;
      cards.push(card('Connection estimate', c && c.effectiveType ? `${c.effectiveType.toUpperCase()}${c.type ? ' · ' + c.type : ''}` : 'Not reported',
        c && c.effectiveType ? `Browser estimate: ~${c.downlinkMbps} Mbps, ${c.rttMs ? `~${c.rttMs} ms` : 'under 25 ms'} RTT${c.saveData ? ', data saver on' : ''}.` : 'This browser doesn\'t expose the Network Information API.'));
    } else {
      cards.push(card('Time zone', null), card('Device', null), card('Connection estimate', null));
    }

    const t = d.trace;
    cards.push(card('Cloudflare edge', t ? (t.colo || '—') : (settled('trace') ? 'Unreachable' : null),
      t ? [t.http && t.http.toUpperCase(), t.tls, t.warp && t.warp !== 'off' ? `WARP ${t.warp}` : null].filter(Boolean).join(' · ') : null));

    cards.push(card('Round-trip time',
      d.serverRttMs != null ? fmtMs(d.serverRttMs) : (settled('cfmeta') ? '—' : null),
      d.serverRttMs != null ? 'TCP RTT measured by Cloudflare\'s server — the cleanest latency figure here.' : 'Server-side RTT not available.'));

    g.replaceChildren(...cards);
    renderSignals(d);
  }

  function renderSignals(d) {
    const out = [];
    const add = (level, title, text) => out.push(el('li', { class: 'signal' }, el('span', { class: `dot ${level}` }), el('div', null, el('b', null, title), text ? ' — ' + text : '')));
    const env = state.env;

    // Same IP everywhere?
    const v4s = Object.keys(d.seenIps).filter(ip => ip.includes('.'));
    if (v4s.length > 1) add('warn', 'Different services see different IPv4 addresses', v4s.map(ip => `${ip} (${d.seenIps[ip].join(', ')})`).join('; ') + '. Common with load-balanced proxies, VPN split tunnels, or multi-WAN routers.');
    else if (v4s.length === 1 && Object.values(d.seenIps)[0].length > 1) add('ok', 'Consistent public IP', `${Object.values(d.seenIps).reduce((a, x) => a + x.length, 0)} services agree on your address.`);

    // Hosting / VPN flags (when ipapi.is provides them)
    const iis = d.iis;
    if (iis) {
      const flags = ['is_vpn', 'is_proxy', 'is_tor', 'is_datacenter', 'is_abuser', 'is_crawler'].filter(k => iis[k] === true);
      const known = ['is_vpn', 'is_proxy', 'is_tor', 'is_datacenter'].some(k => typeof iis[k] === 'boolean');
      if (flags.length) add('warn', 'IP flagged by ipapi.is', flags.map(f => f.replace('is_', '')).join(', ') + '.');
      else if (known) add('ok', 'No VPN, proxy, Tor or datacenter flags', 'According to ipapi.is.');
      if (iis.is_mobile === true) add('info', 'Mobile carrier network', 'Your IP belongs to a cellular provider.');
      const ctype = (iis.company && iis.company.type) || (iis.asn && iis.asn.type);
      if (ctype === 'hosting') add('warn', 'Hosting-provider IP', 'Your traffic exits from a datacenter network, which is typical of VPNs, proxies and cloud machines.');
    }

    // Cloudflare WARP / Gateway
    if (d.trace) {
      if (d.trace.warp && d.trace.warp !== 'off') add('info', `Cloudflare WARP is ${d.trace.warp}`, 'Your traffic is going through Cloudflare\'s VPN.');
      if (d.trace.gateway && d.trace.gateway !== 'off') add('info', 'Cloudflare Gateway is active', 'A Cloudflare Zero Trust policy is filtering your traffic.');
    }

    // Time zone vs IP
    if (env && d.primary && d.primary.tz) {
      const ipOff = tzOffsetMinutes(d.primary.tz);
      if (d.primary.tz === env.timeZone) add('ok', 'Time zone matches your IP location', env.timeZone);
      else if (ipOff === env.utcOffsetMinutes) add('ok', 'Time zone offset matches your IP location', `${env.timeZone} and ${d.primary.tz} are both ${fmtOffset(ipOff)} right now.`);
      else add('warn', 'Time zone doesn\'t match your IP location', `Device: ${env.timeZone} (${fmtOffset(env.utcOffsetMinutes)}), IP: ${d.primary.tz} (${fmtOffset(ipOff)}). Often a sign of a VPN or proxy in another region — or travel.`);
    }

    // Geolocation agreement
    const cities = [...new Set(d.geo.map(g => g.city).filter(Boolean))];
    const countries = [...new Set(d.geo.map(g => countryName(g.cc, g.country).toLowerCase()).filter(Boolean))];
    if (countries.length > 1) add('warn', 'Location providers disagree on your country', d.geo.map(g => `${g.source}: ${g.country || g.cc}`).join(' · '));
    else if (cities.length > 1) add('info', 'Location providers disagree on your city', `${d.geo.filter(g => g.city).map(g => `${g.source}: ${g.city}`).join(' · ')}. IP geolocation is approximate — this is normal.`);

    // WebRTC
    const rtc = state.webrtc;
    if (rtc) {
      if (!rtc.supported) add('info', 'WebRTC not available', 'This browser can\'t reveal addresses through WebRTC.');
      else {
        const srflx = [...new Set(rtc.candidates.filter(c => c.type === 'srflx').map(c => c.address))];
        const hostRaw = [...new Set(rtc.candidates.filter(c => c.type === 'host' && c.address && !c.address.endsWith('.local')).map(c => c.address))];
        const known = new Set(Object.keys(d.seenIps));
        const leak = srflx.filter(ip => !known.has(ip) && !(d.publicV6 && ip.includes(':')));
        if (leak.length && known.size) add('warn', 'WebRTC reveals a different public IP', `${leak.join(', ')}. If you use a VPN, it may be leaking around it.`);
        else if (srflx.length) add('ok', 'WebRTC sees the same public IP', 'No WebRTC leak detected.');
        else add('info', 'WebRTC STUN lookup returned nothing', 'UDP may be blocked, or WebRTC is restricted by your browser or network.');
        const priv = hostRaw.filter(isPrivateIp);
        if (priv.length) add('info', 'WebRTC exposes your local network address', `${priv.join(', ')}. Most modern browsers hide this behind an mDNS name.`);
        else if (rtc.candidates.some(c => c.type === 'host')) add('ok', 'Local network address is hidden', 'Your browser masks it with an mDNS name.');
      }
    }

    // Transport
    if (d.trace && d.trace.http) {
      const http = d.trace.http.toLowerCase();
      if (http === 'http/3') add('ok', 'HTTP/3 (QUIC) works', 'UDP 443 is open and your browser negotiated QUIC with Cloudflare.');
      else if (http === 'http/2') add('info', 'Connected over HTTP/2', 'HTTP/3 may still be available — browsers often upgrade on later requests.');
      else add('info', `Connected over ${d.trace.http}`, 'Something between you and Cloudflare may be proxying or downgrading connections.');
    }

    if (env) {
      if (env.privacy.globalPrivacyControl) add('info', 'Global Privacy Control is on', 'Your browser asks sites not to sell or share your data.');
      if (env.privacy.webdriver) add('info', 'Automated browser', 'navigator.webdriver is true — this browser is being driven by software.');
      if (location.protocol === 'file:') add('info', 'Opened as a local file', 'Everything still works, but serving over http://localhost gives the most consistent results.');
    }

    if (!out.length) out.push(el('li', { class: 'signal' }, el('span', { class: 'dot pending' }), el('div', { class: 'muted' }, 'Gathering signals…')));
    $('#signals').replaceChildren(...out);
  }

  function renderProbes() {
    const rows = PROBES.map((p, i) => {
      const r = state.probes && state.probes[i] || state.probeProgress && state.probeProgress[i];
      if (!r) return el('tr', null, el('td', null, p.name), el('td', null, el('span', { class: 'status' }, el('span', { class: 'dot pending' }), 'Testing…')), el('td', { class: 'num' }, '—'), el('td', { class: 'num' }, '—'), el('td', { class: 'num' }, '—'), el('td', { class: 'host' }, hostOf(p.url)));
      const level = !r.reachable ? 'bad' : (r.warmMedianMs ?? r.coldMs) > 300 ? 'warn' : 'ok';
      return el('tr', null,
        el('td', null, r.name),
        el('td', null, el('span', { class: 'status' }, el('span', { class: `dot ${level}` }), r.reachable ? 'Reachable' : `Failed (${r.error})`)),
        el('td', { class: 'num' }, fmtMs(r.coldMs)),
        el('td', { class: 'num' }, fmtMs(r.warmMedianMs)),
        el('td', { class: 'num' }, fmtMs(r.jitterMs)),
        el('td', { class: 'host' }, r.host));
    });
    $('#probe-rows').replaceChildren(...rows);
  }

  // ---------------------------------------------------------------- rendering: deep dive

  function kv(obj) {
    const dl = el('dl', { class: 'kv' });
    for (const [k, v] of Object.entries(obj)) {
      if (v == null || v === '') continue;
      dl.append(el('dt', null, k), el('dd', null, v instanceof Node ? v : String(v)));
    }
    return dl;
  }

  function jsonTree(value, key, depth = 0) {
    const keyEl = key !== undefined ? [el('span', { class: 'k' }, typeof key === 'number' ? key : JSON.stringify(key)), ': '] : [];
    if (value && typeof value === 'object') {
      const isArr = Array.isArray(value);
      const entries = isArr ? value.map((x, i) => [i, x]) : Object.entries(value);
      const d = el('details', { open: depth < 2 });
      d.append(el('summary', null, keyEl, el('span', { class: 'c' }, isArr ? `[${entries.length}]` : `{${entries.length}}`)));
      for (const [k, x] of entries) d.append(jsonTree(x, k, depth + 1));
      return d;
    }
    let v;
    if (typeof value === 'string') v = el('span', { class: 's' }, JSON.stringify(value));
    else if (typeof value === 'number') v = el('span', { class: 'n' }, String(value));
    else if (typeof value === 'boolean') v = el('span', { class: 'b' }, String(value));
    else v = el('span', { class: 'z' }, 'null');
    return el('div', { class: 'row' }, keyEl, v);
  }

  function timingPanel(t, rec) {
    const wrap = el('div');
    if (t.restricted) {
      wrap.append(el('p', { class: 'note' }, `The server didn't send a Timing-Allow-Origin header, so the browser hides the DNS / TCP / TLS breakdown. Total time as measured by the browser: ${fmtMs(t.duration)}.`));
    } else {
      const total = Math.max(t.duration, 1);
      const wf = el('div', { class: 'wf' });
      for (const ph of t.phases) {
        wf.append(el('div', { class: 'wf-row' },
          el('span', null, ph.name),
          el('div', { class: 'wf-track' }, el('span', { class: 'wf-seg', style: `left:${(ph.start / total) * 100}%;width:${(ph.duration / total) * 100}%` })),
          el('span', { class: 'num' }, fmtMs(ph.duration))));
      }
      wrap.append(wf);
      if (t.connectionReused) wrap.append(el('p', { class: 'note' }, 'DNS and connect took 0 ms: the browser reused an existing connection to this host.'));
    }
    wrap.append(el('div', { style: 'margin-top:12px' }, kv({
      'Protocol': t.protocol || (t.restricted ? 'hidden' : null),
      'Total duration': fmtMs(t.duration),
      'Fetch round trip': rec && rec.durationMs != null ? fmtMs(rec.durationMs) : null,
      'Transfer size': t.transferSize ? fmtBytes(t.transferSize) : null,
      'Encoded body': t.encodedBodySize ? fmtBytes(t.encodedBodySize) : null,
      'Decoded body': t.decodedBodySize ? fmtBytes(t.decodedBodySize) : null,
    })));
    if (t.serverTiming && t.serverTiming.length) {
      wrap.append(el('p', { class: 'note' }, 'Server-Timing reported by the server:'),
        kv(Object.fromEntries(t.serverTiming.map(s => [s.name, [s.duration ? `${s.duration} ms` : '', s.description].filter(Boolean).join(' ') || '(no value)']))));
    }
    return wrap;
  }

  function headersPanel(rec) {
    const wrap = el('div');
    const entries = Object.entries(rec.headers || {});
    wrap.append(entries.length ? kv(Object.fromEntries(entries)) : el('p', { class: 'note' }, 'No headers visible.'));
    wrap.append(el('p', { class: 'note' }, 'Browsers only show cross-origin response headers that are CORS-safelisted or that the server lists in Access-Control-Expose-Headers, so this may be a subset of what was actually sent.'));
    return wrap;
  }

  function rawPanel(text) {
    const pre = el('pre', { class: 'raw' }, text);
    const btn = el('button', { class: 'btn btn-small', type: 'button' }, 'Copy');
    btn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; } catch { btn.textContent = 'Copy failed'; }
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
    return el('div', null, el('div', { class: 'copy-row' }, btn), pre);
  }

  function renderRecord(rec) {
    const panels = [];
    const overview = kv({
      'What this is': rec.purpose,
      'URL': rec.url,
      'Method': rec.kind === 'data' ? null : rec.method,
      'Status': rec.status != null ? `${rec.status} ${rec.statusText || ''}`.trim() : null,
      'Error': rec.error,
      'Response type': rec.responseType,
      'Final URL': rec.finalUrl && rec.finalUrl !== rec.url ? rec.finalUrl : null,
      'Round trip': rec.durationMs != null ? fmtMs(rec.durationMs) : null,
      'Body size': rec.bodyBytes != null ? fmtBytes(rec.bodyBytes) : null,
      'Started': rec.startedAt,
    });
    if (rec.error && rec.kind !== 'data') {
      overview.append(el('dt', null, 'Likely cause'), el('dd', null, el('span', { class: 'hint' },
        /timed out/i.test(rec.error) ? 'The server didn\'t answer in time — a slow or filtered network, or the service is down.'
          : 'The browser blocked or couldn\'t complete the request: offline, DNS failure, firewall, content blocker, or (for IPv6) no IPv6 route.')));
    }
    panels.push(['Overview', overview]);
    if (rec.timing) panels.push(['Timing', timingPanel(rec.timing, rec)]);
    if (rec.headers) panels.push(['Headers', headersPanel(rec)]);
    if (rec.body && typeof rec.body === 'object') panels.push(['Parsed', el('div', { class: 'tree' }, jsonTree(rec.body))]);
    if (rec.bodyText != null && rec.bodyText !== '') panels.push(['Raw', rawPanel(rec.bodyText)]);

    const tabs = el('div', { class: 'tabs', role: 'tablist' });
    const body = el('div', { class: 'req-body' }, tabs);
    panels.forEach(([name, content], i) => {
      const panel = el('div', { class: 'tab-panel', role: 'tabpanel', hidden: i !== 0 }, content);
      const tab = el('button', { class: 'tab', type: 'button', role: 'tab', 'aria-selected': i === 0 ? 'true' : 'false' }, name);
      tab.addEventListener('click', () => {
        tabs.querySelectorAll('.tab').forEach(t => t.setAttribute('aria-selected', 'false'));
        body.querySelectorAll('.tab-panel').forEach(p => { p.hidden = true; });
        tab.setAttribute('aria-selected', 'true'); panel.hidden = false;
      });
      tabs.append(tab); body.append(panel);
    });

    const pill = rec.kind === 'data'
      ? el('span', { class: 'pill' }, 'local')
      : el('span', { class: 'pill ' + (rec.ok ? 'ok' : 'bad') }, rec.status != null ? rec.status : 'failed');
    return el('details', { class: 'req', 'data-id': rec.id },
      el('summary', null,
        el('span', { class: 'req-name' }, rec.label), pill,
        el('span', { class: 'req-meta' },
          rec.url ? el('span', null, hostOf(rec.url)) : null,
          rec.durationMs != null ? el('span', null, fmtMs(rec.durationMs)) : null)),
      body);
  }

  function addRecord(rec) {
    const i = state.requests.findIndex(r => r.id === rec.id);
    if (i >= 0) state.requests[i] = rec; else state.requests.push(rec);
    const node = renderRecord(rec);
    const old = deepEls.get(rec.id);
    if (old) { node.open = old.open; old.replaceWith(node); } else $('#deep').append(node);
    deepEls.set(rec.id, node);
  }

  // ---------------------------------------------------------------- speed test

  async function timedDownload(bytes, onProgress) {
    const url = bust(`${SPEED}/__down?bytes=${bytes}`);
    const t0 = performance.now();
    const res = await fetch(url, { cache: 'no-store' });
    const reader = res.body.getReader();
    let got = 0, tFirst = null;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (tFirst == null) tFirst = performance.now();
      got += value.length;
      onProgress && onProgress(got, performance.now() - t0);
    }
    const t1 = performance.now();
    const timing = resourceTiming(url);
    // Measure from first byte so connection setup doesn't drag the number down.
    const ms = timing && !timing.restricted ? timing.phases.find(p => p.name === 'Download').duration || (t1 - t0) : (t1 - (tFirst || t0));
    return { bytes: got, ms, mbps: (got * 8) / (ms / 1000) / 1e6, colo: res.headers.get('cf-meta-colo') };
  }

  async function timedUpload(bytes) {
    const data = new Uint8Array(bytes);
    const url = bust(`${SPEED}/__up`);
    const t0 = performance.now();
    const res = await fetch(url, { method: 'POST', body: data, cache: 'no-store' });
    await res.text();
    const ms = performance.now() - t0;
    // Subtract the server's own processing time when it reports it.
    const st = parseServerTiming(res.headers.get('server-timing'));
    const serverMs = st.filter(s => s.dur).reduce((a, s) => Math.max(a, s.dur), 0);
    const net = Math.max(ms - serverMs, 1);
    return { bytes, ms: net, mbps: (bytes * 8) / (net / 1000) / 1e6 };
  }

  // Small transfers are dominated by timer noise, so judge on the 1 MB+ runs when there are any.
  function bestMbps(runs) {
    const big = runs.filter(r => r.bytes >= 1e6);
    return Math.max(...(big.length ? big : runs).map(r => r.mbps));
  }

  async function runSpeedTest() {
    const btn = $('#btn-speed');
    const status = $('#speed-status');
    btn.disabled = true;
    const result = { startedAt: new Date().toISOString(), latency: [], download: [], upload: [] };
    const show = (id, v, unit) => { $(id).replaceChildren(v, unit ? el('small', null, unit) : ''); };
    try {
      status.textContent = 'Measuring idle latency…';
      for (let i = 0; i < 8; i++) {
        const url = bust(`${SPEED}/__down?bytes=0`);
        const t0 = performance.now();
        const res = await fetch(url, { cache: 'no-store' }); await res.arrayBuffer();
        const st = parseServerTiming(res.headers.get('server-timing'));
        const serverMs = st.filter(s => s.dur).reduce((a, s) => Math.max(a, s.dur), 0);
        const ms = performance.now() - t0 - serverMs;
        if (i > 0) result.latency.push(Math.max(ms, 0)); // first one pays for connection setup
        if (!result.colo) result.colo = res.headers.get('cf-meta-colo');
      }
      if (!result.colo) { const t = derive().trace; result.colo = t && t.colo; }
      const lat = median(result.latency);
      show('#sp-lat', lat < 10 ? lat.toFixed(1) : Math.round(lat), 'ms');
      show('#sp-colo', result.colo || '—');

      for (const size of [1e5, 1e6, 1e7, 2.5e7]) {
        status.textContent = `Downloading ${fmtBytes(size)}…`;
        const r = await timedDownload(size, (got, ms) => {
          if (size >= 1e6 && ms > 200) show('#sp-down', ((got * 8) / (ms / 1000) / 1e6).toFixed(1), 'Mbps');
        });
        result.download.push(r);
        if (r.ms > 8000) break; // slow link: don't drag it out
      }
      const down = bestMbps(result.download);
      show('#sp-down', down.toFixed(1), 'Mbps');

      for (const size of [1e5, 1e6, 2e6, 5e6]) {
        status.textContent = `Uploading ${fmtBytes(size)}…`;
        const r = await timedUpload(size);
        result.upload.push(r);
        if (size >= 1e6) show('#sp-up', r.mbps.toFixed(1), 'Mbps');
        if (r.ms > 8000) break;
      }
      const up = bestMbps(result.upload);
      show('#sp-up', up.toFixed(1), 'Mbps');

      result.summary = { downloadMbps: +down.toFixed(2), uploadMbps: +up.toFixed(2), idleLatencyMs: +lat.toFixed(1), server: result.colo };
      status.textContent = `Done. Download ${down.toFixed(1)} Mbps, upload ${up.toFixed(1)} Mbps, latency ${fmtMs(lat)}${result.colo ? ` via Cloudflare ${result.colo}` : ''}.`;
    } catch (e) {
      result.error = e.message || String(e);
      status.textContent = `Speed test stopped: ${result.error}`;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Run speed test again';
      state.speed = result;
      addData('speed', 'Speed test', 'Every latency sample and each download/upload, with the throughput computed from it. Download time is measured from the first byte; upload time has server processing time subtracted.', result);
    }
  }

  // ---------------------------------------------------------------- DNS lookup

  const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 43: 'DS', 46: 'RRSIG', 48: 'DNSKEY', 65: 'HTTPS', 257: 'CAA' };
  const RCODES = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
  let dnsSeq = 0;

  async function runDns(name, type) {
    const out = $('#dns-out');
    const q = encodeURIComponent(name);
    const resolvers = [
      { label: 'Google Public DNS', url: `https://dns.google/resolve?name=${q}&type=${type}` },
      { label: 'Cloudflare 1.1.1.1', url: `https://cloudflare-dns.com/dns-query?name=${q}&type=${type}`, init: { headers: { accept: 'application/dns-json' } } },
    ];
    out.replaceChildren(...resolvers.map(r => el('div', { class: 'card' }, el('h3', null, r.label), el('span', { class: 'skeleton' }))));
    const seq = ++dnsSeq;
    const recs = await Promise.all(resolvers.map((r, i) => tracked({
      id: `dns-${seq}-${i}`, label: `DNS ${type} ${name} — ${r.label}`, url: r.url, init: r.init, parse: 'json', bust: false,
      purpose: 'A DNS-over-HTTPS query. "AD: true" means the resolver validated the answer with DNSSEC.',
    }, runId)));
    out.replaceChildren(...recs.map((rec, i) => {
      const b = rec.body;
      const head = el('h3', null, resolvers[i].label, el('span', { class: 'muted small' }, rec.ok && b ? `${RCODES[b.Status] || b.Status}${b.AD ? ' · DNSSEC ✓' : ''} · ${fmtMs(rec.durationMs)}` : 'failed'));
      if (!rec.ok || !b) return el('div', { class: 'card' }, head, el('p', { class: 'note' }, rec.error || `HTTP ${rec.status}`));
      const ans = (b.Answer || []);
      const list = ans.length
        ? el('ul', null, ans.map(a => el('li', null, `${DNS_TYPES[a.type] || a.type}  ${a.data}`, el('span', { class: 'muted' }, `  ttl ${a.TTL}`))))
        : el('p', { class: 'note' }, b.Status === 3 ? 'This name does not exist.' : 'No records of this type.');
      return el('div', { class: 'card' }, head, list);
    }));
  }

  // ---------------------------------------------------------------- orchestration

  async function runProbes(myRun) {
    state.probes = null;
    state.probeProgress = [];
    renderProbes();
    const results = await Promise.all(PROBES.map((p, i) => runProbe(p).then(r => {
      if (myRun !== runId) return r;
      state.probeProgress[i] = r; renderProbes(); return r;
    })));
    if (myRun !== runId) return;
    state.probes = results;
    renderProbes();
    addData('probes', 'Reachability probes', 'Opaque (no-cors) requests: the reply can\'t be read, but a completed request proves DNS, TCP, TLS and HTTP all worked. The cold attempt includes connection setup; warm attempts reuse it.', results);
    renderSummary();
  }

  async function run() {
    const myRun = ++runId;
    state = freshState();
    deepEls.clear();
    $('#deep').replaceChildren();
    $('#btn-rerun').disabled = true;
    renderSummary();
    renderProbes();

    const jobs = [
      gatherEnv().then(env => {
        if (myRun !== runId) return;
        state.env = env;
        addData('env', 'Browser environment', 'What your browser reports about itself to any website you visit — no network request involved.', env);
        renderSummary();
      }),
      ...SOURCES.map(src => tracked(src, myRun).then(rec => {
        if (myRun !== runId) return;
        state.sources[src.id] = rec;
        renderSummary();
      })),
      gatherWebRTC().then(rtc => {
        if (myRun !== runId) return;
        state.webrtc = rtc;
        addData('webrtc', 'WebRTC ICE candidates', 'Addresses your browser would offer to a peer for a video call. "srflx" candidates are your public IP as seen by a STUN server over UDP; "host" candidates are local interfaces (usually hidden as *.local).', rtc);
        renderSummary();
      }),
      runProbes(myRun),
    ];
    await Promise.allSettled(jobs);
    if (myRun === runId) $('#btn-rerun').disabled = false;
  }

  function exportJson() {
    const report = {
      tool: 'Network Check', generatedAt: new Date().toISOString(), page: location.href,
      summary: (() => { const d = derive(); return { publicIPv4: d.publicV4, publicIPv6: d.publicV6, isp: d.isp, asn: d.asnStr, location: d.primary, serverRttMs: d.serverRttMs }; })(),
      environment: state.env, webrtc: state.webrtc, probes: state.probes, speed: state.speed,
      requests: state.requests,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `network-check-${new Date().toISOString().replace(/[:.]/g, '-')}.json` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // Theme: follow the OS unless the viewer picks one.
  function applyTheme(t) {
    if (t) document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
  }
  try { applyTheme(localStorage.getItem('nc-theme')); } catch { /* storage blocked */ }
  $('#btn-theme').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme')
      || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('nc-theme', next); } catch { /* storage blocked */ }
  });

  $('#btn-rerun').addEventListener('click', run);
  $('#btn-export').addEventListener('click', exportJson);
  $('#btn-probe').addEventListener('click', () => runProbes(runId));
  $('#btn-speed').addEventListener('click', runSpeedTest);
  $('#dns-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = $('#dns-name').value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (name) runDns(name, $('#dns-type').value);
  });

  // Table of contents: keep its offset in step with the top bar, and mark the section in view.
  function setupToc() {
    const toc = $('.toc');
    const topbar = $('.topbar');
    const links = [...toc.querySelectorAll('a[href^="#"]')];
    const sections = links.map(a => document.getElementById(a.getAttribute('href').slice(1)));

    const syncTopbar = () => document.documentElement.style.setProperty('--topbar-h', `${topbar.offsetHeight}px`);
    syncTopbar();
    if (window.ResizeObserver) new ResizeObserver(syncTopbar).observe(topbar);

    let current = null;
    let queued = false;
    const update = () => {
      queued = false;
      const sticky = getComputedStyle(topbar).position === 'sticky' ? topbar.offsetHeight : 0;
      const line = sticky + toc.offsetHeight * (innerWidth <= 960 ? 1 : 0) + 40;
      let active = sections[0];
      for (const sec of sections) if (sec && sec.getBoundingClientRect().top <= line) active = sec;
      // At the very bottom, the last section wins even if it is short.
      if (innerHeight + scrollY >= document.documentElement.scrollHeight - 4) active = sections[sections.length - 1];
      if (active === current) return;
      current = active;
      links.forEach((a, i) => a.setAttribute('aria-current', sections[i] === active ? 'true' : 'false'));
      // In the horizontal (narrow-screen) bar, slide the active chip into view.
      const link = links[sections.indexOf(active)];
      if (toc.scrollWidth > toc.clientWidth) toc.scrollTo({ left: link.offsetLeft - 16, behavior: 'smooth' });
    };
    const queue = () => { if (!queued) { queued = true; requestAnimationFrame(update); } };
    addEventListener('scroll', queue, { passive: true });
    addEventListener('resize', queue);
    update();
  }

  setupToc();
  run();
})();
