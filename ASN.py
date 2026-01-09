# -*- coding: utf-8 -*-
import os
import re
import io
import json
import time
import hashlib
import socket
import logging
import random
import html
from typing import Optional, List, Dict, Tuple
from base64 import b64encode

import pandas as pd
import concurrent.futures
import streamlit as st

APP_NAME = "INSSIDE â€¢ IPRadar"
APP_VER = "2025.11"
HEUR_VER = "1.3"

st.set_page_config(page_title=APP_NAME, page_icon="ðŸ›°ï¸", layout="wide")

# =============== Seguridad: directorios con permisos restrictivos ===============
def _safe_mkdir(path):
    os.makedirs(path, exist_ok=True)
    try:
        if os.name != "nt":
            os.chmod(path, 0o700)
    except Exception:
        pass

CACHE_DIR = os.getenv("CACHE_DIR", ".cache_insside")
CDN_LISTS_DIR = os.path.join(CACHE_DIR, "cdn_ranges")
RUNS_DIR = os.path.join(CACHE_DIR, "runs")
_safe_mkdir(CACHE_DIR); _safe_mkdir(CDN_LISTS_DIR); _safe_mkdir(RUNS_DIR)

# =============== ParÃ¡metros (ENV) ===============
MAX_FILE_BYTES      = int(os.getenv("MAX_FILE_BYTES", str(5 * 1024 * 1024)))
MAX_LINES           = int(os.getenv("MAX_LINES", "100000"))
MAX_LINE_LEN        = int(os.getenv("MAX_LINE_LEN", "2048"))
MAX_ENTRIES_PER_RUN = int(os.getenv("MAX_ENTRIES_PER_RUN", "20000"))
MAX_THREADS_SLIDER  = int(os.getenv("MAX_THREADS_SLIDER", "40"))
GLOBAL_MAX_WORKERS  = int(os.getenv("GLOBAL_MAX_WORKERS", "50"))
EXCEL_MAX_ROWS      = int(os.getenv("EXCEL_MAX_ROWS", "50000"))
CACHE_TTL_SECONDS   = int(os.getenv("CACHE_TTL_SECONDS", str(24 * 3600)))
MIN_SECONDS_BETWEEN_RUNS = float(os.getenv("MIN_SECONDS_BETWEEN_RUNS", "5"))
MAX_CONSECUTIVE_ERRORS   = int(os.getenv("MAX_CONSECUTIVE_ERRORS", "80"))
READONLY = os.getenv("READONLY_NETWORK", "false").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# =============== BLOQUE LOGO ROBUSTO (extremo derecho topbar) ===============
LOGO_FORCE_PATH = ""  # Setea ruta absoluta si querÃ©s forzarla.

def find_logo_path() -> str:
    if LOGO_FORCE_PATH and os.path.exists(LOGO_FORCE_PATH):
        return LOGO_FORCE_PATH
    for p in ["logo_insside.png", os.path.join("assets","logo_insside.png"), os.path.join("static","logo_insside.png")]:
        ap = os.path.abspath(p)
        if os.path.exists(ap): return ap
    return ""

def load_logo_b64(abs_path: str) -> str:
    if not abs_path: return ""
    try:
        with open(abs_path, "rb") as f:
            return b64encode(f.read()).decode("ascii")
    except Exception:
        return ""

LOGO_ABS = find_logo_path()
LOGO_B64 = load_logo_b64(LOGO_ABS)
LOGO_HREF = ""  # opcional

diag_html = ""
if not LOGO_B64:
    search_paths = [
        LOGO_FORCE_PATH or "(no force path)",
        os.path.abspath("logo_insside.png"),
        os.path.abspath(os.path.join("assets", "logo_insside.png")),
        os.path.abspath(os.path.join("static", "logo_insside.png")),
    ]
    diag_html = f'<div style="color:#ff9f9f;font-size:.85rem;padding:4px 8px;">Logo no encontrado<br><small>ProbÃ© en:<br>{"<br>".join(search_paths)}</small></div>'

logo_html = ""
if LOGO_B64:
    img_tag = f'<img src="data:image/png;base64,{LOGO_B64}" alt="INSSIDE" height="40" style="display:block;max-height:40px;">'
    logo_html = f'<a href="{LOGO_HREF}" target="_blank" rel="noopener">{img_tag}</a>' if LOGO_HREF else img_tag

# =============== Defaults ===============
DEF = {
    "cdn": "Desconocido",
    "evidence": "Sin evidencia",
    "asn": "N/D",
    "as_name": "N/D",
    "prefix": "N/D",
    "rdns": "Sin rDNS",
    "cnames": "Sin CNAME",
}

# =============== Utilidades generales ===============
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SAFE_LINE_RE = re.compile(r"^[0-9A-Za-z.\-_\s#:/]+$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

def is_valid_ip(s: str) -> bool:
    if not IP_RE.match(s): return False
    try: return all(0 <= int(p) <= 255 for p in s.split("."))
    except: return False

def is_valid_host(h: str) -> bool:
    return bool(HOST_RE.match(h)) and "." in h

def normalize_entry(s: str) -> str:
    return s.strip().lower()

def sanitize_entry(s: str) -> Optional[str]:
    s = normalize_entry(s)
    if not s: return None
    if s.startswith(("http://", "https://")) or "@" in s or (":" in s and not is_valid_ip(s)):
        return None
    if is_valid_ip(s):
        return s
    if ".." in s: return None
    if is_valid_host(s) and all(1 <= len(part) <= 63 for part in s.split(".")):
        return s
    return None

def unique_preserve_order(items: List[str]) -> List[str]:
    seen = set(); out = []
    for x in items:
        nx = normalize_entry(x)
        if nx not in seen:
            seen.add(nx); out.append(x)
    return out

def safe_text(s: str) -> str:
    return re.sub(r"[^ -~]", " ", str(s))[:256].strip()

def k(ns: str, key: str) -> str:
    return f"{HEUR_VER}:{ns}:{key}"

def ck(key: str) -> str:
    return os.path.join(CACHE_DIR, hashlib.sha1(key.encode("utf-8")).hexdigest() + ".json")

def cache_get(key: str, ttl: int = CACHE_TTL_SECONDS):
    path = ck(key)
    try:
        if time.time() - os.path.getmtime(path) > ttl: return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def cache_set(key: str, obj) -> None:
    try:
        with open(ck(key), "w", encoding="utf-8") as f:
            json.dump(obj, f)
    except Exception:
        pass

def safe_fetch(url: str, timeout: float = 10.0, max_bytes: int = 1_000_000) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "insside-ipradar/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(max_bytes)
    return data

def with_retries(fn, *a, retries=2, base=0.7, **kw):
    for i in range(retries+1):
        try:
            return fn(*a, **kw)
        except Exception:
            time.sleep(base*(2**i) + random.random()*0.2)
    return None

# =============== DNS ===============
def dns_resolve(host: str) -> Tuple[List[str], List[str]]:
    addrs, cnames = [], []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if is_valid_ip(ip) and ip not in addrs:
                addrs.append(ip)
    except Exception:
        pass
    try:
        _, aliaslist, addrlist = socket.gethostbyname_ex(host)
        cnames.extend(aliaslist)
        for ip in addrlist:
            if is_valid_ip(ip) and ip not in addrs:
                addrs.append(ip)
    except Exception:
        pass
    return addrs, list(dict.fromkeys(cnames))

def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""

# =============== ASN HTTP ===============
def asn_via_bgpview(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    data = safe_fetch(f"https://api.bgpview.io/ip/{ip}", timeout=timeout)
    j = json.loads(data.decode("utf-8", "ignore"))
    if j.get("status") != "ok": return None
    d = j.get("data", {})
    prefixes = d.get("prefixes", [])
    if not prefixes: return None
    p = prefixes[0]
    asn_info = p.get("asn", {}) or {}
    return {
        "asn": str(asn_info.get("asn", "")),
        "ip": ip,
        "prefix": p.get("prefix", ""),
        "cc": asn_info.get("country_code", ""),
        "registry": "",
        "allocated": "",
        "as_name": safe_text(asn_info.get("name", "")),
    }

def asn_via_ipwhois(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    data = safe_fetch(f"https://ipwho.is/{ip}", timeout=timeout)
    j = json.loads(data.decode("utf-8", "ignore"))
    if not j.get("success", False): return None
    asn = j.get("connection", {}).get("asn") or ""
    org = j.get("connection", {}).get("org") or ""
    if asn:
        return {
            "asn": str(asn), "ip": ip, "prefix": "",
            "cc": j.get("country_code",""), "registry":"", "allocated":"",
            "as_name": safe_text(org)
        }
    return None

def asn_lookup_http(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    row = with_retries(asn_via_bgpview, ip, timeout=timeout)
    return row or with_retries(asn_via_ipwhois, ip, timeout=timeout)

# =============== CDN heurÃ­sticas ===============
CDN_SOURCES = {
    "Cloudflare": {
        "ipv4": "https://www.cloudflare.com/ips-v4",
        "asn": {"13335"},
        "cnames": ["cdn.cloudflare.net"],
        "rdns": ["cloudflare", "cf-"],
        "headers": ["cf-ray", "cf-cache-status", "cf-visitor"],
    },
    "Fastly": {
        "ipv4": "https://api.fastly.com/public-ip-list",
        "asn": {"54113"},
        "cnames": ["fastly.net", "global.ssl.fastly.net"],
        "rdns": ["fastly", "cache-"],
        "headers": ["x-served-by", "via"],
    },
    "CloudFront": {
        "ipv4": "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
        "asn": {"16509", "14618"},
        "cnames": ["cloudfront.net"],
        "rdns": ["cloudfront"],
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
    },
    "Akamai": {
        "asn": {"20940"},
        "cnames": ["akamai", "akamaiedge", "akadns.net"],
        "rdns": ["akamai", "edgesuite", "edgekey"],
        "headers": ["x-akamai-pragma", "server: AkamaiGHost"],
    },
    "AzureFrontDoor": {
        "asn": {"8075"},
        "cnames": ["azurefd.net", "azureedge.net"],
        "rdns": ["azurefd", "azureedge"],
        "headers": ["x-azure-ref"],
    },
    "GoogleCDN": {
        "asn": {"15169"},
        "cnames": ["google", "gcdn", "googleusercontent.com"],
        "rdns": ["1e100.net"],
        "headers": ["x-cache: goog"],
    },
    "Imperva": {
        "asn": {"19551"},
        "cnames": ["incapdns.net", "impervadns.net"],
        "rdns": ["imperva", "incapdns"],
        "headers": ["x-iinfo", "x-cdn"],
    },
}

def local_path_for(name: str) -> str:
    return os.path.join(CDN_LISTS_DIR, f"{name}.json")

def _valid_cidr_list(lst):
    import ipaddress
    out = []
    for x in lst:
        try:
            ipaddress.ip_network(x, strict=False)
            out.append(x)
        except Exception:
            pass
    return out

def refresh_cdn_ranges() -> Dict[str, Dict]:
    if READONLY:
        st.warning("Modo solo lectura de red: actualizaciÃ³n de listas deshabilitada.")
        return load_cdn_ranges()

    data: Dict[str, Dict] = {}
    for provider, meta in CDN_SOURCES.items():
        entry = {"ipv4": [], "asn": list(meta.get("asn", []))}
        try:
            if provider == "Cloudflare" and meta.get("ipv4"):
                for url in [meta["ipv4"], "https://www.cloudflare.com/ips-v6"]:
                    txt = safe_fetch(url, timeout=10).decode("utf-8", errors="ignore")
                    for line in txt.splitlines():
                        line = line.strip()
                        if line and ":" not in line:
                            entry["ipv4"].append(line)
            elif provider == "Fastly" and meta.get("ipv4"):
                j = json.loads(safe_fetch(meta["ipv4"], timeout=10).decode("utf-8", errors="ignore"))
                entry["ipv4"].extend(j.get("addresses", []))
            elif provider == "CloudFront" and meta.get("ipv4"):
                j = json.loads(safe_fetch(meta["ipv4"], timeout=10).decode("utf-8", errors="ignore"))
                entry["ipv4"].extend(j.get("CLOUDFRONT_GLOBAL_IP_LIST", []))
                entry["ipv4"].extend(j.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST", []))
        except Exception:
            pass
        entry["ipv4"] = _valid_cidr_list(entry["ipv4"])
        data[provider] = entry
        try:
            with open(local_path_for(provider), "w", encoding="utf-8") as f:
                json.dump(entry, f)
        except Exception:
            pass
    return data

def load_cdn_ranges() -> Dict[str, Dict]:
    data = {}
    for provider in CDN_SOURCES.keys():
        path = local_path_for(provider)
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            obj["ipv4"] = _valid_cidr_list(obj.get("ipv4", []))
            obj["asn"] = list(obj.get("asn", []))
            data[provider] = obj
        except Exception:
            data[provider] = {"ipv4": [], "asn": list(CDN_SOURCES[provider].get("asn", []))}
    return data

def cidr_contains_ip(cidr: str, ip: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def guess_cdn(ip: str, asn: str, rdns: str, cnames: List[str], cdn_db: Dict[str, Dict]) -> Tuple[str, str]:
    evidence: List[str] = []; provider = ""
    def record(p: str, ev: str):
        nonlocal provider
        if not provider: provider = p
        if ev: evidence.append(ev)
    lower_rdns = (rdns or "").lower()
    lower_cnames = [c.lower() for c in (cnames or [])]

    for p, meta in CDN_SOURCES.items():
        if asn and asn.split()[0] in meta.get("asn", set()):
            record(p, f"ASN={asn}")
        for token in meta.get("rdns", []):
            if token in lower_rdns:
                record(p, f"rDNS~{token}")
        for token in meta.get("cnames", []):
            if any(token in c for c in lower_cnames):
                record(p, f"CNAME~{token}")
        for cidr in cdn_db.get(p, {}).get("ipv4", [])[:3000]:
            if cidr_contains_ip(cidr, ip):
                record(p, f"CIDR={cidr}")
                break
    ev_str = "; ".join(sorted(set(evidence))) if evidence else ""
    return (provider or "", ev_str)

# =============== HTTP HEAD ===============
def http_head(host_or_ip: str, timeout: float = 3.5) -> Dict[str, str]:
    import http.client
    headers_collected = {}
    if READONLY: return headers_collected
    targets = []
    if is_valid_host(host_or_ip):
        targets = [(host_or_ip, True), (host_or_ip, False)]
    elif is_valid_ip(host_or_ip):
        targets = [(host_or_ip, True), (host_or_ip, False)]
    for target, use_https in targets:
        try:
            conn = http.client.HTTPSConnection(target, timeout=timeout) if use_https else http.client.HTTPConnection(target, timeout=timeout)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            for k, v in resp.getheaders():
                k_lower = k.lower()
                if k_lower in ("server","via","cf-ray","cf-cache-status","x-amz-cf-id","x-amz-cf-pop","x-akamai-pragma","x-azure-ref","x-served-by"):
                    headers_collected[k_lower] = v
            conn.close()
            if headers_collected: break
        except Exception:
            continue
    return headers_collected

# =============== CSS y Topbar (incluye slot del logo a la derecha) ===============
st.markdown(f"""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{{ --bg:#0e1430; --text:#dfe6ff; --muted:#9aa4c7; --card:#121b3a; --border:#ffffff22; --accent:#e21d2d; }}
html, body, .stApp{{ font-family:'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial; background:var(--bg); color:var(--text); }}
.block-container{{ padding-top: 0.8rem; }}
.topbar{{ position:sticky; top:0; z-index:100; display:flex; align-items:center; gap:12px;
  background:rgba(14,20,48,.85); backdrop-filter:saturate(1.2) blur(8px);
  border-bottom:1px solid var(--border); padding:10px 12px; border-radius:12px; }}
.topbar .title{{ font-weight:700; letter-spacing:.2px; white-space:nowrap; }}
.topbar .right{{ margin-left:auto; display:flex; align-items:center; gap:12px; }}
.logo-slot{{ width: 360px; min-height:48px; display:flex; align-items:center; justify-content:flex-end; }}
.kpi{{ background:linear-gradient(180deg,#141d41,#0f1734); border:1px solid #263068; border-radius:12px; padding:12px; }}
.kpi .label{{ color:var(--muted); font-size:.9rem; }}
.kpi .value{{ font-size:1.4rem; font-weight:700; }}
.section{{ background:var(--card); border:1px solid var(--border); border-radius:14px; padding:12px; }}
.stButton > button{{ background: linear-gradient(180deg, #1f2a60, #18214a); color:#fff;
  border:1px solid #2a3a84; border-radius:12px; padding:10px 16px; font-weight:600; }}
.stButton > button:hover{{ box-shadow:0 0 0 3px #2a3a8422, 0 6px 20px #00000055; }}
[data-testid="stProgressBar"] > div > div{{ background: linear-gradient(90deg, var(--accent), #ff5261); }}
.badge-cdn{{ padding:2px 8px; border-radius:999px; border:1px solid #2a3a84; font-size:.78rem; display:inline-block; }}
.badge-cdn[data-p="Cloudflare"]{{ background:#18263f; color:#ff9f9f; border-color:#ff6b6b55; }}
.badge-cdn[data-p="Fastly"]{{ background:#1d243f; color:#ffbd7a; border-color:#ff8a3d55; }}
.badge-cdn[data-p="CloudFront"]{{ background:#182b3a; color:#9ad5ff; border-color:#4db3ff55; }}
.badge-cdn[data-p="Akamai"]{{ background:#1b2b2f; color:#9fe3ff; border-color:#4ac8ff55; }}
.badge-cdn[data-p="AzureFrontDoor"]{{ background:#192b40; color:#b4d7ff; border-color:#5ca9ff55; }}
.badge-cdn[data-p="GoogleCDN"]{{ background:#1b2f1d; color:#b9f7b9; border-color:#4cff4c55; }}
.badge-cdn[data-p="Imperva"]{{ background:#2b1b2f; color:#f1b9ff; border-color:#cc66ff55; }}
.badge-cdn[data-p="Desconocido"]{{ background:#262a3f; color:#c2c6de; border-color:#8c94b355; }}
.footer{{ color:var(--muted); font-size:.85rem; text-align:right; padding-top:6px; }}
.small{{ color:var(--muted); font-size:.9rem; }}
</style>

<div class="topbar">
  <span class="title">ðŸ›°ï¸ {APP_NAME}</span>
  <div class="right">
    <div class="logo-slot">
      {logo_html if logo_html else diag_html}
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# =============== Cabecera ===============
c_header = st.container()
with c_header:
    st.markdown('<div class="section"><h2 style="margin:0">Carga y parÃ¡metros</h2><p class="small">IP/Host â†’ ASN usando APIs HTTP + heurÃ­sticas de DNS/CDN</p></div>', unsafe_allow_html=True)

left, right = st.columns([3, 2], gap="large")

# =============== Panel izquierdo: carga, preview y deduplicaciÃ³n ===============
entries: List[str] = []
raw_lines: List[str] = []

with left:
    st.subheader("Sube un .txt con IPs o dominios (una por lÃ­nea)")
    uploaded = st.file_uploader("Arrastra tu archivo o examina", type=["txt"], label_visibility="collapsed")

    if uploaded:
        if uploaded.size > MAX_FILE_BYTES:
            st.error(f"Archivo demasiado grande (> {MAX_FILE_BYTES//(1024*1024)} MB)."); st.stop()
        content = uploaded.read().decode("utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
        raw_lines = content.splitlines()

        if len(raw_lines) > MAX_LINES:
            st.error(f"Demasiadas lÃ­neas (> {MAX_LINES:,}). Reduce el archivo."); st.stop()
        if any(len(ln) > MAX_LINE_LEN for ln in raw_lines):
            st.error("LÃ­neas demasiado largas; posible payload malicioso."); st.stop()
        suspicious = [i for i, ln in enumerate(raw_lines, 1) if ln and not SAFE_LINE_RE.match(ln)]
        if suspicious:
            st.error(f"Se detectaron {len(suspicious)} lÃ­neas con caracteres invÃ¡lidos. Limpia el archivo."); st.stop()

        show_preview = [ln.strip() for ln in raw_lines[:100]]
        st.caption(f"Preview (primeras {min(100,len(raw_lines))} lÃ­neas)")
        preview_df = pd.DataFrame(show_preview, columns=["Preview"])
        st.dataframe(preview_df, use_container_width=True, height=200)

        cleaned = [ln.strip() for ln in raw_lines if ln.strip() and not ln.strip().startswith("#")]
        invalid = []
        valid_cleaned = []
        for x in cleaned:
            sx = sanitize_entry(x)
            if sx is None:
                invalid.append(x)
            else:
                valid_cleaned.append(sx)

        entries = unique_preserve_order(valid_cleaned)  # Dedupe preservando orden
        removed_dups = len(valid_cleaned) - len(entries)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("LÃ­neas", f"{len(raw_lines):,}")
        m2.metric("InvÃ¡lidos", f"{len(invalid):,}")
        m3.metric("VÃ¡lidos Ãºnicos", f"{len(entries):,}")
        m4.metric("Duplicados removidos", f"{removed_dups:,}")
        if invalid:
            st.download_button("Descargar invÃ¡lidos", "\n".join(invalid), "invalidos.txt", "text/plain")

        if len(entries) > MAX_ENTRIES_PER_RUN:
            st.error(f"MÃ¡ximo permitido: {MAX_ENTRIES_PER_RUN:,} entradas por ejecuciÃ³n."); st.stop()

# =============== Panel derecho: parÃ¡metros e inspector ===============
with right:
    st.subheader("ParÃ¡metros")
    c1, c2 = st.columns(2)
    threads = c1.slider("Hilos en paralelo", 1, 100, 40, help="Concurrencia del procesamiento")
    timeout = c2.slider("Timeout por consulta (seg)", 1.0, 15.0, 6.0)
    do_http = st.checkbox("Intentar HEAD HTTP (headers)", value=False, help="AÃ±ade seÃ±ales por headers del borde. MÃ¡s lento.")
    if READONLY:
        do_http = False
        st.info("Modo solo lectura de red: HEAD y actualizaciÃ³n de listas deshabilitados.")

    mode = st.toggle("Modo profundo", help="Aumenta seÃ±ales (HEAD/TLS) y reduce hilos para mejor precisiÃ³n.")
    if mode:
        threads = min(threads, 20)
        timeout = max(timeout, 8.0)
        do_http = not READONLY

    c3, c4 = st.columns(2)
    if c3.button("Actualizar rangos CDN"):
        refresh_cdn_ranges()
        st.success("Listas CDN actualizadas.")
    cdn_db = load_cdn_ranges()

    st.caption("Inspector rÃ¡pido (1 entrada)")
    inspector_target = st.text_input("IP/Host")
    inspector_go = st.button("Inspeccionar")
    if inspector_go and inspector_target:
        item_sane = sanitize_entry(inspector_target)
        if not item_sane:
            st.error("Entrada invÃ¡lida.")
        else:
            def _inspect(item: str):
                rows = []
                if is_valid_ip(item):
                    addrs = [item]; cnames = []
                else:
                    cached = cache_get(k("dns", item))
                    if cached is None:
                        addrs, cnames = dns_resolve(item)
                        cache_set(k("dns", item), (addrs, cnames))
                    else:
                        addrs, cnames = cached
                for ip in addrs if 'addrs' in locals() else [item]:
                    cy = cache_get(k("asn", ip))
                    if cy is None:
                        cy = asn_lookup_http(ip, timeout=timeout)
                        cache_set(k("asn", ip), cy)
                    asn = (cy.get("asn") if cy else "") or ""
                    prefix = (cy.get("prefix") if cy else "") or ""
                    as_name = (cy.get("as_name") if cy else "") or ""
                    rd = cache_get(k("rdns", ip))
                    if rd is None:
                        rd = reverse_dns(ip)
                        cache_set(k("rdns", ip), rd)
                    heads = {}
                    if do_http:
                        heads = cache_get(k("head", item))
                        if heads is None:
                            heads = http_head(item, timeout=timeout)
                            cache_set(k("head", item), heads)
                    provider, ev = guess_cdn(ip, asn, rd or "", cnames if not is_valid_ip(item) else [], cdn_db)
                    if heads:
                        h_text = " ".join([f"{k}:{v}" for k, v in heads.items()]).lower()
                        ev_parts = [x for x in (ev.split("; ") if ev else [])]
                        if "cf-ray" in heads or "cf-cache-status" in heads or "cloudflare" in h_text:
                            provider = provider or "Cloudflare"; ev_parts.append("headers:Cloudflare")
                        if "x-amz-cf-id" in heads or "x-amz-cf-pop" in heads:
                            provider = provider or "CloudFront"; ev_parts.append("headers:CloudFront")
                        if "x-served-by" in heads or "via" in heads:
                            if "varnish" in h_text or "fastly" in h_text or "cache-" in h_text:
                                provider = provider or "Fastly"; ev_parts.append("headers:Fastly")
                        ev = "; ".join(sorted(set(ev_parts))) if ev_parts else ""
                    rows.append({
                        "input": item, "ip": ip, "cdn": provider or DEF["cdn"],
                        "evidence": ev or DEF["evidence"], "asn": asn or DEF["asn"],
                        "as_name": as_name or DEF["as_name"], "prefix": prefix or DEF["prefix"],
                        "rdns": rd or DEF["rdns"], "cnames": ", ".join(cnames) if cnames else DEF["cnames"]
                    })
                return rows
            st.json(_inspect(item_sane)[0] if item_sane else {"info":"sin datos"})

# =============== Persistencia y control de recalculo ===============
def entries_fingerprint(items: List[str]) -> Optional[str]:
    if not items: return None
    return hashlib.sha1("\n".join(items).encode("utf-8")).hexdigest()

if "last_run_ts" not in st.session_state:
    st.session_state.last_run_ts = 0.0
cooldown_left = max(0, MIN_SECONDS_BETWEEN_RUNS - (time.time() - st.session_state.last_run_ts))

current_params = {
    "threads": int(threads),
    "timeout": float(timeout),
    "do_http": bool(do_http),
    "entries_hash": entries_fingerprint(entries) if entries else None,
}

prev_params = st.session_state.get("last_params")
needs_rerun = (prev_params is None) or any(prev_params.get(k) != current_params.get(k) for k in current_params)

run = st.button("Ejecutar anÃ¡lisis", disabled=(not entries) or cooldown_left > 0)
if cooldown_left > 0:
    st.caption(f"Espera {cooldown_left:.1f}s para volver a ejecutar.")

results: List[Dict[str, str]] = []
df = None

# =============== Proceso principal (solo si run) ===============
if run and entries:
    st.session_state.last_run_ts = time.time()
    start_time = time.time()
    threads = min(int(threads), MAX_THREADS_SLIDER)

    progress = st.progress(0); status = st.empty()
    done, total = 0, len(entries)
    errors_consec = 0

    mem_asn: Dict[str, Optional[Dict[str, str]]] = {}
    mem_dns: Dict[str, Tuple[List[str], List[str]]] = {}
    mem_rdns: Dict[str, str] = {}
    mem_head: Dict[str, Dict[str, str]] = {}

    def analyze_item(item: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        if is_valid_ip(item):
            addrs = [item]; cnames: List[str] = []
        else:
            cached = mem_dns.get(item) or cache_get(k("dns", item))
            if cached is None:
                addrs, cnames = dns_resolve(item)
                mem_dns[item] = (addrs, cnames); cache_set(k("dns", item), (addrs, cnames))
            else:
                addrs, cnames = cached

        for ip in addrs if 'addrs' in locals() else [item]:
            cy = mem_asn.get(ip) or cache_get(k("asn", ip))
            if cy is None:
                cy = asn_lookup_http(ip, timeout=timeout)
                mem_asn[ip] = cy; cache_set(k("asn", ip), cy)
            asn = (cy.get("asn") if cy else "") or ""
            prefix = (cy.get("prefix") if cy else "") or ""
            as_name = (cy.get("as_name") if cy else "") or ""

            rd = mem_rdns.get(ip) or cache_get(k("rdns", ip))
            if rd is None:
                rd = reverse_dns(ip)
                mem_rdns[ip] = rd; cache_set(k("rdns", ip), rd)
            rd = rd or ""

            heads = {}
            if do_http:
                heads = mem_head.get(item) or cache_get(k("head", item))
                if heads is None:
                    heads = http_head(item, timeout=timeout)
                    mem_head[item] = heads; cache_set(k("head", item), heads)

            provider, ev = guess_cdn(ip, asn, rd, cnames if not is_valid_ip(item) else [], load_cdn_ranges())

            if heads:
                h_text = " ".join([f"{k}:{v}" for k, v in heads.items()])
                h_low = h_text.lower()
                ev_parts = [x for x in (ev.split("; ") if ev else [])]
                if "cf-ray" in heads or "cf-cache-status" in heads or "cloudflare" in h_low:
                    provider = provider or "Cloudflare"; ev_parts.append("headers:Cloudflare")
                if "x-amz-cf-id" in heads or "x-amz-cf-pop" in heads:
                    provider = provider or "CloudFront"; ev_parts.append("headers:CloudFront")
                if "x-served-by" in heads or "via" in heads:
                    if "varnish" in h_low or "fastly" in h_low or "cache-" in h_low:
                        provider = provider or "Fastly"; ev_parts.append("headers:Fastly")
                ev = "; ".join(sorted(set(ev_parts))) if ev_parts else ""

            cnames_str = ""
            if not is_valid_ip(item):
                if isinstance(cnames, (list, tuple)):
                    cnames_str = ", ".join(str(x) for x in cnames if x)
                elif cnames:
                    cnames_str = str(cnames)

            rows.append({
                "input": str(item or ""),
                "ip": str(ip or ""),
                "cdn": str(provider or DEF["cdn"]),
                "evidence": str(ev or DEF["evidence"]),
                "asn": str(asn or DEF["asn"]),
                "as_name": str(as_name or DEF["as_name"]),
                "prefix": str(prefix or DEF["prefix"]),
                "rdns": str(rd or DEF["rdns"]),
                "cnames": str(cnames_str or DEF["cnames"]),
            })
        return rows

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = [ex.submit(analyze_item, it) for it in entries]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    rows = fut.result()
                except Exception:
                    rows = []; errors_consec += 1
                if rows:
                    results.extend(rows)
                    if any(r.get("asn") or r.get("cdn") for r in rows):
                        errors_consec = 0
                done += 1
                progress.progress(int(done * 100 / total))
                status.write(f"Procesadas {done:,}/{total:,}")
                if errors_consec >= MAX_CONSECUTIVE_ERRORS:
                    st.error("Demasiados errores seguidos. Se detiene para evitar bloqueos.")
                    break
    finally:
        progress.progress(100)

    order = {s: i for i, s in enumerate(entries)}
    results.sort(key=lambda r: (order.get(r["input"], 10**9), r["ip"]))
    if results:
        df = pd.DataFrame(results, columns=["input","ip","cdn","evidence","asn","as_name","prefix","rdns","cnames"]).fillna("")
        df = df.drop_duplicates(subset=["input","ip","cdn","asn","prefix","rdns","cnames"])
        # Normalizaciones
        repl = {"cdn": DEF["cdn"], "evidence": DEF["evidence"], "asn": DEF["asn"],
                "as_name": DEF["as_name"], "prefix": DEF["prefix"], "rdns": DEF["rdns"], "cnames": DEF["cnames"]}
        for col, default_val in repl.items():
            df[col] = df[col].replace({"": default_val}).astype(str)
        for col in ["input","ip"]:
            df[col] = df[col].astype(str)

        # Guardar en sesiÃ³n para persistir
        st.session_state["results_df"] = df
        st.session_state["results_all_rows"] = results
        st.session_state["last_params"] = current_params

        st.success("Â¡Listo! Resultados generados.")

# =============== Reutilizar resultados si no hay nuevo run ===============
if df is None and "results_df" in st.session_state and not needs_rerun:
    df = st.session_state["results_df"]
    results = st.session_state.get("results_all_rows", [])

# =============== Mostrar resultados persistidos (si existen) ===============
if df is not None and len(df):
    total_rows = len(df)
    detected = (df["cdn"] != DEF["cdn"]).sum()

    k1,k2,k3,k4 = st.columns(4)
    k1.markdown(f'<div class="kpi"><div class="label">Total filas</div><div class="value">{total_rows:,}</div></div>', unsafe_allow_html=True)
    k2.markdown(f'<div class="kpi"><div class="label">Detectados</div><div class="value">{detected:,} ({(detected/total_rows*100 if total_rows else 0):.1f}%)</div></div>', unsafe_allow_html=True)
    top = df.loc[df["cdn"]!=DEF["cdn"],"cdn"].value_counts().head(1)
    k3.markdown(f'<div class="kpi"><div class="label">Top CDN</div><div class="value">{(top.index[0] if not top.empty else "-")}</div></div>', unsafe_allow_html=True)
    k4.markdown(f'<div class="kpi"><div class="label">Timeout</div><div class="value">{timeout:.1f}s</div></div>', unsafe_allow_html=True)

    # Filtros en formulario (no re-ejecuta hasta "Aplicar filtros")
    with st.expander("Filtros", expanded=True):
        with st.form("filters_form"):
            cols = st.columns([2,2,2,3])
            cdns = sorted(df["cdn"].unique())
            sel = cols[0].multiselect("CDN", cdns, default=st.session_state.get("flt_sel", []))
            only_unk = cols[1].checkbox("Solo Desconocido", value=st.session_state.get("flt_only_unk", False))
            search = cols[2].text_input("Buscar (ASN/Org/rDNS/Prefijo)", value=st.session_state.get("flt_search",""))
            limit_rows = cols[3].slider("MÃ¡x. filas a mostrar", 1000, 50000, st.session_state.get("flt_limit", 5000), 500)
            apply_filters = st.form_submit_button("Aplicar filtros")

        # Guardar filtros al aplicar
        if apply_filters:
            st.session_state["flt_sel"] = sel
            st.session_state["flt_only_unk"] = only_unk
            st.session_state["flt_search"] = search
            st.session_state["flt_limit"] = limit_rows
        else:
            # Usar los guardados si existen
            sel = st.session_state.get("flt_sel", sel)
            only_unk = st.session_state.get("flt_only_unk", only_unk)
            search = st.session_state.get("flt_search", search)
            limit_rows = st.session_state.get("flt_limit", limit_rows)

    mask = pd.Series(True, index=df.index)
    if sel: mask &= df["cdn"].isin(sel)
    if only_unk: mask &= df["cdn"].eq(DEF["cdn"])
    if search:
        s = search.lower()
        mask &= (
            df["asn"].astype(str).str.contains(s, case=False) |
            df["as_name"].str.lower().str.contains(s) |
            df["rdns"].str.lower().str.contains(s) |
            df["prefix"].str.lower().str.contains(s)
        )
    df_view = df[mask].head(limit_rows)

    # Pie (best effort)
    try:
        import plotly.express as px
        dist = df_view["cdn"].replace(DEF["cdn"], "Sin detectar").value_counts().reset_index()
        dist.columns = ["CDN","Cantidad"]
        fig = px.pie(dist, values="Cantidad", names="CDN", hole=0.35, title="DistribuciÃ³n por CDN")
        st.plotly_chart(fig, use_container_width=True)
    except Exception:
        pass

    # Escapar HTML en columnas; badge solo para CDN
    df_html = df_view.copy()
    for c in ["input","ip","evidence","asn","as_name","prefix","rdns","cnames"]:
        df_html[c] = df_html[c].apply(lambda v: html.escape(str(v)))
    def cdn_badge(c):
        c = c or DEF["cdn"]
        return f'<span class="badge-cdn" data-p="{html.escape(c)}">{html.escape(c)}</span>'
    df_html["cdn"] = df_html["cdn"].apply(cdn_badge)

    st.markdown("### Resultados")
    st.markdown(df_html.to_html(escape=False, index=False), unsafe_allow_html=True)

    # Exportar
    st.subheader("Exportar")
    cA, cB, cC, cD, cE = st.columns(5)
    txt_buf = io.StringIO()
    for _, r in df_view.iterrows():
        txt_buf.write(f'{r["input"]} -> {r["ip"]} -> {r["cdn"]}\n')
    cA.download_button("TXT (filtrado)", data=txt_buf.getvalue(), file_name="cdn_radar.txt", mime="text/plain")
    cB.download_button("CSV (filtrado)", df_view.to_csv(index=False), "cdn_radar_filtered.csv", "text/csv")
    cC.download_button("CSV (todo)", df.to_csv(index=False), "cdn_radar_full.csv", "text/csv")
    if len(df_view) <= EXCEL_MAX_ROWS:
        try:
            import xlsxwriter  # noqa
            xlsx_buf = io.BytesIO()
            with pd.ExcelWriter(xlsx_buf, engine="xlsxwriter") as writer:
                df_view.to_excel(writer, index=False, sheet_name="Resultados")
            cD.download_button("Excel (filtrado)", xlsx_buf.getvalue(),
                               "cdn_radar_filtered.xlsx",
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        except Exception:
            pass
    try:
        import pyarrow as pa, pyarrow.parquet as pq
        buf = io.BytesIO(); pq.write_table(pa.Table.from_pandas(df), buf)
        cE.download_button("Parquet (todo)", buf.getvalue(), "cdn_radar.parquet", "application/octet-stream")
    except Exception:
        pass

    proj = {
        "app": APP_NAME, "ver": APP_VER,
        "params": {"threads": int(threads), "timeout": float(timeout), "do_http": bool(do_http)},
        "entries_count": int(len(df["input"].unique())),
        "results": st.session_state.get("results_all_rows", results)
    }
    st.download_button("Guardar proyecto (.ipr)", data=json.dumps(proj).encode("utf-8"),
                       file_name="insside_ipradar.ipr", mime="application/json")


# =============== Abrir proyecto ===============
st.subheader("Abrir proyecto")
proj_file = st.file_uploader("Cargar .ipr/.json", type=["ipr","json"], key="proj_up")
if proj_file:
    try:
        data = json.loads(proj_file.getvalue().decode("utf-8","ignore"))
        st.json({"app": data.get("app"), "ver": data.get("ver"), "params": data.get("params"),
                 "entries_count": data.get("entries_count", 0)})
        if "results" in data:
            dfp = pd.DataFrame(data["results"])
            st.markdown("Vista rapida del proyecto cargado")
            st.dataframe(dfp.head(200), use_container_width=True, height=300)
            st.session_state["results_df"] = dfp.drop_duplicates()
            st.session_state["results_all_rows"] = data["results"]
            st.session_state["last_params"] = None
    except Exception as e:
        st.error(f"No se pudo abrir el proyecto: {e}")

# =============== Footer ===============
st.markdown(f'<div class="footer">INSSIDE  IPRadar v{APP_VER}  Heurísticas {HEUR_VER}</div>', unsafe_allow_html=True)
