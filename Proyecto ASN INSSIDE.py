import os
import re
import io
import json
import time
import hashlib
import socket
import logging
import pandas as pd
import concurrent.futures
from typing import Optional, List, Dict, Tuple
from threading import Semaphore

import streamlit as st

APP_NAME = "INSSIDE • IPRadar"
st.set_page_config(page_title=APP_NAME, page_icon="🛰️", layout="wide")

# --------- CSS mínimo seguro ---------
st.markdown("""
<style>
:root{
  --bg:#0e1430; --text:#dfe6ff; --muted:#9aa4c7; --card:#121b3a; --border:#ffffff22; --accent:#e21d2d;
}
.stApp{ background: var(--bg); color: var(--text); }
.block-container{ padding-top: 1.3rem; }
.header{ display:flex; gap:16px; align-items:center; background: var(--card); border:1px solid var(--border); border-radius:14px; padding:14px 16px; }
.header h1{ margin:0; font-size:1.6rem; }
.header p{ margin:.1rem 0 0; color: var(--muted); }
div[data-testid="stFileUploader"], .stSlider, .stDataFrame, .stDownloadButton, .stAlert, .stTextInput, .stCheckbox{
  border:1px solid var(--border); border-radius:14px; background: var(--card); padding:10px 12px;
}
.stButton > button{ background: linear-gradient(180deg, #1f2a60, #18214a); color:#fff; border:1px solid #2a3a84; border-radius:12px; padding:10px 16px; font-weight:600; }
.stButton > button:hover{ box-shadow: 0 0 0 3px #2a3a8422, 0 6px 20px #00000055; }
[data-testid="stProgressBar"] > div > div{ background: linear-gradient(90deg, var(--accent), #ff5261); }
.badge{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:.78rem; color:#fff; background:#24306a; border:1px solid #2a3a84; }
.default-dim { color:#8c94b3; font-style: italic; }
</style>
""", unsafe_allow_html=True)

# --------- Header ---------
# --------- Header robusto ---------
LOGO_FILENAME = "logon_insside.png"  # Usa aquí el nombre real de tu archivo
LOGO_PATH = os.path.abspath(LOGO_FILENAME)

col_logo, col_title = st.columns([2, 8], vertical_alignment="center")
with col_logo:
    st.caption(f"CWD: {os.getcwd()}")
    st.caption(f"Logo path: {LOGO_PATH}")
    st.caption(f"Logo existe: {os.path.exists(LOGO_PATH)}")
    try:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=120)
        else:
            st.write("INSSIDE")
    except Exception as e:
        st.write("INSSIDE")
        st.caption(f"Error mostrando logo: {e}")

with col_title:
    st.markdown(
        f'<div class="header"><div><h1>{APP_NAME}</h1>'
        '<p>IP/Host → ASNd detection using HTTP APIs + DNS heuristics</p></div></div>',
        unsafe_allow_html=True
    )
st.markdown("<div class='badge'>Security • Networking • Edge Intelligence</div>", unsafe_allow_html=True)
st.write("")

# --------- Defaults amables ---------
DEF = {
    "cdn": "Desconocido",
    "evidence": "Sin evidencia",
    "asn": "N/D",
    "as_name": "N/D",
    "prefix": "N/D",
    "rdns": "Sin rDNS",
    "cnames": "Sin CNAME",
}

# --------- Utilidades básicas ---------
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
SAFE_LINE_RE = re.compile(r"^[0-9A-Za-z.\-_\s#]+$")  # IPs, hostnames, comentarios
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

GLOBAL_SEM = Semaphore(GLOBAL_MAX_WORKERS)

def is_valid_ip(s: str) -> bool:
    if not IP_RE.match(s): return False
    try: return all(0 <= int(p) <= 255 for p in s.split("."))
    except: return False

def is_valid_host(h: str) -> bool:
    return bool(HOST_RE.match(h)) and "." in h

def safe_text(s: str) -> str:
    return re.sub(r"[^ -~]", " ", s)[:256].strip()

def ck(key: str) -> str:
    return os.path.join(CACHE_DIR, hashlib.sha1(key.encode("utf-8")).hexdigest() + ".json")

def cache_get(key: str, ttl: int = CACHE_TTL_SECONDS):
    path = ck(key)
    try:
        if time.time() - os.path.getmtime(path) > ttl: return None
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except: return None

def cache_set(key: str, obj) -> None:
    try:
        with open(ck(key), "w", encoding="utf-8") as f: json.dump(obj, f)
    except: pass

# --------- DNS helpers ---------
def dns_resolve(host: str) -> Tuple[List[str], List[str]]:
    addrs, cnames = [], []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if is_valid_ip(ip) and ip not in addrs:
                addrs.append(ip)
    except: pass
    try:
        name, aliaslist, addrlist = socket.gethostbyname_ex(host)
        cnames.extend(aliaslist)
        for ip in addrlist:
            if is_valid_ip(ip) and ip not in addrs:
                addrs.append(ip)
    except: pass
    return addrs, list(dict.fromkeys(cnames))

def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except:
        return ""

# --------- ASN vía HTTP (BGPView primero, ipwho.is fallback) ---------
def asn_via_bgpview(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    import urllib.request
    url = f"https://api.bgpview.io/ip/{ip}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8", "ignore"))
        if j.get("status") != "ok":
            return None
        data = j.get("data", {})
        prefixes = data.get("prefixes", [])
        if not prefixes:
            return None
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
    except Exception:
        return None

def asn_via_ipwhois(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    import urllib.request
    try:
        with urllib.request.urlopen(f"https://ipwho.is/{ip}", timeout=timeout) as r:
            j = json.loads(r.read().decode("utf-8", "ignore"))
        if not j.get("success", False):
            return None
        asn = j.get("connection", {}).get("asn") or ""
        org = j.get("connection", {}).get("org") or ""
        if asn:
            return {
                "asn": str(asn), "ip": ip, "prefix": "",
                "cc": j.get("country_code",""), "registry":"", "allocated":"",
                "as_name": safe_text(org)
            }
    except Exception:
        return None
    return None

def asn_lookup_http(ip: str, timeout: float = 6.0) -> Optional[Dict[str, str]]:
    row = asn_via_bgpview(ip, timeout=timeout)
    if row: return row
    return asn_via_ipwhois(ip, timeout=timeout)

# --------- Listas de rangos CDN y patrones ---------
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
}

def local_path_for(name: str) -> str:
    return os.path.join(CDN_LISTS_DIR, f"{name}.json")

def refresh_cdn_ranges() -> Dict[str, Dict]:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    data: Dict[str, Dict] = {}
    for provider, meta in CDN_SOURCES.items():
        entry = {"ipv4": [], "asn": list(meta.get("asn", []))}
        try:
            if provider == "Cloudflare":
                for url in [meta["ipv4"], "https://www.cloudflare.com/ips-v6"]:
                    with urllib.request.urlopen(url, context=ctx, timeout=10) as r:
                        txt = r.read().decode("utf-8", errors="ignore")
                        for line in txt.splitlines():
                            line = line.strip()
                            if line and ":" not in line:
                                entry["ipv4"].append(line)
            elif provider == "Fastly":
                with urllib.request.urlopen(meta["ipv4"], context=ctx, timeout=10) as r:
                    j = json.loads(r.read().decode("utf-8", errors="ignore"))
                    entry["ipv4"].extend(j.get("addresses", []))
            elif provider == "CloudFront":
                with urllib.request.urlopen(meta["ipv4"], context=ctx, timeout=10) as r:
                    j = json.loads(r.read().decode("utf-8", errors="ignore"))
                    entry["ipv4"].extend(j.get("CLOUDFRONT_GLOBAL_IP_LIST", []))
                    entry["ipv4"].extend(j.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST", []))
        except Exception:
            pass
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
                data[provider] = json.load(f)
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
    evidence: List[str] = []
    provider = ""
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

# --------- HTTP HEAD opcional ---------
def http_head(host_or_ip: str, timeout: float = 3.5) -> Dict[str, str]:
    import http.client
    headers_collected = {}
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

# --------- Carga de archivo y sanitización ---------
def load_entries_from_upload(uploaded) -> List[str]:
    if uploaded.size > MAX_FILE_BYTES:
        st.error(f"Archivo demasiado grande (> {MAX_FILE_BYTES//(1024*1024)} MB)."); st.stop()
    raw_bytes = uploaded.read()
    content = raw_bytes.decode("utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines()
    if len(lines) > MAX_LINES:
        st.error(f"Demasiadas líneas (> {MAX_LINES:,}). Reduce el archivo."); st.stop()
    suspicious = [i for i, ln in enumerate(lines, 1) if ln and not SAFE_LINE_RE.match(ln)]
    if suspicious:
        st.error(f"Se detectaron {len(suspicious)} líneas con caracteres inválidos. Limpia el archivo."); st.stop()
    items = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    valid: List[str] = []
    for s in items:
        if is_valid_ip(s) or is_valid_host(s):
            valid.append(s)
    if len(valid) > MAX_ENTRIES_PER_RUN:
        st.error(f"Máximo permitido: {MAX_ENTRIES_PER_RUN:,} entradas por ejecución."); st.stop()
    return valid

# --------- UI ---------
st.subheader("Sube un .txt con IPs o dominios (una por línea)")
uploaded = st.file_uploader("Arrastra tu archivo o examina", type=["txt"], label_visibility="collapsed")

c1, c2, c3, c4 = st.columns(4)
with c1: threads = st.slider("Hilos en paralelo", 1, 100, 40)
with c2: timeout = st.slider("Timeout por consulta (seg)", 1.0, 15.0, 6.0)
with c3: do_http = st.checkbox("Intentar HEAD HTTP (headers)", value=False, help="Añade señal por headers del borde. Lento.")
with c4:
    if st.button("Actualizar rangos CDN"):
        refresh_cdn_ranges()
        st.success("Listas CDN actualizadas.")
cdn_db = load_cdn_ranges()

entries: List[str] = []
if uploaded:
    entries = load_entries_from_upload(uploaded)
    st.info(f"Detectadas {len(entries):,} entradas válidas.".replace(",", "."))

# Rate limiting por sesión
if "last_run_ts" not in st.session_state:
    st.session_state.last_run_ts = 0.0
cooldown_left = max(0, MIN_SECONDS_BETWEEN_RUNS - (time.time() - st.session_state.last_run_ts))
run = st.button("Ejecutar análisis", disabled=not uploaded or len(entries) == 0 or cooldown_left > 0)
if cooldown_left > 0:
    st.caption(f"Espera {cooldown_left:.1f}s para volver a ejecutar.")

# --------- Proceso principal (HTTP-only) ---------
if run:
    st.session_state.last_run_ts = time.time()
    start_time = time.time()
    threads = min(int(threads), MAX_THREADS_SLIDER)

    progress = st.progress(0); status = st.empty()
    results: List[Dict[str, str]] = []
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
            cached = mem_dns.get(item) or cache_get(f"dns:{item}")
            if cached is None:
                addrs, cnames = dns_resolve(item)
                mem_dns[item] = (addrs, cnames); cache_set(f"dns:{item}", (addrs, cnames))
            else:
                addrs, cnames = cached

        for ip in addrs if 'addrs' in locals() else [item]:
            cy = mem_asn.get(ip) or cache_get(f"asn:{ip}")
            if cy is None:
                cy = asn_lookup_http(ip, timeout=timeout)
                mem_asn[ip] = cy; cache_set(f"asn:{ip}", cy)
            asn = (cy.get("asn") if cy else "") or ""
            prefix = (cy.get("prefix") if cy else "") or ""
            as_name = (cy.get("as_name") if cy else "") or ""

            rd = mem_rdns.get(ip) or cache_get(f"rdns:{ip}")
            if rd is None:
                rd = reverse_dns(ip)
                mem_rdns[ip] = rd; cache_set(f"rdns:{ip}", rd)
            rd = rd or ""

            heads = {}
            if do_http:
                heads = mem_head.get(item) or cache_get(f"head:{item}")
                if heads is None:
                    heads = http_head(item, timeout=timeout)
                    mem_head[item] = heads; cache_set(f"head:{item}", heads)

            provider, ev = guess_cdn(ip, asn, rd, cnames if not is_valid_ip(item) else [], cdn_db)

            # Evidencia por headers → normalizar a string
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

            # Normalizar evidence y cnames a string + defaults
            ev_str = ev if isinstance(ev, str) else (", ".join(ev) if isinstance(ev, (list, tuple)) else "")
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
                "evidence": str(ev_str or DEF["evidence"]),
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
                status.write(f"Procesadas {done:,}/{total:,}".replace(",", "."))
                if errors_consec >= MAX_CONSECUTIVE_ERRORS:
                    st.error("Demasiados errores seguidos. Se detiene para evitar bloqueos.")
                    break
    finally:
        progress.progress(100)

    # Orden estable por input, luego IP
    order = {s: i for i, s in enumerate(entries)}
    results.sort(key=lambda r: (order.get(r["input"], 10**9), r["ip"]))

    if results:
        df = pd.DataFrame(results, columns=["input","ip","cdn","evidence","asn","as_name","prefix","rdns","cnames"])
        # Normalizar tipos y rellenar defaults (por si algo quedó nulo)
        df = df.fillna("")
        repl = {
            "cdn": DEF["cdn"],
            "evidence": DEF["evidence"],
            "asn": DEF["asn"],
            "as_name": DEF["as_name"],
            "prefix": DEF["prefix"],
            "rdns": DEF["rdns"],
            "cnames": DEF["cnames"],
        }
        for col, default_val in repl.items():
            df[col] = df[col].replace({"": default_val}).astype(str)
        for col in ["input","ip"]:
            df[col] = df[col].astype(str)

        st.success("¡Listo! Resultados generados.")
        st.dataframe(df, use_container_width=True, height=520)

        # Descargas con defaults
        txt_buf = io.StringIO()
        for _, r in df.iterrows():
            txt_buf.write(f'{r["input"]} -> {r["ip"]} -> {r["cdn"]}\n')
        st.download_button("Descargar TXT", data=txt_buf.getvalue(), file_name="cdn_radar.txt", mime="text/plain")

        csv_buf = io.StringIO(); df.to_csv(csv_buf, index=False)
        st.download_button("Descargar CSV", data=csv_buf.getvalue(), file_name="cdn_radar.csv", mime="text/csv")

        if len(df) <= EXCEL_MAX_ROWS:
            try:
                import xlsxwriter  # noqa
                xlsx_buf = io.BytesIO()
                with pd.ExcelWriter(xlsx_buf, engine="xlsxwriter") as writer:
                    df.to_excel(writer, index=False, sheet_name="Resultados")
                st.download_button("Descargar Excel", data=xlsx_buf.getvalue(),
                                   file_name="cdn_radar.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            except Exception:
                st.info("Excel no disponible en este entorno; descargá CSV.")
        else:
            st.info(f"Excel deshabilitado para > {EXCEL_MAX_ROWS:,} filas. Usá CSV.")
    else:
        st.warning("Sin resultados. Verifica conectividad o reduce concurrencia.")

    duration = time.time() - start_time
    detected = sum(1 for r in results if r.get("cdn") and r["cdn"] != DEF["cdn"])
    logging.info(f"Run: entries={len(entries)} duration={duration:.2f}s cdn_detected={detected} threads={threads} http_head={do_http}")
else:
    if not uploaded:
        st.info("Sube un .txt con IPs o dominios (una por línea).")
    elif uploaded and not entries:
        st.warning("No se encontraron entradas válidas en el archivo.")