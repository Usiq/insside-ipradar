import re, json, socket, ipaddress, requests
from typing import List, Dict, Tuple, Optional
import pandas as pd

DEF = {"cdn":"Desconocido","evidence":"Sin evidencia","asn":"N/D","as_name":"N/D","prefix":"N/D","rdns":"Sin rDNS","cnames":"Sin CNAME"}
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")

def is_valid_ip(s: str) -> bool:
    if not IP_RE.match(s): return False
    try: return all(0 <= int(p) <= 255 for p in s.split("."))
    except: return False

def is_valid_host(h: str) -> bool:
    return bool(HOST_RE.match(h)) and "." in h

def safe_text(s: str) -> str:
    return re.sub(r"[^ -~]", " ", s)[:256].strip() if s else ""

def dns_resolve(host: str):
    addrs, cnames = [], []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if is_valid_ip(ip) and ip not in addrs: addrs.append(ip)
    except: pass
    try:
        name, aliaslist, addrlist = socket.gethostbyname_ex(host)
        cnames.extend(aliaslist)
        for ip in addrlist:
            if is_valid_ip(ip) and ip not in addrs: addrs.append(ip)
    except: pass
    return addrs, list(dict.fromkeys(cnames))

def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except:
        return ""

def asn_via_bgpview(ip: str, timeout: float = 6.0) -> Optional[Dict[str,str]]:
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=timeout)
        r.raise_for_status()
        j = r.json()
        if j.get("status")!="ok": return None
        pfxs = j.get("data",{}).get("prefixes",[])
        if not pfxs: return None
        p = pfxs[0]
        asn_info = p.get("asn",{}) or {}
        return {"asn": str(asn_info.get("asn","")), "ip": ip, "prefix": p.get("prefix",""), "as_name": safe_text(asn_info.get("name",""))}
    except: return None

def asn_via_ipwhois(ip: str, timeout: float = 6.0) -> Optional[Dict[str,str]]:
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=timeout)
        j = r.json()
        if not j.get("success", False): return None
        asn = j.get("connection",{}).get("asn") or ""
        org = j.get("connection",{}).get("org") or ""
        if asn: return {"asn": str(asn), "ip": ip, "prefix":"", "as_name": safe_text(org)}
    except: return None
    return None

def asn_lookup_http(ip: str, timeout: float = 6.0) -> Dict[str,str]:
    row = asn_via_bgpview(ip, timeout) or asn_via_ipwhois(ip, timeout) or {}
    return {"asn": row.get("asn") or DEF["asn"], "prefix": row.get("prefix") or DEF["prefix"], "as_name": row.get("as_name") or DEF["as_name"]}

CDN_SOURCES = {
    "Cloudflare":{"asn":{"13335"},"rdns":["cloudflare","cf-"],"cnames":["cdn.cloudflare.net"]},
    "Fastly":{"asn":{"54113"},"rdns":["fastly","cache-"],"cnames":["fastly.net","global.ssl.fastly.net"]},
    "CloudFront":{"asn":{"16509","14618"},"rdns":["cloudfront"],"cnames":["cloudfront.net"]},
}

def cidr_contains_ip(cidr: str, ip: str) -> bool:
    try: return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except: return False

def refresh_cdn_ranges(timeout: float = 10.0) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    out["Cloudflare"] = {"ipv4": [], "asn": list(CDN_SOURCES["Cloudflare"]["asn"])}
    try:
        v4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=timeout).text.splitlines()
        out["Cloudflare"]["ipv4"].extend([x.strip() for x in v4 if x.strip() and ":" not in x])
    except: pass
    out["Fastly"] = {"ipv4": [], "asn": list(CDN_SOURCES["Fastly"]["asn"])}
    try:
        j = requests.get("https://api.fastly.com/public-ip-list", timeout=timeout).json()
        out["Fastly"]["ipv4"].extend(j.get("addresses", []))
    except: pass
    out["CloudFront"] = {"ipv4": [], "asn": list(CDN_SOURCES["CloudFront"]["asn"])}
    try:
        j = requests.get("https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips", timeout=timeout).json()
        out["CloudFront"]["ipv4"].extend(j.get("CLOUDFRONT_GLOBAL_IP_LIST", []))
        out["CloudFront"]["ipv4"].extend(j.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST", []))
    except: pass
    return out

def guess_cdn(ip: str, asn: str, rdns: str, cnames, cdn_db):
    evidence, provider = [], ""
    def record(p, ev):
        nonlocal provider
        if not provider: provider = p
        if ev: evidence.append(ev)
    lower_rdns = (rdns or "").lower()
    lower_cnames = [c.lower() for c in (cnames or [])]
    for p, meta in CDN_SOURCES.items():
        if asn and asn.split()[0] in meta.get("asn", set()): record(p, f"ASN={asn}")
        for t in meta.get("rdns", []):
            if t in lower_rdns: record(p, f"rDNS~{t}")
        for t in meta.get("cnames", []):
            if any(t in c for c in lower_cnames): record(p, f"CNAME~{t}")
        for cidr in (cdn_db.get(p) or {}).get("ipv4", [])[:3000]:
            if cidr_contains_ip(cidr, ip): record(p, f"CIDR={cidr}"); break
    ev = "; ".join(sorted(set(evidence))) if evidence else ""
    return provider, ev

def load_inputs(path: str):
    items = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            if is_valid_ip(s) or is_valid_host(s): items.append(s)
    return items

def process_items(items, timeout: float = 6.0, cdn_db=None) -> pd.DataFrame:
    cdn_db = cdn_db or {"Cloudflare":{"ipv4":[]}, "Fastly":{"ipv4":[]}, "CloudFront":{"ipv4":[]}}
    rows = []
    for item in items:
        if is_valid_ip(item):
            addrs, cnames = [item], []
        else:
            addrs, cnames = dns_resolve(item)
        if not addrs:
            rows.append({"Entrada": item,"IP": "","CDN": DEF["cdn"],"Evidencia": DEF["evidence"],"ASN": DEF["asn"],"Organización (AS)": DEF["as_name"],"Prefijo BGP": DEF["prefix"],"rDNS": DEF["rdns"],"CNAME(s)": DEF["cnames"]})
            continue
        for ip in addrs:
            asdata = asn_lookup_http(ip, timeout=timeout)
            rd = reverse_dns(ip) or ""
            provider, ev = guess_cdn(ip, asdata["asn"], rd, cnames if not is_valid_ip(item) else [], cdn_db)
            cnames_str = ", ".join(cnames) if (cnames and not is_valid_ip(item)) else ""
            rows.append({"Entrada": str(item),"IP": str(ip),"CDN": provider or DEF["cdn"],"Evidencia": ev or DEF["evidence"],"ASN": asdata["asn"] or DEF["asn"],"Organización (AS)": asdata["as_name"] or DEF["as_name"],"Prefijo BGP": asdata["prefix"] or DEF["prefix"],"rDNS": rd or DEF["rdns"],"CNAME(s)": cnames_str or DEF["cnames"]})
    return pd.DataFrame(rows, columns=["Entrada","IP","CDN","Evidencia","ASN","Organización (AS)","Prefijo BGP","rDNS","CNAME(s)"]).fillna("")