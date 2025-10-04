# cctv_vapt_prototype.py
"""
Streamlit-friendly, SAFE, NON-DESTRUCTIVE prototype of an Automated VAPT framework for CCTV / DVRs.
Run with:
    streamlit run cctv_vapt_prototype.py
"""


import os
import socket
import requests
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

import pandas as pd
import numpy as np

# sklearn imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split

import streamlit as st

# optional libs (wrapped)
try:
    import nmap  # python-nmap wrapper
except Exception:
    nmap = None

try:
    import shodan
except Exception:
    shodan = None

# ---------------------------
# Config / Constants
# ---------------------------
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HTTP_HEADERS = {"User-Agent": "CCTV-VAPT-Prototype/1.0 (+https://example.org)"}

# ---------------------------
# Data classes
# ---------------------------
@dataclass
class DeviceRecord:
    ip: str
    hostname: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    server_banner: Optional[str] = None
    product: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cvss_score: Optional[float] = None
    cves: List[str] = field(default_factory=list)
    risk_score: Optional[float] = None
    recommendation: Optional[str] = None

# ---------------------------
# Discovery: Shodan wrapper
# ---------------------------
class ShodanDiscoverer:
    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("Shodan API key required for ShodanDiscoverer")
        if shodan is None:
            raise ImportError("shodan package not installed (pip install shodan)")
        self.api = shodan.Shodan(api_key)

    def search_cctv(self, query: str = 'camera OR DVR OR "Network Camera"', limit: int = 50):
        results = []
        try:
            res = self.api.search(query, page=1)
            for m in res.get("matches", [])[:limit]:
                ip = m.get("ip_str")
                host = None
                if m.get("hostnames"):
                    host = m.get("hostnames")[0] if len(m.get("hostnames")) else None
                ports = [m.get("port")] if m.get("port") else []
                banner = m.get("data", "")
                results.append({
                    "ip": ip,
                    "hostname": host,
                    "ports": ports,
                    "banner": banner,
                })
        except Exception as e:
            # return empty list on error; Streamlit UI will show message
            st.error(f"[Shodan] search error: {e}")
        return results

# ---------------------------
# Local scanner (Nmap wrapper)
# ---------------------------
class NmapScanner:
    def __init__(self):
        if nmap is None:
            raise ImportError("python-nmap not installed (pip install python-nmap)")
        self.scanner = nmap.PortScanner()

    def scan(self, target: str, ports: str = "22,23,80,554,8080"):
        # Safe, non-destructive scan: only look for open ports (no NSE)
        try:
            args = f"-p {ports} --open -sS -T4"
            self.scanner.scan(hosts=target, arguments=args)
        except Exception as e:
            st.error(f"[Nmap] scan error: {e}")
            return []
        hosts = []
        try:
            for host in self.scanner.all_hosts():
                open_ports = []
                try:
                    for proto in self.scanner[host].all_protocols():
                        for p in self.scanner[host][proto].keys():
                            open_ports.append(int(p))
                except Exception:
                    pass
                hosts.append({"ip": host, "ports": open_ports})
        except Exception as e:
            st.error(f"[Nmap] parse error: {e}")
        return hosts

# ---------------------------
# Fingerprinter: HTTP / RTSP header checks
# ---------------------------
class Fingerprinter:
    def __init__(self, timeout=5):
        self.timeout = timeout

    def http_banner(self, ip: str, port: int = 80):
        url = f"http://{ip}:{port}/"
        try:
            r = requests.get(url, headers=HTTP_HEADERS, timeout=self.timeout, allow_redirects=True)
            server = r.headers.get("Server") or r.headers.get("server")
            html = (r.text or "")[:4000].lower()
            model = None
            firmware = None
            if "hikvision" in html:
                model = "Hikvision (detected in page)"
            if "firmware" in html:
                firmware = "firmware-info-found"
            return server, model, firmware
        except Exception:
            return None, None, None

    def rtsp_probe(self, ip: str, port: int = 554):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((ip, port))
            req = f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CCTV-VAPT-Prototype/1.0\r\n\r\n"
            s.sendall(req.encode("utf-8"))
            resp = s.recv(8192)
            try:
                return resp.decode(errors="ignore")
            except Exception:
                return str(resp)
        except Exception:
            return None
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

# ---------------------------
# CVE Lookup (NVD v2)
# ---------------------------
class CVELookup:
    def __init__(self):
        self.base = NVD_API_BASE

    def lookup_by_keyword(self, vendor: str, product: str, max_results: int = 5):
        q = f"{vendor} {product}".strip()
        params = {"keywordSearch": q, "resultsPerPage": max_results}
        headers = HTTP_HEADERS.copy()
        try:
            r = requests.get(self.base, params=params, headers=headers, timeout=10)
            if r.status_code != 200:
                return []
            data = r.json()
            cves = []
            for v in data.get("vulnerabilities", []):
                cveid = v.get("cve", {}).get("id")
                metrics = v.get("cve", {}).get("metrics", {}) or {}
                score = None
                for m in metrics.values():
                    cvss = m.get("cvssMetricV31") or m.get("cvssMetricV30") or m.get("cvssMetricV2")
                    if cvss:
                        try:
                            score = float(cvss[0]["cvssData"].get("baseScore"))
                        except Exception:
                            score = None
                cves.append({"id": cveid, "cvss": score})
            return cves
        except Exception:
            return []

# ---------------------------
# Simple ML risk predictor (synthetic)
# ---------------------------
class SimpleMLRiskModel:
    def __init__(self):
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=50, random_state=42))
        ])
        self.trained = False

    def generate_synthetic_dataset(self, n=1000, seed=42):
        rng = np.random.RandomState(seed)
        open_ports = rng.poisson(2, size=n)
        has_rtsp = rng.binomial(1, 0.6, size=n)
        has_http = rng.binomial(1, 0.8, size=n)
        firmware_age = rng.exponential(scale=24, size=n)
        known_cves = rng.poisson(0.3, size=n)
        default_creds = rng.binomial(1, 0.15, size=n)
        risk = ((open_ports > 3) | (firmware_age > 36) | (known_cves >= 1) | (default_creds == 1)).astype(int)
        X = np.vstack([open_ports, has_rtsp, has_http, firmware_age, known_cves, default_creds]).T
        y = risk
        df = pd.DataFrame(X, columns=["open_ports", "rtsp", "http", "firmware_age", "known_cves", "default_creds"])
        df["risk"] = y
        return df

    def train(self, df=None):
        if df is None:
            df = self.generate_synthetic_dataset()
        X = df[["open_ports", "rtsp", "http", "firmware_age", "known_cves", "default_creds"]]
        y = df["risk"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.pipeline.fit(X_train, y_train)
        score = self.pipeline.score(X_test, y_test)
        self.trained = True
        return score

    def predict_proba(self, feature_row: Dict):
        if not self.trained:
            raise RuntimeError("Model not trained")
        X = pd.DataFrame([feature_row])
        proba = self.pipeline.predict_proba(X)[0][1]
        return float(proba)

# ---------------------------
# Orchestrator (use cached resource in Streamlit)
# ---------------------------
class VAPTOrchestrator:
    def __init__(self, use_shodan: bool = False, shodan_key: str = ""):
        self.use_shodan = bool(use_shodan and shodan_key and (shodan is not None))
        self.shodan = ShodanDiscoverer(shodan_key) if self.use_shodan else None
        self.nmap = NmapScanner() if (nmap is not None) else None
        self.fp = Fingerprinter()
        self.cve = CVELookup()
        self.ml = SimpleMLRiskModel()
        self.ml_score = 0.0
        # train quickly
        try:
            self.ml_score = self.ml.train()
        except Exception:
            self.ml_score = 0.0

    def discover_via_shodan(self, query="camera OR DVR OR \"Network Camera\"", limit=50):
        if not self.use_shodan:
            raise RuntimeError("Shodan not configured")
        return self.shodan.search_cctv(query, limit=limit)

    def scan_local(self, target_range, ports="22,23,80,554,8080"):
        if self.nmap is None:
            raise RuntimeError("Nmap not available")
        return self.nmap.scan(target_range, ports=ports)

    def analyze_host(self, ip: str, ports: List[int]):
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None

        rec = DeviceRecord(ip=ip, hostname=hostname, ports=list(ports or []))

        # HTTP banner
        if 80 in rec.ports or 8080 in rec.ports:
            port = 80 if 80 in rec.ports else 8080
            srv, model, firmware = self.fp.http_banner(ip, port)
            rec.server_banner = srv
            if model:
                rec.model = model
            if firmware:
                rec.firmware = firmware

        # RTSP probe
        if 554 in rec.ports:
            rtsp_resp = self.fp.rtsp_probe(ip, 554)
            if rtsp_resp and "rtsp" in (rtsp_resp or "").lower():
                rec.product = "RTSP-service"
            rec.server_banner = (rec.server_banner or "") + ("\nRTSP: " + (rtsp_resp[:200] if rtsp_resp else "NoResp"))

        # CVE lookup (heuristic)
        vendor = rec.vendor or (rec.server_banner or "")
        product = rec.model or (rec.product or "")
        vendor_kw = "hikvision" if "hikvision" in (vendor or "").lower() else vendor
        cves = []
        if vendor_kw:
            cves = self.cve.lookup_by_keyword(vendor_kw, product if product else "")
        rec.cves = [c["id"] for c in cves if c.get("id")]
        cvss_vals = [c.get("cvss") for c in cves if c.get("cvss") is not None]
        rec.cvss_score = max(cvss_vals) if cvss_vals else None

        # ML features
        feat = {
            "open_ports": len(rec.ports),
            "rtsp": 1 if 554 in rec.ports else 0,
            "http": 1 if (80 in rec.ports or 8080 in rec.ports) else 0,
            "firmware_age": 48 if (rec.firmware and "firmware-info-found" in rec.firmware) else 12,
            "known_cves": len(rec.cves),
            "default_creds": 0
        }
        try:
            rec.risk_score = round(self.ml.predict_proba(feat), 3)
        except Exception:
            rec.risk_score = 0.0

        rec.recommendation = self.synthesize_recommendation(rec)
        return rec

    def synthesize_recommendation(self, rec: DeviceRecord) -> str:
        recs = []
        if rec.risk_score is None:
            return "No data"
        if rec.risk_score > 0.7:
            recs.append("High risk: immediate review required.")
        elif rec.risk_score > 0.4:
            recs.append("Medium risk: plan remediation soon.")
        else:
            recs.append("Low risk: maintain monitoring.")
        if rec.cvss_score and rec.cvss_score >= 7.0:
            recs.append(f"Device has CVEs with high CVSS ({rec.cvss_score}). Patch firmware immediately.")
        if rec.firmware is None:
            recs.append("Check firmware version and update to latest vendor release.")
        if len(rec.ports) > 3:
            recs.append("Restrict open ports; use firewall rules to segment camera network.")
        recs.append("Ensure unique strong passwords and disable unused services.")
        return " ".join(recs)

# ---------------------------
# Streamlit app helpers
# ---------------------------
@st.cache_resource
def get_orchestrator(use_shodan: bool, shodan_key: str):
    try:
        return VAPTOrchestrator(use_shodan=use_shodan, shodan_key=shodan_key)
    except Exception as e:
        # raise up to UI to show message
        raise

# ---------------------------
# Streamlit UI
# ---------------------------
def run_streamlit_app():
    st.set_page_config(page_title="CCTV/DVR VAPT Prototype", layout="wide")
    st.title("CCTV/DVR - VAPT Prototype (SAFE, Non-Destructive)")

    st.sidebar.header("Configuration")
    use_shodan = st.sidebar.checkbox("Use Shodan for discovery (requires API key)", value=bool(SHODAN_API_KEY))
    shodan_key = st.sidebar.text_input("Shodan API Key", value=SHODAN_API_KEY or "")
    target_range = st.sidebar.text_input("Local scan target (CIDR or IP)", value="192.168.1.0/24")
    do_local_scan = st.sidebar.checkbox("Enable local nmap scan", value=False)
    run_discovery = st.sidebar.button("Run Discovery")

    # Instantiate orchestrator (cached)
    try:
        orchestrator = get_orchestrator(use_shodan=use_shodan, shodan_key=shodan_key if shodan_key else "")
    except Exception as e:
        st.error(f"Initialization error (missing libs or invalid keys). {e}")
        return

    st.sidebar.markdown(f"ML demo accuracy: **{orchestrator.ml_score:.2f}**")

    if "results" not in st.session_state:
        st.session_state["results"] = []

    if run_discovery:
        st.info("Starting discovery... (only non-destructive probes will be used)")
        results = []

        # Shodan discovery (if configured)
        if use_shodan:
            if not shodan_key:
                st.error("Shodan checkbox enabled but API key empty. Enter key or disable Shodan.")
            elif shodan is None:
                st.error("python 'shodan' package not installed. Install with: pip install shodan")
            else:
                with st.spinner("Running Shodan discovery..."):
                    try:
                        sh_res = orchestrator.discover_via_shodan()
                        st.write(f"Shodan returned {len(sh_res)} matches (capped).")
                        for r in sh_res:
                            ip = r.get("ip")
                            ports = r.get("ports", []) or []
                            rec = orchestrator.analyze_host(ip, ports)
                            results.append(asdict(rec))
                    except Exception as e:
                        st.error(f"Shodan discovery error: {e}")

        # Local Nmap scan
        if do_local_scan:
            if nmap is None:
                st.error("python-nmap not installed. Install with: pip install python-nmap")
            else:
                with st.spinner("Running local nmap scan (may take time)..."):
                    try:
                        nm_hosts = orchestrator.scan_local(target_range)
                        st.write(f"Nmap found {len(nm_hosts)} hosts with open ports.")
                        for h in nm_hosts:
                            rec = orchestrator.analyze_host(h["ip"], h.get("ports", []))
                            results.append(asdict(rec))
                    except Exception as e:
                        st.error(f"Nmap scanning error: {e}")

        # store results
        st.session_state["results"] = results
        st.success(f"Discovery finished: {len(results)} devices analyzed.")

    st.subheader("Discovered Devices")

    if st.session_state["results"]:
        df = pd.DataFrame(st.session_state["results"])
        # ensure risk_score numeric
        if "risk_score" in df.columns:
            df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)
        highest_risk = st.checkbox("Show only risk_score > 0.5", value=False)
        if highest_risk:
            df = df[df["risk_score"] > 0.5]
        display_cols = ["ip", "hostname", "ports", "model", "firmware", "cves", "cvss_score", "risk_score", "recommendation"]
        df_display = df[[c for c in display_cols if c in df.columns]]
        st.dataframe(df_display, height=400)

        st.subheader("Device Details")
        if not df.empty:
            ip_to_show = st.selectbox("Select IP to view detailed record", df["ip"].tolist())
            rec = next((r for r in st.session_state["results"] if r["ip"] == ip_to_show), None)
            if rec:
                st.json(rec)
    else:
        st.info("No devices discovered yet. Run discovery from the sidebar.")

    st.markdown("---")
    st.caption("Prototype for authorized, defensive security assessments only. No offensive or exploit code included.")

# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    run_streamlit_app()
