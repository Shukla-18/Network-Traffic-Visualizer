# app.py - Optimized for Kali Linux (Fixed CSS)
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from utils import sniff_packets, packet_to_dict
import os
import sys
import base64
import requests
from io import BytesIO
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Network Traffic Visualizer",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🔐"
)

# Check root (required for live capture)
def is_root():
    try:
        return os.geteuid() == 0
    except Exception:
        return True

# Helper: fetch remote background as data URI (fallback to URL on error)
def bg_data_from_url(url, timeout=6):
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return "data:image/png;base64," + base64.b64encode(r.content).decode()
    except Exception:
        return url

# Background image (optional) - change or set to None to keep CSS grid
BG_IMAGE_URL = None
# BG_IMAGE_URL = "https://images.unsplash.com/photo-1515879218367-8466d910aaa4?auto=format&fit=crop&w=1950&q=80"
bg_data = bg_data_from_url(BG_IMAGE_URL) if BG_IMAGE_URL else None

# ----------------- CUSTOM CSS -----------------
CUSTOM_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Fira+Code&family=Rajdhani&display=swap');

html, body, [class*="css"] {{
    font-family: 'Share Tech Mono', 'Fira Code', monospace;
    color: #a0c5d4;
}}

.stApp {{
    background: linear-gradient(180deg, #0a0e27 0%, #050810 100%);
    {"background-image: url('" + bg_data + "'); background-size: cover; background-position: center;" if bg_data else 
     "background-image: linear-gradient(rgba(0, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 255, 0.03) 1px, transparent 1px); background-size:50px 50px;"}
}}

/* Cyber card */
.cyber-card {{
    background: linear-gradient(135deg, rgba(15, 25, 45, 0.75), rgba(10, 15, 30, 0.85));
    border: 1px solid rgba(0,255,136,0.12);
    border-radius: 12px;
    padding: 16px;
    backdrop-filter: blur(6px);
    box-shadow: 0 8px 30px rgba(0,0,0,0.5);
}}

/* Headers */
h1 {{
    color: #00ff41 !important;
    text-shadow: 0 0 10px #00ff41;
}}
h2, h3 {{
    color: #00d4ff !important;
}}

/* Sidebar */
section[data-testid="stSidebar"] {{
    background-color: #0f1419 !important;
    border-right: 2px solid #00ff41 !important;
    padding-top: 1rem !important;
}}

/* Buttons */
.stButton > button {{
    background: linear-gradient(90deg, #ff00ff, #00d4ff) !important;
    color: white !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
}}
.stDownloadButton > button {{
    background: #00ff41 !important;
    color: #071018 !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
}}

/* Inputs */
input, select, textarea {{
    background-color: #1a1f35 !important;
    border: 1px solid #00d4ff !important;
    color: #00ff41 !important;
    border-radius: 6px !important;
}}

/* Dataframe */
[data-testid="stDataFrame"] {{
    background-color: rgba(15,20,35,0.85) !important;
    border-radius: 8px !important;
    border: 1px solid rgba(0,211,255,0.06) !important;
}}

/* Metrics */
[data-testid="stMetricValue"] {{ color: #00ff41 !important; font-family: 'Rajdhani', sans-serif !important; }}

/* Footer */
.footer-text {{ text-align:center; color: rgba(0,217,255,0.6); padding:10px; }}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ----------------- HEADER -----------------
st.title("🔐 NETWORK TRAFFIC VISUALIZER")
col_info1, col_info2, col_info3 = st.columns(3)
with col_info1:
    st.info("🐉 Kali Linux (optimized)")
with col_info2:
    if is_root():
        st.success("🔓 Running as Root")
    else:
        st.warning("🔒 Running as User")
with col_info3:
    st.info(f"📡 Python {sys.version_info.major}.{sys.version_info.minor}")

if not is_root():
    st.error("⚠️ ROOT PRIVILEGES REQUIRED for live packet capture")
    st.code("sudo streamlit run app.py --server.headless true", language="bash")

st.markdown("---")

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.header("⚙️ CAPTURE SETTINGS")
    st.subheader("Interface Selection")
    common_interfaces = st.radio("Common interfaces", ["Custom", "eth0", "wlan0", "wlan0mon", "lo"])
    if common_interfaces == "Custom":
        iface = st.text_input("Custom interface", value="", help="Leave blank for default")
    else:
        iface = common_interfaces
        st.caption(f"Selected: {iface}")

    count = st.number_input("Packet count (max per capture)", min_value=1, max_value=5000, value=200, step=10)
    timeout = st.number_input("Timeout (seconds)", min_value=1, max_value=300, value=10, step=1)

    st.markdown("---")
    st.subheader("Packet Filters (Optional)")
    use_filter = st.checkbox("Apply BPF filter")
    if use_filter:
        bpf_filter = st.text_input("BPF Filter", value="tcp port 80", help="e.g., 'tcp port 80' or 'icmp'")
    else:
        bpf_filter = None

    st.markdown("---")
    st.subheader("Capture Mode")
    mode = st.selectbox("", ["Capture (live)", "Load PCAP file"])
    pcap_file = None
    if mode == "Load PCAP file":
        pcap_file = st.file_uploader("Upload .pcap/.pcapng file", type=["pcap","pcapng","cap"])

    st.markdown("---")
    if st.button("🚀 START CAPTURE / LOAD", use_container_width=True):
        st.session_state._start_capture = True

    with st.expander("🛠️ Kali Linux Tips"):
        st.markdown("""
List interfaces:
```bash
ip link show
ifconfig -a
```
Enable monitor mode:
```bash
sudo airmon-ng start wlan0
```
Capture with tcpdump:
```bash
sudo tcpdump -i eth0 -w capture.pcap
```
""")

# ----------------- SESSION STATE -----------------
if 'df' not in st.session_state:
    st.session_state.df = None

# React to start button (sidebar sets a flag)
start = st.session_state.pop('_start_capture', False)

# ----------------- CAPTURE / LOAD LOGIC -----------------
if start:
    try:
        with st.spinner("🔍 Capturing / loading packets..."):
            rows = []
            if pcap_file:
                # read pcap directly from BytesIO
                from scapy.all import rdpcap
                pkts = rdpcap(BytesIO(pcap_file.read()))
                rows = [packet_to_dict(p) for p in pkts]
            else:
                # live capture: require root
                if not is_root():
                    st.error("🚫 Root privileges required for live capture")
                    st.stop()

                # If user requested BPF filter, use scapy.sniff directly (libpcap filter)
                if use_filter and bpf_filter:
                    from scapy.all import sniff
                    pkts = sniff(count=int(count), timeout=int(timeout),
                                 iface=iface if iface else None,
                                 filter=bpf_filter)
                    rows = [packet_to_dict(p) for p in pkts]
                else:
                    rows = sniff_packets(count=int(count), timeout=int(timeout),
                                         iface=iface if iface else None)

            if not rows:
                st.warning("⚠️ No packets captured. Try increasing timeout or checking interface.")
            else:
                st.session_state.df = pd.DataFrame(rows)
                st.success(f"✅ Captured/loaded {len(st.session_state.df)} packets")
    except PermissionError:
        st.error("🚫 Permission denied. Run with: sudo streamlit run app.py")
    except ModuleNotFoundError as e:
        st.error(f"❌ Missing dependency: {e}")
        st.info("Install with: sudo apt install python3-scapy && pip install -r requirements.txt")
    except Exception as e:
        st.error(f"❌ Capture error: {e}")

df = st.session_state.df

# ----------------- METRICS / MAIN LAYOUT -----------------
st.markdown("---")
if df is None or df.empty:
    st.markdown('<div class="cyber-card" style="text-align:center;padding:3rem;">', unsafe_allow_html=True)
    st.markdown('<h2 style="color:#00d4ff">🎯 READY TO ANALYZE</h2>', unsafe_allow_html=True)
    st.markdown('<div style="color:rgba(0,255,65,0.6)">Click "START CAPTURE / LOAD" in the sidebar to begin</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    # Key metrics
    st.subheader("📊 KEY METRICS")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        st.metric("Unique Sources", int(df['src'].nunique()) if 'src' in df.columns else 0)
    with col3:
        st.metric("Unique Destinations", int(df['dst'].nunique()) if 'dst' in df.columns else 0)
    with col4:
        total_kb = df['length'].sum() / 1024 if 'length' in df.columns else 0
        st.metric("Total Data (KB)", f"{total_kb:.2f}")

    st.markdown("---")

    left, right = st.columns([2,1])
    with left:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("📡 PACKETS TABLE")
        cols_show = [c for c in ['time','src','sport','dst','dport','proto','length','summary'] if c in df.columns]
        st.dataframe(df[cols_show].sort_values(by='time', ascending=False).reset_index(drop=True), height=420, use_container_width=True)
        # Downloads
        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("💾 Download CSV", data=csv, file_name=f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime='text/csv')
        with dl_col2:
            summary = df.describe(include='all').to_string()
            st.download_button("📝 Download Summary", data=summary, file_name='summary.txt', mime='text/plain')
        st.markdown('</div>', unsafe_allow_html=True)

    with right:
        st.markdown('<div class="cyber-card">', unsafe_allow_html=True)
        st.subheader("🔷 Protocol Distribution")
        if 'proto' in df.columns:
            proto_counts = df['proto'].fillna("Other").value_counts().reset_index()
            proto_counts.columns = ['proto','count']
            fig1 = px.pie(proto_counts, names='proto', values='count',
                          color_discrete_sequence=['#00ff41','#00d4ff','#ff00ff','#ffaa00','#ff0055'])
            fig1.update_layout(paper_bgcolor='rgba(10,14,39,0.85)', plot_bgcolor='rgba(10,14,39,0.85)', font=dict(color='#00d4ff'))
            st.plotly_chart(fig1, use_container_width=True)
        else:
            st.info("No protocol data available")

        st.subheader("🔷 Top Source IPs")
        if 'src' in df.columns:
            top_src = df['src'].value_counts().reset_index().head(10)
            top_src.columns = ['src','count']
            fig2 = px.bar(top_src, x='src', y='count', color='count', color_continuous_scale=['#ff00ff','#00d4ff','#00ff41'])
            fig2.update_layout(paper_bgcolor='rgba(10,14,39,0.85)', plot_bgcolor='rgba(10,14,39,0.85)', font=dict(color='#00d4ff'), xaxis=dict(tickangle=-45))
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No source IP data")

        st.subheader("🔷 Traffic Over Time")
        try:
            df_time = df.copy()
            if 'time' in df_time.columns:
                df_time['time_ts'] = pd.to_datetime(df_time['time'])
                counts = df_time.set_index('time_ts').resample('1S').size().reset_index(name='count')
                fig3 = go.Figure()
                fig3.add_trace(go.Scatter(x=counts['time_ts'], y=counts['count'], mode='lines+markers',
                                          line=dict(color='#00ff41', width=2), marker=dict(color='#00d4ff', size=4),
                                          fill='tozeroy', fillcolor='rgba(0,255,65,0.08)'))
                fig3.update_layout(paper_bgcolor='rgba(10,14,39,0.85)', plot_bgcolor='rgba(10,14,39,0.85)', font=dict(color='#00d4ff'))
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("Timestamps not available for time-series")
        except Exception as e:
            st.info(f"Time-series unavailable: {e}")

        st.markdown('</div>', unsafe_allow_html=True)

    st.success(f"✅ Successfully processed {len(df)} packets")

# ----------------- FOOTER / SETUP -----------------
st.markdown("---")
st.info("""
### 🐉 Kali Linux Setup

Install dependencies:
```bash
sudo apt update
sudo apt install python3-scapy python3-pip
pip install -r requirements.txt
```

Run:
```bash
sudo streamlit run app.py --server.headless true
```
""")
st.markdown('<div class="footer-text">⚡ Built with Scapy + Streamlit + Plotly | For authorized security testing only | © 2025</div>', unsafe_allow_html=True)