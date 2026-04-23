import streamlit as st
import pandas as pd
from transformers import pipeline
import plotly.express as px
from datetime import datetime
from utils import save_to_db
import dateparser
import requests
import time

# Импортируем наши новые сканеры
from scanners import scan_ip_shodan, scan_ip_vt

st.set_page_config(
    page_title="VBI Terminal",
    page_icon="🛡️",
    layout="wide"
)

# Твои стили остаются без изменений
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top, #020617, #000000);
    color: #e2e8f0;
}
.main-title {
    font-size: 42px;
    font-weight: 700;
    color: #38bdf8;
}
.subtitle {
    color: #94a3b8;
    margin-bottom: 20px;
}
div[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid #1e293b;
    border-radius: 14px;
    padding: 20px;
    backdrop-filter: blur(10px);
    box-shadow: 0 0 20px rgba(56,189,248,0.15);
}
.stButton button {
    background: linear-gradient(90deg, #06b6d4, #3b82f6);
    border-radius: 12px;
    border: none;
    color: white;
    font-weight: 600;
    height: 45px;
}
.section {
    margin-top: 30px;
}
</style>
""", unsafe_allow_html=True)

# Загрузка ключей из секретов
SERP_API_KEY = st.secrets.get("SERPAPI_KEY")
SHODAN_API_KEY = st.secrets.get("SHODAN_API_KEY")
VT_API_KEY = st.secrets.get("VT_API_KEY")

if not SERP_API_KEY:
    st.error("🚨 SERPAPI_KEY not found")
    st.stop()

@st.cache_resource
def load_model():
    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

analyzer = load_model()

risk_vectors = ["Legal/Compliance", "Financial Risk", "Technical Failure", "Market Expansion", "PR Crisis"]
sentiment_cats = ["Positive", "Negative", "Neutral"]

def fetch_intelligence(query, region, depth, mode, api_key):
    if mode == "Social Buzz (Risk)":
        query = f"{query} scandal OR leak OR complaint OR opinion"

    url = "https://serpapi.com/search.json"
    params = {
        "engine": "google",
        "q": query,
        "hl": "en",
        "gl": region,
        "tbm": "nws",
        "num": depth,
        "api_key": api_key
    }

    for _ in range(3):
        try:
            r = requests.get(url, params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
            results = data.get("news_results", [])
            clean = []
            for item in results:
                title = item.get("title", "")
                if not title: continue
                parsed_date = dateparser.parse(item.get("date", "")) or datetime.now()
                clean.append({
                    "Timestamp": parsed_date,
                    "Source": item.get("source", "Unknown"),
                    "Headline": title
                })
            return clean
        except Exception as e:
            print("SerpAPI error:", e)
            time.sleep(2)
    return []

# --- SIDEBAR CONFIG ---
with st.sidebar:
    st.header("🛰️ CONFIG")
    
    # Новый переключатель типа сканирования
    scan_type = st.radio("Scan Target Type", ["Entity (News/OSINT)", "IP Infrastructure"])
    
    st.divider()
    
    target_region = st.selectbox("Region", ["KZ", "US", "GB", "RU"], index=0)
    source_mode = st.radio("Mode", ["Corporate News", "Social Buzz (Risk)"])
    scan_depth = st.slider("Depth", 10, 50, 20)

st.markdown('<div class="main-title">🛡️ VBI INTELLIGENCE TERMINAL</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Real-Time OSINT • AI Risk Detection</div>', unsafe_allow_html=True)

col1, col2 = st.columns([4,1])

with col1:
    placeholder = "Kaspi, Air Astana..." if scan_type == "Entity (News/OSINT)" else "8.8.8.8"
    query = st.text_input("🔎 Target Search", placeholder=placeholder)

with col2:
    scan = st.button("RUN SCAN")

if scan:
    if not query:
        st.warning("Enter target")
        st.stop()

    # --- РЕЖИМ 1: ИНФРАСТРУКТУРА (IP) ---
        if scan_type == "IP Infrastructure":
    if not SHODAN_API_KEY or not VT_API_KEY:
        st.error("🚨 Missing SHODAN or VirusTotal API key")
        st.stop()

    with st.spinner("🔍 Querying Shodan & VirusTotal..."):
        sh_data = scan_ip_shodan(query, SHODAN_API_KEY)
        vt_data = scan_ip_vt(query, VT_API_KEY)

            st.markdown('<div class="section"></div>', unsafe_allow_html=True)
            
            # Верхние карточки с метриками
            m1, m2, m3, m4 = st.columns(4)
            
            if "error" not in sh_data:
                m1.metric("ISP", sh_data['isp'])
                m2.metric("City", sh_data['city'])
            
            if "error" not in vt_data:
                m3.metric("VT Reputation", vt_data['reputation'])
                m4.metric("Malicious Signals", vt_data['malicious'])

            col_left, col_right = st.columns(2)

            with col_left:
                st.subheader("📡 Shodan Intelligence")
                if "error" not in sh_data:
                    st.info(f"**Organization:** {sh_data['org']}")
                    st.write(f"**Operating System:** {sh_data['os']}")
                    st.write(f"**Open Ports:** `{sh_data['ports']}`")
                    if sh_data['hostnames']:
                        st.write(f"**Hostnames:** {', '.join(sh_data['hostnames'])}")
                else:
                    st.error(sh_data['error'])

            with col_right:
                st.subheader("🦠 VirusTotal Analysis")
                if "error" not in vt_data:
                    st.write(f"**Owner:** {vt_data['as_owner']}")
                    
                    # Визуализация опасностей
                    stats_df = pd.DataFrame({
                        "Category": ["Malicious", "Suspicious", "Harmless"],
                        "Count": [vt_data['malicious'], vt_data['suspicious'], vt_data['harmless']]
                    })
                    fig_vt = px.bar(stats_df, x="Category", y="Count", color="Category",
                                   color_discrete_map={"Malicious": "#ef4444", "Suspicious": "#f59e0b", "Harmless": "#10b981"})
                    fig_vt.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"))
                    st.plotly_chart(fig_vt, use_container_width=True)
                else:
                    st.error(vt_data['error'])

    # --- РЕЖИМ 2: НОВОСТИ / СУЩНОСТИ (Твой старый код) ---
    else:
        with st.spinner("🛰️ Scanning News..."):
            raw = fetch_intelligence(query, target_region, scan_depth, source_mode, SERP_API_KEY)

            if not raw:
                st.error("No data found")
                st.stop()

            processed = []
            for item in raw:
                headline = item.get("Headline", "")
                if not headline: continue
                risk = analyzer(headline, candidate_labels=risk_vectors)
                sent = analyzer(headline, candidate_labels=sentiment_cats)
                processed.append({
                    "Time": item["Timestamp"],
                    "Source": item["Source"],
                    "Headline": headline,
                    "Risk": risk["labels"][0],
                    "Sentiment": sent["labels"][0]
                })

            df = pd.DataFrame(processed)
            save_to_db(df)

            # Отображение графиков (твой оригинальный код)
            pos = len(df[df["Sentiment"]=="Positive"])
            neg = len(df[df["Sentiment"]=="Negative"])
            total = len(df)
            score = 50 + ((pos - neg)/total * 50)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("🧠 Reputation", f"{round(score,1)}%")
            c2.metric("📡 Signals", total)
            c3.metric("🟢 Positive", pos)
            c4.metric("🔴 Negative", neg)

            colA, colB = st.columns(2)
            with colA:
                fig1 = px.pie(df, names="Sentiment", hole=0.6)
                fig1.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"))
                st.plotly_chart(fig1, use_container_width=True)
            with colB:
                rc = df["Risk"].value_counts().reset_index()
                rc.columns = ["Risk","Count"]
                fig2 = px.bar(rc, x="Count", y="Risk", orientation="h")
                fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"))
                st.plotly_chart(fig2, use_container_width=True)

            st.subheader("📡 Live Feed")
            def color(val):
                return f'color: {"#22c55e" if val=="Positive" else "#ef4444" if val=="Negative" else "#94a3b8"}; font-weight:bold'
            st.dataframe(df.style.map(color, subset=["Sentiment"]), use_container_width=True, hide_index=True)
