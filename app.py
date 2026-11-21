import streamlit as st
import pandas as pd
import os
import glob
import re
import math
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title="Smart Domain & DNS Fingerprint Matcher", layout="wide")

st.title("🎯 Smart Domain Intelligence & DNS Fingerprint Matcher")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- FULL DNS SCANNER (MX, NS, TXT) ---
def get_full_dns(domain):
    mx_list, ns_list, txt_list = [], [], []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 1.5

    try:
        for r in resolver.resolve(domain, 'MX'):
            mx_list.append(str(r.exchange).rstrip('.').lower())
    except Exception:
        pass

    try:
        for r in resolver.resolve(domain, 'NS'):
            ns_list.append(str(r.target).rstrip('.').lower())
    except Exception:
        pass

    try:
        for r in resolver.resolve(domain, 'TXT'):
            txt_val = "".join([b.decode('utf-8', errors='ignore') for b in r.strings]).lower()
            txt_list.append(txt_val)
    except Exception:
        pass

    return {
        "Domain": domain,
        "MX": ", ".join(mx_list) if mx_list else "None",
        "NS": ", ".join(ns_list) if ns_list else "None",
        "TXT": " | ".join(txt_list) if txt_list else "None"
    }

# --- EXTRACT KEY DNS SIGNATURES FROM TARGET ---
def extract_dns_signatures(dns_dict):
    combined = f"{dns_dict['MX']} {dns_dict['NS']} {dns_dict['TXT']}".lower()
    
    # Extract root provider domains from MX and NS (e.g., google.com, cloudflare.com)
    raw_hosts = re.findall(r'([a-z0-9-]+\.[a-z]{2,})', f"{dns_dict['MX']} {dns_dict['NS']}")
    # Extract SPF includes from TXT (e.g., include:_spf.google.com)
    spf_includes = re.findall(r'include:([a-z0-9.-]+)', dns_dict['TXT'])
    
    signatures = set()
    ignore_words = {'com', 'net', 'org', 'co', 'io', 'in', 'uk', 'info', 'biz'}
    
    for host in raw_hosts + spf_includes:
        parts = host.split('.')
        if len(parts) >= 2:
            brand = parts[-2]
            if len(brand) > 2 and brand not in ignore_words:
                signatures.add(brand)
                
    return sorted(list(signatures))

@st.cache_data(max_entries=2, ttl=3600)
def load_policy_data(prefix):
    part_files = sorted(glob.glob(os.path.join(BASE_DIR, f"{prefix}*.csv.gz")))
    
    if not part_files:
        gz_single = os.path.join(BASE_DIR, f"{prefix}.csv.gz")
        csv_single = os.path.join(BASE_DIR, f"{prefix}.csv")
        if os.path.exists(gz_single):
            part_files = [gz_single]
        elif os.path.exists(csv_single):
            part_files = [csv_single]
            
    if not part_files:
        return None
        
    df_list = [pd.read_csv(f) for f in part_files]
    df = pd.concat(df_list, ignore_index=True)
    
    if 'Domain' in df.columns:
        df['Domain'] = df['Domain'].astype(str).str.strip().str.lower()
        df = df.drop_duplicates(subset=['Domain'], keep='first')
    
    if 'Referring_Domains' in df.columns:
        df['Referring_Domains'] = pd.to_numeric(df['Referring_Domains'], errors='coerce').fillna(0).astype('int32')
    if 'OpenPageRank_Score' in df.columns:
        df['OpenPageRank_Score'] = pd.to_numeric(df['OpenPageRank_Score'], errors='coerce').fillna(0.0).astype('float32')
    if 'Extension' in df.columns:
        df['Extension'] = df['Extension'].astype('category')
        
    return df

policies = {
    "p=none Policy": "POWER_p_none_domains",
    "no_dmarc Policy": "POWER_no_dmarc_domains",
    "p=quarantine Policy": "POWER_p_quarantine_domains"
}

selected_policy = st.sidebar.selectbox("Select DMARC Policy File", list(policies.keys()))
df = load_policy_data(policies[selected_policy])

if df is not None:
    # ==========================================================
    # SIDEBAR: SMART DOMAIN ANALYZER & RELATED FINDER
    # ==========================================================
    st.sidebar.header("🚀 Smart Domain Analyzer")
    smart_domain_input = st.sidebar.text_input(
        "Enter Any Domain (Auto-Check DNS + Find Related)",
        placeholder="e.g. reef.org"
    ).strip().lower()
    target_clean = re.sub(r'^https?://', '', smart_domain_input).strip('/')

    strength_mode = st.sidebar.radio(
        "Authority Strength Filter",
        ["Stronger or Equal (>= Target)", "Similar Strength (±30%)", "All Strong Domains (Top Authority)"]
    )
    candidate_pool_size = st.sidebar.slider("DNS Scan Pool Size (Candidates)", min_value=50, max_value=1000, value=250, step=50)

    # ==========================================================
    # SIDEBAR: BASE FILTERS (GENERAL EXPLORER)
    # ==========================================================
    st.sidebar.markdown("---")
    st.sidebar.header("🔍 General Explorer Filters")
    if 'Extension' in df.columns:
        available_tlds = sorted(df['Extension'].dropna().astype(str).unique().tolist())
        selected_tlds = st.sidebar.multiselect("Select TLDs", options=available_tlds)
    else:
        selected_tlds = []

    range_options = [
        "All Ranges", "1 - 10", "10 - 20", "20 - 50", "50 - 100",
        "100 - 500", "500 - 1500", "1500+ (High Authority)", "Custom Range"
    ]
    selected_range = st.sidebar.selectbox("Referring Domains Range", range_options)

    # ==========================================================
    # MAIN AREA: SMART DOMAIN DNS + RELATED ENGINE
    # ==========================================================
    if target_clean:
        st.subheader(f"🔎 Deep DNS & Authority Analysis for: `{target_clean}`")
        
        with st.spinner(f"Fetching live MX, NS & TXT records for {target_clean}..."):
            target_dns = get_full_dns(target_clean)
            detected_sigs = extract_dns_signatures(target_dns)

        # Show Target Live DNS Profile
        c_mx, c_ns, c_txt = st.columns(3)
        c_mx.info(f"**MX Records:**\n{target_dns['MX']}")
        c_ns.info(f"**NS Records:**\n{target_dns['NS']}")
        c_txt.info(f"**TXT / SPF Records:**\n{target_dns['TXT'][:250]}")

        if detected_sigs:
            st.success(f"🧬 **Detected DNS Footprints (Auto-Matching Keywords):** `{', '.join(detected_sigs)}`")
        else:
            st.warning("No standard DNS provider keywords detected from target. Matching by authority strength.")

        # Check Target Authority in CSV
        target_row = df[df['Domain'].astype(str) == target_clean]
        if not target_row.empty:
            t_ref = int(target_row['Referring_Domains'].values[0])
            t_rank = float(target_row['OpenPageRank_Score'].values[0])
            t_ext = str(target_row['Extension'].values[0])
            
            m1, m2, m3 = st.columns(3)
            m1.metric("Target Referring Domains", f"{t_ref:,}")
            m2.metric("Target PageRank Score", f"{t_rank:.2f}")
            m3.metric("Target Extension", f".{t_ext}")
        else:
            t_ref = 50
            t_rank = 3.0
            st.caption(f"`{target_clean}` not in CSV directly — using baseline strong authority threshold (Ref >= {t_ref}).")

        # Build Candidate Pool based on Strength Mode
        pool = df[df['Domain'].astype(str) != target_clean].copy()
        if selected_tlds:
            pool = pool[pool['Extension'].isin(selected_tlds)]

        if strength_mode == "Stronger or Equal (>= Target)":
            pool = pool[pool['Referring_Domains'] >= t_ref]
        elif strength_mode == "Similar Strength (±30%)":
            pool = pool[(pool['Referring_Domains'] >= int(t_ref * 0.7)) & (pool['Referring_Domains'] <= int(t_ref * 1.3) + 10)]

        # Pick strongest candidates to scan live DNS
        pool = pool.sort_values(by=['Referring_Domains', 'OpenPageRank_Score'], ascending=[False, False]).head(candidate_pool_size)

        if len(pool) > 0:
            with st.spinner(f"Scanning MX, NS & TXT across {len(pool)} strong domains to find DNS matches..."):
                domains_to_scan = pool['Domain'].tolist()
                with ThreadPoolExecutor(max_workers=80) as executor:
                    scanned_results = list(executor.map(get_full_dns, domains_to_scan))
                
                dns_df = pd.DataFrame(scanned_results)
                merged = pd.merge(pool, dns_df, on='Domain', how='left')

                # Score how many DNS footprints match (MX, NS, or TXT)
                def calculate_dns_match(row):
                    if not detected_sigs:
                        return "Authority Match", 1
                    row_dns = f"{row['MX']} {row['NS']} {row['TXT']}".lower()
                    matched_tags = [sig for sig in detected_sigs if sig in row_dns]
                    return (", ".join(matched_tags) if matched_tags else "None"), len(matched_tags)

                match_info = merged.apply(calculate_dns_match, axis=1)
                merged['Matched_DNS_Footprints'] = [m[0] for m in match_info]
                merged['Match_Score'] = [m[1] for m in match_info]

                # Filter only domains that matched at least one DNS footprint (if target had signatures)
                if detected_sigs:
                    related_final = merged[merged['Match_Score'] > 0].copy()
                else:
                    related_final = merged.copy()

                related_final = related_final.sort_values(
                    by=['Match_Score', 'Referring_Domains', 'OpenPageRank_Score'],
                    ascending=[False, False, False]
                )

            total_found = len(related_final)
            if total_found > 0:
                PAGE_SIZE = 15
                total_pages = math.ceil(total_found / PAGE_SIZE)
                st.write(f"🔥 **Found {total_found} Strong Related Domains matching DNS (MX / NS / TXT):**")
                
                curr_page = st.selectbox(f"Select Page (1 to {total_pages})", list(range(1, total_pages + 1)), key="smart_page")
                start_i = (curr_page - 1) * PAGE_SIZE
                
                display_cols = ['Domain', 'Referring_Domains', 'OpenPageRank_Score', 'Matched_DNS_Footprints', 'MX', 'NS', 'TXT']
                st.dataframe(related_final[display_cols].iloc[start_i:start_i + PAGE_SIZE], use_container_width=True)

                dl_csv = related_final[display_cols].to_csv(index=False).encode('utf-8-sig')
                st.download_button(
                    label=f"📥 Download All {total_found} Related Strong Domains (CSV)",
                    data=dl_csv,
                    file_name=f"smart_dns_related_{target_clean}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No domains matched the exact DNS footprints in this pool. Try increasing 'DNS Scan Pool Size' or switching Authority Strength Filter.")
        st.markdown("---")

    # ==========================================================
    # GENERAL EXPLORER (WHEN NO TARGET DOMAIN IS ENTERED)
    # ==========================================================
    st.subheader(f"📊 General Dataset Explorer: {selected_policy}")
    filtered_df = df.copy()

    if selected_range == "1 - 10":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 1) & (filtered_df['Referring_Domains'] <= 10)]
    elif selected_range == "10 - 20":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 10) & (filtered_df['Referring_Domains'] <= 20)]
    elif selected_range == "20 - 50":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 20) & (filtered_df['Referring_Domains'] <= 50)]
    elif selected_range == "50 - 100":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 50) & (filtered_df['Referring_Domains'] <= 100)]
    elif selected_range == "100 - 500":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 100) & (filtered_df['Referring_Domains'] <= 500)]
    elif selected_range == "500 - 1500":
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= 500) & (filtered_df['Referring_Domains'] <= 1500)]
    elif selected_range == "1500+ (High Authority)":
        filtered_df = filtered_df[filtered_df['Referring_Domains'] >= 1500]
    elif selected_range == "Custom Range":
        c1, c2 = st.sidebar.columns(2)
        min_v = c1.number_input("Min", value=int(df['Referring_Domains'].min()), step=1)
        max_v = c2.number_input("Max", value=int(df['Referring_Domains'].max()), step=1)
        filtered_df = filtered_df[(filtered_df['Referring_Domains'] >= min_v) & (filtered_df['Referring_Domains'] <= max_v)]

    if selected_tlds:
        filtered_df = filtered_df[filtered_df['Extension'].isin(selected_tlds)]

    sort_order = st.sidebar.radio("Sort General Results", ["High to Low (Descending)", "Low to High (Ascending)"])
    filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=(sort_order == "Low to High (Ascending)"))

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Unique Domains", f"{len(df):,}")
    col2.metric("Filtered Domains", f"{len(filtered_df):,}")
    col3.metric("Selected Range", selected_range)

    st.dataframe(filtered_df.head(5000), use_container_width=True)

    csv_dl = filtered_df.to_csv(index=False).encode('utf-8-sig')
    st.download_button(
        label="📥 Download Filtered List (CSV)",
        data=csv_dl,
        file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
        mime="text/csv"
    )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")
