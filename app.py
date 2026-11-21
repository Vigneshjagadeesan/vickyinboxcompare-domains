import streamlit as st
import pandas as pd
import os
import glob
import re
import math
import gc
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title="Domain Intelligence Matcher", layout="wide")

st.title("🎯 Domain Intelligence & DNS Fingerprint Matcher")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- LIGHTWEIGHT DNS SCANNER ---
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

def extract_dns_signatures(dns_dict):
    raw_hosts = re.findall(r'([a-z0-9-]+\.[a-z]{2,})', f"{dns_dict['MX']} {dns_dict['NS']}")
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

# --- ULTRA-LOW MEMORY DATA LOADER ---
@st.cache_data(max_entries=1, ttl=1800)
def load_policy_data(prefix):
    gc.collect()
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
        
    use_cols = ['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']
    df_list = []
    
    for f in part_files:
        temp_df = pd.read_csv(f, usecols=lambda c: c in use_cols)
        if 'Referring_Domains' in temp_df.columns:
            temp_df['Referring_Domains'] = pd.to_numeric(temp_df['Referring_Domains'], errors='coerce').fillna(0).astype('int32')
        if 'OpenPageRank_Score' in temp_df.columns:
            temp_df['OpenPageRank_Score'] = pd.to_numeric(temp_df['OpenPageRank_Score'], errors='coerce').fillna(0.0).astype('float32')
        df_list.append(temp_df)
        
    df = pd.concat(df_list, ignore_index=True)
    del df_list
    gc.collect()
    
    if 'Domain' in df.columns:
        df['Domain'] = df['Domain'].astype(str).str.strip().str.lower()
        df = df.drop_duplicates(subset=['Domain'], keep='first')
    if 'Extension' in df.columns:
        df['Extension'] = df['Extension'].astype('category')
        
    gc.collect()
    return df

policies = {
    "p=none Policy": "POWER_p_none_domains",
    "no_dmarc Policy": "POWER_no_dmarc_domains",
    "p=quarantine Policy": "POWER_p_quarantine_domains"
}

selected_policy = st.sidebar.selectbox("Select DMARC Policy File", list(policies.keys()))
df = load_policy_data(policies[selected_policy])

if df is not None:
    st.sidebar.header("🚀 Smart Domain Analyzer")
    smart_domain_input = st.sidebar.text_input(
        "Enter Any Domain (Auto DNS + Related)",
        placeholder="e.g. reef.org"
    ).strip().lower()
    target_clean = re.sub(r'^https?://', '', smart_domain_input).strip('/')

    strength_mode = st.sidebar.radio(
        "Authority Strength Filter",
        ["Stronger or Equal (>= Target)", "Similar Strength (±30%)", "All Strong Domains"]
    )
    # Safe pool size to prevent Streamlit Cloud 1GB RAM crash
    candidate_pool_size = st.sidebar.slider("DNS Scan Pool Size", min_value=30, max_value=200, value=80, step=10)

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

    # --- SMART TARGET DOMAIN ENGINE ---
    if target_clean:
        st.subheader(f"🔎 Deep DNS & Authority Analysis for: `{target_clean}`")
        
        with st.spinner(f"Checking live MX, NS & TXT for {target_clean}..."):
            target_dns = get_full_dns(target_clean)
            detected_sigs = extract_dns_signatures(target_dns)

        c_mx, c_ns, c_txt = st.columns(3)
        c_mx.info(f"**MX:** {target_dns['MX']}")
        c_ns.info(f"**NS:** {target_dns['NS']}")
        c_txt.info(f"**TXT:** {target_dns['TXT'][:200]}")

        if detected_sigs:
            st.success(f"🧬 **Detected DNS Footprints:** `{', '.join(detected_sigs)}`")

        target_row = df[df['Domain'] == target_clean]
        if not target_row.empty:
            t_ref = int(target_row['Referring_Domains'].values[0])
            t_rank = float(target_row['OpenPageRank_Score'].values[0])
            t_ext = str(target_row['Extension'].values[0])
            
            m1, m2, m3 = st.columns(3)
            m1.metric("Referring Domains", f"{t_ref:,}")
            m2.metric("PageRank Score", f"{t_rank:.2f}")
            m3.metric("Extension", f".{t_ext}")
        else:
            t_ref = 50
            st.caption(f"`{target_clean}` not in CSV — matching strong domains (Ref >= {t_ref}).")

        pool = df[df['Domain'] != target_clean]
        if selected_tlds:
            pool = pool[pool['Extension'].isin(selected_tlds)]

        if strength_mode == "Stronger or Equal (>= Target)":
            pool = pool[pool['Referring_Domains'] >= t_ref]
        elif strength_mode == "Similar Strength (±30%)":
            pool = pool[(pool['Referring_Domains'] >= int(t_ref * 0.7)) & (pool['Referring_Domains'] <= int(t_ref * 1.3) + 10)]

        pool = pool.sort_values(by=['Referring_Domains', 'OpenPageRank_Score'], ascending=[False, False]).head(candidate_pool_size).copy()

        if len(pool) > 0:
            with st.spinner(f"Scanning DNS across {len(pool)} strong domains..."):
                domains_to_scan = pool['Domain'].tolist()
                # Safe max_workers=15 to keep RAM low
                with ThreadPoolExecutor(max_workers=15) as executor:
                    scanned_results = list(executor.map(get_full_dns, domains_to_scan))
                
                dns_df = pd.DataFrame(scanned_results)
                merged = pd.merge(pool, dns_df, on='Domain', how='left')

                def calculate_dns_match(row):
                    if not detected_sigs:
                        return "Authority Match", 1
                    row_dns = f"{row['MX']} {row['NS']} {row['TXT']}".lower()
                    matched_tags = [sig for sig in detected_sigs if sig in row_dns]
                    return (", ".join(matched_tags) if matched_tags else "None"), len(matched_tags)

                match_info = merged.apply(calculate_dns_match, axis=1)
                merged['Matched_DNS'] = [m[0] for m in match_info]
                merged['Match_Score'] = [m[1] for m in match_info]

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
                st.write(f"🔥 **Found {total_found} Strong Related Domains:**")
                
                curr_page = st.selectbox(f"Select Page (1 to {total_pages})", list(range(1, total_pages + 1)), key="smart_page")
                start_i = (curr_page - 1) * PAGE_SIZE
                
                display_cols = ['Domain', 'Referring_Domains', 'OpenPageRank_Score', 'Matched_DNS', 'MX', 'NS', 'TXT']
                st.dataframe(related_final[display_cols].iloc[start_i:start_i + PAGE_SIZE], use_container_width=True)

                dl_csv = related_final[display_cols].to_csv(index=False).encode('utf-8-sig')
                st.download_button(
                    label=f"📥 Download {total_found} Related Domains (CSV)",
                    data=dl_csv,
                    file_name=f"related_{target_clean}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No exact DNS footprint matches found in this pool. Try increasing 'DNS Scan Pool Size'.")
        gc.collect()
        st.markdown("---")

    # --- GENERAL EXPLORER ---
    st.subheader(f"📊 General Explorer: {selected_policy}")
    filtered_df = df

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

    st.dataframe(filtered_df.head(2000), use_container_width=True)

    csv_dl = filtered_df.to_csv(index=False).encode('utf-8-sig')
    st.download_button(
        label="📥 Download Filtered List (CSV)",
        data=csv_dl,
        file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
        mime="text/csv"
    )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")
