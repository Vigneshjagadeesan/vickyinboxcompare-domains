import streamlit as st
import pandas as pd
import os
import glob
import re
import math
import gc
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title="Domain Intelligence + MX Search", layout="wide")

st.title("🎯 Domain Intelligence & Live MX / DNS Matcher")

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
    # ==========================================================
    # 1. DIRECT MX / DNS KEYWORD SEARCH BOX
    # ==========================================================
    st.sidebar.header("📧 Direct MX / DNS Search")
    direct_mx_input = st.sidebar.text_input(
        "Search by MX / Provider Keyword",
        placeholder="e.g. google, aspmx, outlook, zoho"
    ).strip().lower()
    mx_scan_limit = st.sidebar.slider("MX Scan Pool Size", min_value=30, max_value=250, value=100, step=10)

    # ==========================================================
    # 2. SMART DOMAIN ANALYZER (TARGET DOMAIN INPUT)
    # ==========================================================
    st.sidebar.markdown("---")
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
    candidate_pool_size = st.sidebar.slider("Related Scan Pool Size", min_value=30, max_value=200, value=80, step=10)

    # ==========================================================
    # 3. GENERAL EXPLORER FILTERS
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

    # Apply base range & TLD filters first
    base_filtered = df
    if selected_range == "1 - 10":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 1) & (base_filtered['Referring_Domains'] <= 10)]
    elif selected_range == "10 - 20":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 10) & (base_filtered['Referring_Domains'] <= 20)]
    elif selected_range == "20 - 50":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 20) & (base_filtered['Referring_Domains'] <= 50)]
    elif selected_range == "50 - 100":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 50) & (base_filtered['Referring_Domains'] <= 100)]
    elif selected_range == "100 - 500":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 100) & (base_filtered['Referring_Domains'] <= 500)]
    elif selected_range == "500 - 1500":
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= 500) & (base_filtered['Referring_Domains'] <= 1500)]
    elif selected_range == "1500+ (High Authority)":
        base_filtered = base_filtered[base_filtered['Referring_Domains'] >= 1500]
    elif selected_range == "Custom Range":
        c1, c2 = st.sidebar.columns(2)
        min_v = c1.number_input("Min", value=int(df['Referring_Domains'].min()), step=1)
        max_v = c2.number_input("Max", value=int(df['Referring_Domains'].max()), step=1)
        base_filtered = base_filtered[(base_filtered['Referring_Domains'] >= min_v) & (base_filtered['Referring_Domains'] <= max_v)]

    if selected_tlds:
        base_filtered = base_filtered[base_filtered['Extension'].isin(selected_tlds)]

    # ==========================================================
    # OUTPUT A: DIRECT MX KEYWORD SEARCH RESULTS
    # ==========================================================
    if direct_mx_input:
        st.subheader(f"📧 Direct MX Search Results for: `{direct_mx_input}`")
        
        mx_candidates = base_filtered.sort_values(by=['Referring_Domains', 'OpenPageRank_Score'], ascending=[False, False]).head(mx_scan_limit).copy()
        
        if len(mx_candidates) > 0:
            with st.spinner(f"Scanning MX & DNS records across top {len(mx_candidates)} filtered domains..."):
                with ThreadPoolExecutor(max_workers=15) as executor:
                    mx_scanned = list(executor.map(get_full_dns, mx_candidates['Domain'].tolist()))
                
                mx_dns_df = pd.DataFrame(mx_scanned)
                mx_merged = pd.merge(mx_candidates, mx_dns_df, on='Domain', how='left')
                
                # Match MX keyword (also checks TXT/NS if needed, prioritizing MX)
                mx_matches = mx_merged[
                    mx_merged['MX'].str.contains(direct_mx_input, case=False, na=False)
                ].copy()

            total_mx = len(mx_matches)
            if total_mx > 0:
                PAGE_SIZE = 15
                total_mx_pages = math.ceil(total_mx / PAGE_SIZE)
                st.success(f"✅ Found **{total_mx}** Strong Domains using `{direct_mx_input}` MX!")
                
                mx_page = st.selectbox(f"Select MX Result Page (1 to {total_mx_pages})", list(range(1, total_mx_pages + 1)), key="mx_page")
                s_idx = (mx_page - 1) * PAGE_SIZE
                
                cols = ['Domain', 'Referring_Domains', 'OpenPageRank_Score', 'MX', 'NS', 'TXT']
                st.dataframe(mx_matches[cols].iloc[s_idx:s_idx + PAGE_SIZE], use_container_width=True)

                mx_csv = mx_matches[cols].to_csv(index=False).encode('utf-8-sig')
                st.download_button(
                    label=f"📥 Download {total_mx} `{direct_mx_input}` MX Domains (CSV)",
                    data=mx_csv,
                    file_name=f"mx_{direct_mx_input}_domains.csv",
                    mime="text/csv"
                )
            else:
                st.info(f"No domains matched `{direct_mx_input}` MX in the top {mx_scan_limit} pool. Try increasing 'MX Scan Pool Size' or changing the range filter.")
        gc.collect()
        st.markdown("---")

    # ==========================================================
    # OUTPUT B: SMART TARGET DOMAIN ENGINE
    # ==========================================================
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

        pool = base_filtered[base_filtered['Domain'] != target_clean]

        if strength_mode == "Stronger or Equal (>= Target)":
            pool = pool[pool['Referring_Domains'] >= t_ref]
        elif strength_mode == "Similar Strength (±30%)":
            pool = pool[(pool['Referring_Domains'] >= int(t_ref * 0.7)) & (pool['Referring_Domains'] <= int(t_ref * 1.3) + 10)]

        pool = pool.sort_values(by=['Referring_Domains', 'OpenPageRank_Score'], ascending=[False, False]).head(candidate_pool_size).copy()

        if len(pool) > 0:
            with st.spinner(f"Scanning DNS across {len(pool)} strong domains..."):
                with ThreadPoolExecutor(max_workers=15) as executor:
                    scanned_results = list(executor.map(get_full_dns, pool['Domain'].tolist()))
                
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
                st.info("No exact DNS footprint matches found in this pool. Try increasing 'Related Scan Pool Size'.")
        gc.collect()
        st.markdown("---")

    # ==========================================================
    # OUTPUT C: GENERAL EXPLORER
    # ==========================================================
    st.subheader(f"📊 General Explorer: {selected_policy}")
    sort_order = st.sidebar.radio("Sort General Results", ["High to Low (Descending)", "Low to High (Ascending)"])
    sorted_df = base_filtered.sort_values(by="Referring_Domains", ascending=(sort_order == "Low to High (Ascending)"))

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Unique Domains", f"{len(df):,}")
    col2.metric("Filtered Domains", f"{len(sorted_df):,}")
    col3.metric("Selected Range", selected_range)

    st.dataframe(sorted_df.head(2000), use_container_width=True)

    csv_dl = sorted_df.to_csv(index=False).encode('utf-8-sig')
    st.download_button(
        label="📥 Download Filtered List (CSV)",
        data=csv_dl,
        file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
        mime="text/csv"
    )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")
