import streamlit as st
import pandas as pd
import os
import glob
import re
import math
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title="Domain Intelligence + MX/NS Scanner", layout="wide")

st.title("🎯 High-Authority Domain + Live MX & NS Intelligence")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- LIVE DNS LOOKUP FUNCTION ---
def get_dns_records(domain):
    mx_list = []
    ns_list = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        mx_answers = resolver.resolve(domain, 'MX')
        mx_list = [str(r.exchange).rstrip('.').lower() for r in mx_answers]
    except Exception:
        pass

    try:
        ns_answers = resolver.resolve(domain, 'NS')
        ns_list = [str(r.target).rstrip('.').lower() for r in ns_answers]
    except Exception:
        pass

    return {
        "Domain": domain,
        "MX_Records": ", ".join(mx_list) if mx_list else "None",
        "NS_Records": ", ".join(ns_list) if ns_list else "None"
    }

def bulk_dns_lookup(domains_list):
    with ThreadPoolExecutor(max_workers=25) as executor:
        results = list(executor.map(get_dns_records, domains_list))
    return pd.DataFrame(results)

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
        
    df_list = []
    for f in part_files:
        temp_df = pd.read_csv(f)
        df_list.append(temp_df)
            
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
    # --- SIDEBAR: MX & NS FILTER ---
    st.sidebar.markdown("---")
    st.sidebar.header("🌐 MX & NS Record Filter")
    mx_filter_input = st.sidebar.text_input("Filter by MX Keyword (e.g. google, aspmx, outlook, zoho)", "").strip().lower()
    ns_filter_input = st.sidebar.text_input("Filter by NS Keyword (e.g. googledomains, cloudflare, aws)", "").strip().lower()
    scan_limit = st.sidebar.slider("Live DNS Scan Pool Size", min_value=20, max_value=300, value=100, step=20)

    # --- SIDEBAR: TARGET DOMAIN MATCHER ---
    st.sidebar.markdown("---")
    st.sidebar.header("🎯 Target Domain Matcher")
    target_input = st.sidebar.text_input("Enter Target Domain (e.g. reef.org)", "").strip().lower()
    target_clean = re.sub(r'^https?://', '', target_input).strip('/')

    match_mode = st.sidebar.radio(
        "Match Strength Filter",
        ["Super Strong Only (Higher Authority)", "Close Range (±20%)", "Broad Range (±50%)"]
    )
    same_tld_only = st.sidebar.checkbox("Same TLD only", value=False)
    top_limit = st.sidebar.slider("Total Matching Domains Pool", min_value=15, max_value=200, value=100, step=15)

    # --- SIDEBAR: GENERAL FILTERS ---
    st.sidebar.markdown("---")
    st.sidebar.header("🔍 General Explorer Filters")
    if 'Extension' in df.columns:
        available_tlds = sorted(df['Extension'].dropna().astype(str).unique().tolist())
        selected_tlds = st.sidebar.multiselect("Select TLDs", options=available_tlds)
    else:
        selected_tlds = []

    search_keyword = st.sidebar.text_input("Domain Name Contains")

    range_options = [
        "All Ranges", "1 - 10", "10 - 20", "20 - 50", "50 - 100",
        "100 - 500", "500 - 1500", "1500+ (High Authority)", "Custom Range"
    ]
    selected_range = st.sidebar.selectbox("Referring Domains Range", range_options)

    # Apply General Filters
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
    if search_keyword:
        filtered_df = filtered_df[filtered_df['Domain'].astype(str).str.contains(search_keyword.lower(), na=False)]

    # --- SECTION 1: TARGET DOMAIN + MX/NS MATCHER ---
    if target_clean:
        st.subheader(f"🎯 Target Domain Intelligence: `{target_clean}`")
        
        # Check live DNS for target domain itself
        target_dns = get_dns_records(target_clean)
        d1, d2 = st.columns(2)
        d1.info(f"**Target Live MX:** {target_dns['MX_Records']}")
        d2.info(f"**Target Live NS:** {target_dns['NS_Records']}")

        target_row = df[df['Domain'].astype(str) == target_clean]
        keyword_seed = target_clean.split('.')[0]

        if not target_row.empty:
            t_ref = int(target_row['Referring_Domains'].values[0])
            t_rank = float(target_row['OpenPageRank_Score'].values[0])
            t_ext = str(target_row['Extension'].values[0])

            c1, c2, c3 = st.columns(3)
            c1.metric("Target Referring Domains", f"{t_ref:,}")
            c2.metric("Target PageRank", f"{t_rank:.2f}")
            c3.metric("Target TLD", f".{t_ext}")

            if match_mode == "Super Strong Only (Higher Authority)":
                min_match_ref, max_match_ref = t_ref, int(df['Referring_Domains'].max())
            elif match_mode == "Close Range (±20%)":
                min_match_ref, max_match_ref = max(1, int(t_ref * 0.8)), int(t_ref * 1.2) + 2
            else:
                min_match_ref, max_match_ref = max(1, int(t_ref * 0.5)), int(t_ref * 1.5) + 5

            match_pool = df[
                (df['Domain'].astype(str) != target_clean) &
                (df['Referring_Domains'] >= min_match_ref) &
                (df['Referring_Domains'] <= max_match_ref)
            ].copy()

            if same_tld_only:
                match_pool = match_pool[match_pool['Extension'] == t_ext]

            match_pool = match_pool.drop_duplicates(subset=['Domain'], keep='first')
            match_pool['Rank_Score_Diff'] = (match_pool['OpenPageRank_Score'] - t_rank).abs()
            match_pool = match_pool.sort_values(by=['Rank_Score_Diff', 'Referring_Domains'], ascending=[True, False])
            final_matches = match_pool.head(top_limit)
        else:
            st.warning(f"`{target_clean}` CSV-la direct-a illa. Matching by keyword & high authority:")
            keyword_pool = df[df['Domain'].astype(str).str.contains(keyword_seed, na=False)].copy()
            keyword_pool = keyword_pool.drop_duplicates(subset=['Domain'], keep='first')
            final_matches = keyword_pool.sort_values(by='Referring_Domains', ascending=False).head(top_limit)

        if len(final_matches) > 0:
            # If user wants MX/NS scan on related domains
            if mx_filter_input or ns_filter_input or st.button("🔍 Scan Live MX & NS for Related Domains"):
                with st.spinner(f"Scanning Live MX & NS records for {len(final_matches)} related domains..."):
                    dns_df = bulk_dns_lookup(final_matches['Domain'].tolist())
                    final_matches = pd.merge(final_matches, dns_df, on='Domain', how='left')

                    if mx_filter_input:
                        final_matches = final_matches[final_matches['MX_Records'].str.contains(mx_filter_input, case=False, na=False)]
                    if ns_filter_input:
                        final_matches = final_matches[final_matches['NS_Records'].str.contains(ns_filter_input, case=False, na=False)]

            total_matches = len(final_matches)
            if total_matches > 0:
                PAGE_SIZE = 15
                total_pages = math.ceil(total_matches / PAGE_SIZE)
                st.write(f"🔥 **Matched Related Domains: {total_matches} (15 per page)**")
                current_page = st.selectbox(f"Select Page (1 to {total_pages})", list(range(1, total_pages + 1)), key="target_page")
                start_idx = (current_page - 1) * PAGE_SIZE
                page_data = final_matches.iloc[start_idx:start_idx + PAGE_SIZE]
                st.dataframe(page_data, use_container_width=True)

                match_csv = final_matches.to_csv(index=False).encode('utf-8-sig')
                st.download_button(
                    label=f"📥 Download All {total_matches} Matched Domains (CSV)",
                    data=match_csv,
                    file_name=f"related_mx_ns_{target_clean}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No related domains matched that MX/NS keyword. Try increasing 'Total Matching Domains Pool' or changing keyword.")
        st.markdown("---")

    # --- SECTION 2: STANDALONE MX & NS SEARCH ON GENERAL FILTERED DOMAINS ---
    st.subheader(f"🌐 General Explorer & Live MX/NS Filter: {selected_policy}")

    if mx_filter_input or ns_filter_input:
        st.info(f"Filtering by MX: `{mx_filter_input or 'Any'}` | NS: `{ns_filter_input or 'Any'}` (Scanning top {scan_limit} filtered domains)")
        
        # Check if CSV already has MX/NS columns
        has_mx_col = any('mx' in c.lower() for c in filtered_df.columns)
        has_ns_col = any('ns' in c.lower() for c in filtered_df.columns)

        if has_mx_col and has_ns_col:
            mx_col = [c for c in filtered_df.columns if 'mx' in c.lower()][0]
            ns_col = [c for c in filtered_df.columns if 'ns' in c.lower()][0]
            res_df = filtered_df.copy()
            if mx_filter_input:
                res_df = res_df[res_df[mx_col].astype(str).str.contains(mx_filter_input, case=False, na=False)]
            if ns_filter_input:
                res_df = res_df[res_df[ns_col].astype(str).str.contains(ns_filter_input, case=False, na=False)]
        else:
            # Live DNS lookup on top N candidates
            candidates = filtered_df.sort_values(by="Referring_Domains", ascending=False).head(scan_limit).copy()
            with st.spinner(f"Checking Live MX & NS records for {len(candidates)} domains..."):
                dns_results = bulk_dns_lookup(candidates['Domain'].tolist())
                merged_df = pd.merge(candidates, dns_results, on='Domain', how='left')
                if mx_filter_input:
                    merged_df = merged_df[merged_df['MX_Records'].str.contains(mx_filter_input, case=False, na=False)]
                if ns_filter_input:
                    merged_df = merged_df[merged_df['NS_Records'].str.contains(ns_filter_input, case=False, na=False)]
                res_df = merged_df

        st.success(f"✅ Found **{len(res_df)}** domains matching your MX/NS criteria!")
        st.dataframe(res_df, use_container_width=True)

        if len(res_df) > 0:
            mx_csv = res_df.to_csv(index=False).encode('utf-8-sig')
            st.download_button(
                label=f"📥 Download {len(res_df)} MX/NS Filtered Domains (CSV)",
                data=mx_csv,
                file_name=f"mx_ns_filtered_{mx_filter_input}_{ns_filter_input}.csv",
                mime="text/csv"
            )
    else:
        sort_order = st.sidebar.radio("Sort General Results", ["Low to High (Ascending)", "High to Low (Descending)"])
        if sort_order == "Low to High (Ascending)":
            filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=True)
        else:
            filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=False)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Unique Domains", f"{len(df):,}")
        col2.metric("Filtered Domains", f"{len(filtered_df):,}")
        col3.metric("Selected Range", selected_range)

        st.dataframe(filtered_df.head(5000), use_container_width=True)

        csv_dl = filtered_df.to_csv(index=False).encode('utf-8-sig')
        st.download_button(
            label="📥 Download General Filtered Domains (CSV)",
            data=csv_dl,
            file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
            mime="text/csv"
        )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")
