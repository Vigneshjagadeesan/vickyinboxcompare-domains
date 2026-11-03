import streamlit as st
import pandas as pd
import os
import glob
import re
import math

st.set_page_config(page_title="Domain Intelligence Dashboard", layout="wide")

st.title("🎯 High-Authority Domain Intelligence & Matcher")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
    use_cols = ['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']
    
    for f in part_files:
        try:
            temp_df = pd.read_csv(f, usecols=lambda c: c in use_cols)
            df_list.append(temp_df)
        except Exception:
            temp_df = pd.read_csv(f)
            df_list.append(temp_df)
            
    df = pd.concat(df_list, ignore_index=True)
    
    # Clean domain column & remove duplicates across chunks
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
    st.sidebar.markdown("---")
    st.sidebar.header("🎯 Target Domain Matcher")
    target_input = st.sidebar.text_input("Enter Target Domain (e.g. site.com)", "").strip().lower()
    target_clean = re.sub(r'^https?://', '', target_input).strip('/')

    match_mode = st.sidebar.radio(
        "Match Strength Filter",
        ["Super Strong Only (Higher Authority)", "Close Range (±20%)", "Broad Range (±50%)"]
    )
    same_tld_only = st.sidebar.checkbox("Same TLD only (Match Extension)", value=False)
    
    top_limit = st.sidebar.slider("Total Matching Domains Pool", min_value=15, max_value=200, value=200, step=15)

    st.sidebar.markdown("---")
    st.sidebar.header("🔍 Manual Explorer Filters")
    
    if 'Extension' in df.columns:
        available_tlds = sorted(df['Extension'].dropna().astype(str).unique().tolist())
        selected_tlds = st.sidebar.multiselect("Select TLDs", options=available_tlds)
    else:
        selected_tlds = []

    search_keyword = st.sidebar.text_input("General Domain Search (Contains)")

    range_options = [
        "All Ranges",
        "1 - 10",
        "10 - 20",
        "20 - 50",
        "50 - 100",
        "100 - 500",
        "500 - 1500",
        "1500+ (High Authority)",
        "Custom Range"
    ]
    selected_range = st.sidebar.selectbox("Select Count Range", range_options)

    # General filtering
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

    if search_keyword:
        filtered_df = filtered_df[filtered_df['Domain'].astype(str).str.contains(search_keyword.lower(), na=False)]

    # --- TARGET DOMAIN LOOKALIKE ENGINE (DUPLICATE-FREE) ---
    if target_clean:
        st.subheader(f"🎯 Target Analysis: `{target_clean}`")
        target_row = df[df['Domain'].astype(str) == target_clean]
        keyword_seed = target_clean.split('.')[0]

        if not target_row.empty:
            t_ref = int(target_row['Referring_Domains'].values[0])
            t_rank = float(target_row['OpenPageRank_Score'].values[0])
            t_ext = str(target_row['Extension'].values[0])
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Target Referring Domains", f"{t_ref:,}")
            c2.metric("Target PageRank Score", f"{t_rank:.2f}")
            c3.metric("Target TLD", f".{t_ext}")

            if match_mode == "Super Strong Only (Higher Authority)":
                min_match_ref = t_ref
                max_match_ref = int(df['Referring_Domains'].max())
            elif match_mode == "Close Range (±20%)":
                min_match_ref = max(1, int(t_ref * 0.8))
                max_match_ref = int(t_ref * 1.2) + 2
            else:
                min_match_ref = max(1, int(t_ref * 0.5))
                max_match_ref = int(t_ref * 1.5) + 5

            match_pool = df[
                (df['Domain'].astype(str) != target_clean) &
                (df['Referring_Domains'] >= min_match_ref) &
                (df['Referring_Domains'] <= max_match_ref)
            ].copy()

            if same_tld_only:
                match_pool = match_pool[match_pool['Extension'] == t_ext]

            # Drop duplicates in match pool
            match_pool = match_pool.drop_duplicates(subset=['Domain'], keep='first')

            match_pool['Rank_Score_Diff'] = (match_pool['OpenPageRank_Score'] - t_rank).abs()
            match_pool = match_pool.sort_values(
                by=['Rank_Score_Diff', 'Referring_Domains'],
                ascending=[True, False]
            )

            final_matches = match_pool.head(top_limit)

        else:
            st.warning(f"`{target_clean}` list-la direct-a illa. Matching by keyword and high authority:")
            keyword_pool = df[df['Domain'].astype(str).str.contains(keyword_seed, na=False)].copy()
            keyword_pool = keyword_pool.drop_duplicates(subset=['Domain'], keep='first')
            final_matches = keyword_pool.sort_values(by='Referring_Domains', ascending=False).head(top_limit)

        total_matches = len(final_matches)

        if total_matches > 0:
            PAGE_SIZE = 15
            total_pages = math.ceil(total_matches / PAGE_SIZE)

            st.write(f"🔥 **Unique Matched Domains: {total_matches} (Showing 15 per page)**")

            p_col1, p_col2 = st.columns([1, 4])
            with p_col1:
                current_page = st.selectbox(f"Select Page (Total {total_pages} Pages)", list(range(1, total_pages + 1)))

            start_idx = (current_page - 1) * PAGE_SIZE
            end_idx = start_idx + PAGE_SIZE
            page_data = final_matches.iloc[start_idx:end_idx]

            st.dataframe(page_data[['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']], use_container_width=True)
            st.caption(f"Showing items {start_idx + 1} to {min(end_idx, total_matches)} of {total_matches}")

            match_csv = final_matches.to_csv(index=False).encode('utf-8-sig')
            st.download_button(
                label=f"📥 Download All {total_matches} Unique Domains (CSV)",
                data=match_csv,
                file_name=f"unique_strong_matches_{target_clean}.csv",
                mime="text/csv"
            )
        else:
            st.info("No matching domains found. Try selecting 'Broad Range' or untick 'Same TLD'.")

        st.markdown("---")

    # Regular Explorer Section
    st.subheader(f"General Explorer: {selected_policy}")
    sort_order = st.sidebar.radio("Sort General Results", ["Low to High (Ascending)", "High to Low (Descending)"])
    if sort_order == "Low to High (Ascending)":
        filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=True)
    else:
        filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=False)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Unique Domains", f"{len(df):,}")
    col2.metric("Filtered Domains", f"{len(filtered_df):,}")
    col3.metric("Selected Range", selected_range)

    st.dataframe(filtered_df[['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']].head(5000), use_container_width=True)

    csv_dl = filtered_df.to_csv(index=False).encode('utf-8-sig')
    st.download_button(
        label="📥 Download General Filtered Domains (CSV)",
        data=csv_dl,
        file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
        mime="text/csv"
    )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")
