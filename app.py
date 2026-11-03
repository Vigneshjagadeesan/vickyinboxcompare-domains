import streamlit as st
import pandas as pd
import os
import glob
import re

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
    
    # Clean input
    target_clean = re.sub(r'^https?://', '', target_input).strip('/')

    st.sidebar.markdown("---")
    st.sidebar.header("🔍 Manual Filters")
    
    # TLD Filter
    if 'Extension' in df.columns:
        available_tlds = sorted(df['Extension'].dropna().astype(str).unique().tolist())
        selected_tlds = st.sidebar.multiselect("Select TLDs", options=available_tlds)
    else:
        selected_tlds = []

    # Keyword Search
    search_keyword = st.sidebar.text_input("General Domain Search (Contains)")

    # Referring Domains Range
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

    # Base Filtering
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

    # --- TARGET DOMAIN LOOKALIKE ENGINE ---
    if target_clean:
        st.subheader(f"🔍 Analysis & Lookalikes for: `{target_clean}`")
        
        target_row = df[df['Domain'].astype(str).str.lower() == target_clean]
        
        # Extract root keyword
        keyword_seed = target_clean.split('.')[0]
        
        if not target_row.empty:
            t_ref = int(target_row['Referring_Domains'].values[0])
            t_rank = float(target_row['OpenPageRank_Score'].values[0])
            t_ext = str(target_row['Extension'].values[0])
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Target Referring Domains", f"{t_ref:,}")
            c2.metric("Target PageRank", f"{t_rank:.2f}")
            c3.metric("Target TLD", f".{t_ext}")
            
            # Find domains with similar strength (±40% ref range or close rank)
            min_match_ref = max(1, int(t_ref * 0.6))
            max_match_ref = int(t_ref * 1.4) + 5
            
            lookalike_df = df[
                (df['Domain'].astype(str).str.lower() != target_clean) &
                (df['Referring_Domains'] >= min_match_ref) &
                (df['Referring_Domains'] <= max_match_ref)
            ].copy()
            
            # Priority score: closer in rank and ref domains + keyword match
            lookalike_df['Ref_Diff'] = (lookalike_df['Referring_Domains'] - t_ref).abs()
            lookalike_df['Keyword_Bonus'] = lookalike_df['Domain'].astype(str).apply(
                lambda x: 1 if (len(keyword_seed) > 3 and keyword_seed in x.lower()) else 0
            )
            
            lookalike_df = lookalike_df.sort_values(by=['Keyword_Bonus', 'Ref_Diff'], ascending=[False, True])
            
        else:
            st.warning(f"`{target_clean}` database-la direct-a illa. Matching by keyword and authority profile:")
            lookalike_df = df[df['Domain'].astype(str).str.contains(keyword_seed, na=False)].copy()
            lookalike_df = lookalike_df.sort_values(by='Referring_Domains', ascending=False)
            
        st.write(f"**Found {len(lookalike_df):,} Closely Matching Domains:**")
        st.dataframe(lookalike_df[['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']].head(2000))
        
        match_csv = lookalike_df.to_csv(index=False).encode('utf-8-sig')
        st.download_button(
            label="📥 Download Similar Domains (CSV)",
            data=match_csv,
            file_name=f"lookalikes_for_{target_clean}.csv",
            mime="text/csv"
        )
        st.markdown("---")

    # Regular Dashboard Table
    st.subheader(f"General Explorer: {selected_policy}")
    
    sort_order = st.sidebar.radio("Sort Referring Domains", ["Low to High (Ascending)", "High to Low (Descending)"])
    if sort_order == "Low to High (Ascending)":
        filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=True)
    else:
        filtered_df = filtered_df.sort_values(by="Referring_Domains", ascending=False)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total in Policy", f"{len(df):,}")
    col2.metric("Filtered Domains", f"{len(filtered_df):,}")
    col3.metric("Selected Range", selected_range)

    preview_df = filtered_df.head(5000)
    if len(filtered_df) > 5000:
        st.info("Previewing top 5,000 filtered rows for smooth performance. Click below to download all results.")
    
    st.dataframe(preview_df[['Domain', 'Extension', 'Referring_Domains', 'OpenPageRank_Score']])

    csv_dl = filtered_df.to_csv(index=False).encode('utf-8-sig')
    st.download_button(
        label="📥 Download General Filtered Domains (CSV)",
        data=csv_dl,
        file_name=f"{selected_policy.replace(' ', '_').lower()}_{selected_range.replace(' ', '')}.csv",
        mime="text/csv"
    )
else:
    st.error("Data files not found! Ensure part files or .csv.gz files are uploaded to the repository.")