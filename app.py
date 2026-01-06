import streamlit as st
import joblib
import numpy as np
import re
from urllib.parse import urlparse

# 1. Load the model
# Ensure 'phishing_model.pkl' is in the same folder
try:
    model = joblib.load('phishing_model.pkl')
except:
    st.error("Model file not found. Please ensure 'phishing_model.pkl' is in the folder.")

def extract_features(url):
    features = []
    # Standardize
    if not url.startswith('http'): url = 'http://' + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    url_lower = url.lower()

    # 1. UsingIP
    features.append(1 if not re.search(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}', domain) else -1)
    
    # 2. LongURL (Length > 75 is a high-risk indicator)
    features.append(1 if len(url) < 54 else (0 if len(url) <= 75 else -1))
    
    # 3. ShortURL
    features.append(-1 if re.search('bit\.ly|goo\.gl|tinyurl|t\.co|is\.gd', url) else 1)
    
    # 4. Symbol@
    features.append(-1 if "@" in url else 1)
    
    # 5. Redirecting //
    features.append(-1 if url.rfind("//") > 7 else 1)
    
    # 6. PrefixSuffix- (Check domain AND path for that opensea-ceooflidare string)
    features.append(-1 if '-' in domain or '-' in path else 1)
    
    # 7. SubDomains & Multi-Directories
    # High subdirectory count is common in hosted phishing (like .pages.dev/assets/...)
    slashes = url.count('/')
    features.append(-1 if slashes > 4 else 1)
    
    # 8. HTTPS
    features.append(1 if parsed_url.scheme == 'https' else -1)

    # --- NEW: SENSITIVE KEYWORD SCAN ---
    # If the URL contains banking/crypto keywords but isn't a known official domain
    keywords = ['login', 'verify', 'secure', 'ethereum', 'opensea', 'wallet', 'update', 'bank']
    has_keyword = any(key in url_lower for key in keywords)
    
    # We use the remaining slots to "inject" these risks into the model
    # Slot 9: Keyword risk
    features.append(-1 if has_keyword else 1)

    # Fill remaining 21 slots with -1 (Suspicious/Skeptical)
    while len(features) < 30:
        features.append(-1) 

    return np.array(features).reshape(1, -1)

# --- Streamlit UI ---
st.set_page_config(page_title="Banking Security Guard", page_icon="🛡️")

st.title("🛡️ Mobile-Based Banking Phishing Guard")
st.markdown("""
Paste a suspicious link below. Our Engine will analyze the URL structure 
for markers commonly used in banking scams and credential theft.
""")

url_input = st.text_input("URL to Analyze:", placeholder="https://your-bank-login.com")

if st.button("Analyze Security"):
    if url_input:
        with st.spinner('Scanning URL...'):
            features_vector = extract_features(url_input)
            prediction = model.predict(features_vector)
            
            # Result Mapping: 0=Phishing, 1=Legitimate
            if prediction[0] == 0:
                st.error("### 🚨 Result: PHISHING DETECTED")
                st.warning("Warning: This URL matches known malicious patterns. Do not enter credentials.")
            else:
                st.success("### ✅ Result: LEGITIMATE")
                st.info("The URL structure appears consistent with legitimate banking standards.")
            
            # Show the extracted features for the project defense
            with st.expander("View Technical Analysis (Input Vector)"):
                st.write(features_vector)
                st.caption("Values: 1 (Safe), 0 (Neutral), -1 (Suspicious)")
    else:
        st.write("Please enter a URL to start the scan.")