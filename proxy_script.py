# proxy_script.py
import joblib
import urllib.parse
from scipy.sparse import hstack
from mitmproxy import http

# --- This section is copied from your firewall.py for feature extraction ---
def extract_manual_features(request_string):
    decoded_string = urllib.parse.unquote(request_string)
    features = []
    text_to_scan = str(decoded_string).lower()
    features.append(len(text_to_scan))
    special_chars = ['\'', '<', '>', '&', ';', '-', '(', ')']
    features.append(sum(text_to_scan.count(c) for c in special_chars))
    sql_keywords = ['select', 'union', 'from', 'where', 'or 1=1', '--']
    features.append(sum(text_to_scan.count(k) for k in sql_keywords))
    xss_keywords = ['<script>', 'alert(', 'onerror=', 'onload=', 'eval(']
    features.append(sum(text_to_scan.count(k) for k in xss_keywords))
    return features

# --- Load the model and vectorizer when the script starts ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    VECTORIZER = joblib.load('ml_model/vectorizer.pkl')
    print("✅ Proxy: Hybrid ML model and vectorizer loaded.")
except Exception as e:
    MODEL = None
    VECTORIZER = None
    print(f"❌ Proxy: Error loading model: {e}")

# This is the main function that mitmproxy will call for every request
def request(flow: http.HTTPFlow) -> None:
    # We only analyze requests, not responses
    if not MODEL or not VECTORIZER:
        return # Do nothing if the model isn't loaded

    # Combine request details into a single string for analysis
    request_full_text = f"{flow.request.method} {flow.request.headers.get('User-Agent', '')} {flow.request.pretty_url}"

    # --- Use the ML model to get a score ---
    manual_features = [extract_manual_features(request_full_text)]
    tfidf_features = VECTORIZER.transform([request_full_text])
    combined_features = hstack([manual_features, tfidf_features])
    
    malicious_probability = MODEL.predict_proba(combined_features)[0][1]
    threat_score = int(malicious_probability * 100)

    print(f"Analyzing: {flow.request.pretty_url[:70]}... Score: {threat_score}")

    # --- Make a decision ---
    if threat_score > 80: # Set your desired threshold here
        print(f"🚨 HIGH THREAT DETECTED! Blocking request from {flow.client_conn.address[0]}")
        
        # To block the request, we create a simple "Forbidden" response
        flow.response = http.Response.make(
            403,  # Forbidden
            b"Request blocked by Zero Trust WAF.",
            {"Content-Type": "text/html"}
        )
        
        # You could also add your blockchain logging function call here
        # from blockchain import log_threat_to_blockchain
        # log_threat_to_blockchain(...)