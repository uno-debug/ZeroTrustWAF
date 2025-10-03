import joblib
from blockchain import log_threat_to_blockchain
import urllib.parse # <-- Add this

# --- 1. Define the Feature Extraction Function (MUST BE IDENTICAL TO THE TRAINING SCRIPT) ---
def extract_features(request_string):
    """Converts a raw HTTP request string into a list of numerical features."""
    
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

    return [features]

# --- 2. Load the trained model ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    print("✅ New ML model loaded successfully.")
except FileNotFoundError:
    MODEL = None
    print("❌ ML model not found. Firewall will not use ML scoring.")


def analyze_request(request):
    source_ip = request.remote_addr
    # Use request.full_path to get the path and query parameters
    request_full_text = f"{request.method} {request.user_agent} {request.full_path}"

    if MODEL:
        features = extract_features(request_full_text)
        malicious_probability = MODEL.predict_proba(features)[0][1]
        threat_score = int(malicious_probability * 100)
    else:
        threat_score = 0

    if threat_score > 50:
        decision = "BLOCKED"
        print(f"High threat detected from {source_ip} (Score: {threat_score}). Logging to blockchain...")
        log_threat_to_blockchain(
            source_ip,
            urllib.parse.unquote(request_full_text),
            threat_score,
            decision
        )
        return f"Request from {source_ip} was BLOCKED (Score: {threat_score}) and logged."
    else:
        decision = "ALLOWED"
        print(f"Request from {source_ip} allowed (Score: {threat_score}).")
        return f"Request from {source_ip} was ALLOWED (Score: {threat_score})."