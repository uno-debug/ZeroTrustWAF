import joblib
from blockchain import log_threat_to_blockchain
import urllib.parse
from scipy.sparse import hstack # <-- Add this import

# --- Define the Feature Extraction Functions ---
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

# --- Load both model and vectorizer ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    VECTORIZER = joblib.load('ml_model/vectorizer.pkl')
    print("✅ Hybrid ML model and vectorizer loaded.")
except Exception as e:
    MODEL = None
    VECTORIZER = None
    print(f"❌ Error loading model: {e}")

def analyze_request(request):
    source_ip = request.remote_addr
    request_full_text = f"{request.method} {request.user_agent} {request.full_path}"

    if MODEL and VECTORIZER:
        # 1. Get manual features
        manual_features = [extract_manual_features(request_full_text)]
        # 2. Get TF-IDF features
        tfidf_features = VECTORIZER.transform([request_full_text])
        # 3. Combine both feature sets in the same way as training
        combined_features = hstack([manual_features, tfidf_features])
        
        malicious_probability = MODEL.predict_proba(combined_features)[0][1]
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