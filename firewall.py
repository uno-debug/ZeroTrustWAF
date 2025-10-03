import joblib
from blockchain import log_threat_to_blockchain

# --- 1. Define the Feature Extraction Function (MUST BE IDENTICAL TO THE TRAINING SCRIPT) ---
def extract_features(request_string):
    features = []
    request_string = str(request_string).lower()

    special_chars = ['\'', '<', '>', '&', ';', '-', '(', ')']
    features.append(len(request_string))
    features.append(sum(request_string.count(c) for c in special_chars))

    sql_keywords = ['select', 'union', 'from', 'where', 'or 1=1', '--']
    features.append(sum(request_string.count(k) for k in sql_keywords))
    
    xss_keywords = ['<script>', 'alert(', 'onerror=', 'onload=', 'eval(']
    features.append(sum(request_string.count(k) for k in xss_keywords))

    return [features] # Return as a list of lists for the model's predict function

# --- 2. Load the trained model ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    print("✅ New ML model loaded successfully.")
except FileNotFoundError:
    MODEL = None
    print("❌ ML model not found. Firewall will not use ML scoring.")


def analyze_request(request):
    source_ip = request.remote_addr
    request_full_text = f"{request.method} {request.user_agent} {request.path}"

    if MODEL:
        # 1. Extract features from the live request using our function
        features = extract_features(request_full_text)

        # 2. Get a prediction probability from the new model
        malicious_probability = MODEL.predict_proba(features)[0][1]
        threat_score = int(malicious_probability * 100)
    else:
        threat_score = 0
        print("Warning: ML model not loaded.")

    # 3. Make a decision based on the score
    if threat_score > 50: # We can use a more reasonable threshold now
        decision = "BLOCKED"
        print(f"High threat detected from {source_ip} (Score: {threat_score}). Logging to blockchain...")
        log_threat_to_blockchain(
            source_ip,
            request_full_text,
            threat_score,
            decision
        )
        return f"Request from {source_ip} was BLOCKED (Score: {threat_score}) and logged."
    else:
        decision = "ALLOWED"
        print(f"Request from {source_ip} allowed (Score: {threat_score}).")
        return f"Request from {source_ip} was ALLOWED (Score: {threat_score})."