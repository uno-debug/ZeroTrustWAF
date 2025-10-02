# firewall.py
import joblib
from blockchain import log_threat_to_blockchain

# --- Load the trained model and vectorizer ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    VECTORIZER = joblib.load('ml_model/vectorizer.pkl')
    print("✅ ML model and vectorizer loaded successfully.")
except FileNotFoundError:
    MODEL = None
    VECTORIZER = None
    print("❌ ML model or vectorizer not found. Firewall will not use ML scoring.")


def analyze_request(request):
    """Analyzes an incoming request with the real ML model."""
    source_ip = request.remote_addr
    
    # Combine relevant parts of the live request to match training data format
    # Note: We simplify this for a live gateway. A more robust solution would parse all headers.
    request_full_text = f"{request.method} {request.user_agent} {request.path}"

    if MODEL and VECTORIZER:
        # 1. Convert the request text into numerical features
        features = VECTORIZER.transform([request_full_text])

        # 2. Get a prediction probability from the model
        # The [0][1] gets the probability of the request being "malicious" (class 1)
        malicious_probability = MODEL.predict_proba(features)[0][1]
        threat_score = int(malicious_probability * 100)
    else:
        # Fallback if the model isn't loaded
        threat_score = 0 
        print("Warning: ML model not loaded. Defaulting score to 0.")


    # 3. Make a decision based on the score
    if threat_score > 80: # Your threat threshold
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
        # We won't log allowed requests to the blockchain to save space/time
        print(f"Request from {source_ip} allowed (Score: {threat_score}).")
        return f"Request from {source_ip} was ALLOWED (Score: {threat_score})."