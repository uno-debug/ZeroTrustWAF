# proxy_script.py
import joblib
import urllib.parse
from scipy.sparse import hstack
from mitmproxy import http
import json
from web3 import Web3
import os

# --- 1. CONFIGURATION: UPDATE THESE VALUES ---
GANACHE_URL = "http://<YOUR_PC_IP_ADDRESS>:7545" 
CONTRACT_ADDRESS = "<YOUR_LATEST_CONTRACT_ADDRESS>"
CONTRACT_ABI = """
PASTE YOUR FULL MULTI-LINE ABI HERE
"""
# -------------------------------------------

# --- Initialize Web3 and Contract ---
try:
    web3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=json.loads(CONTRACT_ABI))
    print("✅ Proxy: Connected to Ganache and loaded contract.")
except Exception as e:
    contract = None
    print(f"❌ Proxy: Could not connect to Ganache. Blockchain logging will be disabled. Error: {e}")

# --- Feature Extraction Function ---
def extract_manual_features(text):
    decoded_text = urllib.parse.unquote(text)
    features = []
    text_to_scan = str(decoded_text).lower()
    features.append(len(text_to_scan))
    special_chars = ['\'', '<', '>', '&', ';', '-', '(', ')']
    features.append(sum(text_to_scan.count(c) for c in special_chars))
    sql_keywords = ['select', 'union', 'from', 'where', 'or 1=1', '--']
    features.append(sum(text_to_scan.count(k) for k in sql_keywords))
    xss_keywords = ['<script>', 'alert(', 'onerror=', 'onload=', 'eval(']
    features.append(sum(text_to_scan.count(k) for k in xss_keywords))
    return features

# --- Blockchain Logging Function ---
def log_threat_to_blockchain(ip, details, score, decision):
    if not contract or not web3.is_connected():
        print("❌ Blockchain logging skipped: Not connected to Ganache.")
        return
    try:
        account = web3.eth.accounts[0]
        tx_hash = contract.functions.addLog(ip, details, score, decision).transact({'from': account})
        web3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
        print(f"✅ Threat successfully logged to blockchain!")
    except Exception as e:
        print(f"❌ Error logging to blockchain: {e}")

# --- Load the ML model and vectorizer ---
try:
    MODEL = joblib.load('ml_model/threat_model.pkl')
    VECTORIZER = joblib.load('ml_model/vectorizer.pkl')
    print("✅ Proxy: ML model and vectorizer loaded.")
except Exception as e:
    MODEL = None
    VECTORIZER = None
    print(f"❌ Proxy: Error loading model: {e}")

def analyze_text(text_to_analyze):
    if not MODEL or not VECTORIZER:
        return 0
    manual_features = [extract_manual_features(text_to_analyze)]
    tfidf_features = VECTORIZER.transform([text_to_analyze])
    combined_features = hstack([manual_features, tfidf_features])
    malicious_probability = MODEL.predict_proba(combined_features)[0][1]
    return int(malicious_probability * 100)

# --- Main mitmproxy functions ---
def request(flow: http.HTTPFlow) -> None:
    # This function runs for every OUTBOUND request from the user
    request_full_text = f"{flow.request.method} {flow.request.headers.get('User-Agent', '')} {flow.request.pretty_url}"
    threat_score = analyze_text(request_full_text)
    
    print(f"➡️ OUT: {flow.request.host}{flow.request.path[:50]}... Score: {threat_score}")

    if threat_score > 80: # Your desired threshold
        print(f"🚨 THREAT (OUTBOUND)! Blocking request from {flow.client_conn.address[0]}")
        flow.response = http.Response.make(403, b"Outbound request blocked by Zero Trust WAF.")
        log_threat_to_blockchain(flow.client_conn.address[0], urllib.parse.unquote(request_full_text), threat_score, "BLOCKED (Outbound)")

def response(flow: http.HTTPFlow) -> None:
    # This function runs for every INBOUND response from a website
    if flow.response and "text/html" in flow.response.headers.get("content-type", ""):
        response_body = flow.response.text
        threat_score = analyze_text(response_body)
        
        print(f"⬅️ IN: Response from {flow.request.host}... Score: {threat_score}")

        if threat_score > 80: # Your desired threshold
            print(f"🚨 THREAT (INBOUND)! Blocking response from {flow.request.host}")
            flow.response = http.Response.make(403, b"Malicious response from website blocked by Zero Trust WAF.")
            log_threat_to_blockchain(flow.client_conn.address[0], f"Malicious response from {flow.request.host}", threat_score, "BLOCKED (Inbound)")