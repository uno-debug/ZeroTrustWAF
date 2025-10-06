import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os
import urllib.parse
from scipy.sparse import hstack

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

df = pd.read_csv('csic_database.csv')
df.columns = df.columns.str.strip()
df = df.fillna('')
df['request_full'] = df['Method'] + ' ' + df['User-Agent'] + ' ' + df['Host'] + ' ' + df['URL']
df['label'] = df['classification']
print("✅ Dataset loaded.")

X_manual = [extract_manual_features(req) for req in df['request_full']]
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3), max_features=2000)
X_tfidf = vectorizer.fit_transform(df['request_full'])
X_combined = hstack([X_manual, X_tfidf])
y = df['label']
print("✅ Features extracted.")

X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("✅ Hybrid model training complete.")

accuracy = model.score(X_test, y_test)
print(f"📈 New Hybrid Model Accuracy: {accuracy * 100:.2f}%")

joblib.dump(model, 'ml_model/threat_model.pkl')
joblib.dump(vectorizer, 'ml_model/vectorizer.pkl')
print("✅ Hybrid model and vectorizer saved successfully!")