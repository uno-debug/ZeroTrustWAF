# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

# --- 1. Load and Prepare the Dataset ---
print("Loading dataset...")
df = pd.read_csv('csic_database.csv')

# Combine all parts of the request into a single string for analysis
df['request_full'] = df['Method'] + ' ' + df['User-Agent'] + ' ' + df['Pragma'] + ' ' + df['Cache-Control'] + ' ' + df['Accept'] + ' ' + df['Accept-Encoding'] + ' ' + df['Accept-Charset'] + ' ' + df['Accept-Language'] + ' ' + df['Host'] + ' ' + df['Connection'] + ' ' + df['Content-Length'] + ' ' + df['Content-Type'] + ' ' + df['Cookie'] + ' ' + df['URL']

# Convert the label to a binary format (0 for normal, 1 for malicious)
df['label'] = df['Anomalous'].apply(lambda x: 1 if x == '1' else 0)

print("✅ 1. Dataset loaded and prepared.")


# --- 2. Feature Engineering with TF-IDF ---
# TF-IDF is excellent for finding suspicious keywords and characters in text.
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3), max_features=2000)

X = vectorizer.fit_transform(df['request_full'].astype(str))
y = df['label']

print("✅ 2. Features extracted.")


# --- 3. Train the Model ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print("✅ 3. Model training complete.")


# --- 4. Evaluate the Model ---
accuracy = model.score(X_test, y_test)
print(f"📈 Model Accuracy: {accuracy * 100:.2f}%")


# --- 5. Save the Model and Vectorizer ---
joblib.dump(model, 'ml_model/threat_model.pkl')
joblib.dump(vectorizer, 'ml_model/vectorizer.pkl')

print("✅ 5. Model and vectorizer saved successfully to 'ml_model/' folder!")