import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import joblib
import os # <-- THIS IS THE FIX

# --- 1. Define the Feature Extraction Function ---
def extract_features(request_string):
    """Converts a raw HTTP request string into a list of numerical features."""
    features = []
    request_string = str(request_string).lower()

    special_chars = ['\'', '<', '>', '&', ';', '-', '(', ')']
    features.append(len(request_string))
    features.append(sum(request_string.count(c) for c in special_chars))

    sql_keywords = ['select', 'union', 'from', 'where', 'or 1=1', '--']
    features.append(sum(request_string.count(k) for k in sql_keywords))
    
    xss_keywords = ['<script>', 'alert(', 'onerror=', 'onload=', 'eval(']
    features.append(sum(request_string.count(k) for k in xss_keywords))

    return features

print("✅ 1. Feature extraction function defined.")

# --- 2. Load and Prepare the Dataset ---
print("Loading dataset...")
df = pd.read_csv('csic_database.csv')
df.columns = df.columns.str.strip()

cols_to_use = ['Method', 'User-Agent', 'Host', 'URL']
for col in cols_to_use:
    df[col] = df[col].fillna('')
df['request_full'] = df[cols_to_use].apply(lambda row: ' '.join(row.values.astype(str)), axis=1)

df['label'] = df['classification']

print("✅ 2. Dataset loaded and prepared.")

# --- 3. Apply Feature Extraction ---
print("Extracting features from dataset...")
X = [extract_features(req) for req in df['request_full']]
y = df['label']

print("✅ 3. Features extracted.")

# --- 4. Train the Model ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

print("✅ 4. Model training complete.")

# --- 5. Evaluate the Model ---
accuracy = model.score(X_test, y_test)
print(f"📈 Model Accuracy: {accuracy * 100:.2f}%")

# --- 6. Save the Trained Model ---
joblib.dump(model, 'ml_model/threat_model.pkl')
# Clean up the old vectorizer file if it exists
if 'vectorizer.pkl' in os.listdir('ml_model'):
    os.remove('ml_model/vectorizer.pkl')

print("✅ 6. New model saved successfully to 'ml_model/' folder!")