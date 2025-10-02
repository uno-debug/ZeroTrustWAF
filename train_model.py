# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

# --- 1. Load and Prepare the Dataset ---
print("Loading dataset...")
df = pd.read_csv('csic_database.csv')

# Clean up column names by removing any leading/trailing whitespace
df.columns = df.columns.str.strip()

cols_to_use = ['Method', 'User-Agent', 'Pragma', 'Cache-Control', 'Accept', 'Host', 'URL', 'cookie', 'content-type']
for col in cols_to_use:
    df[col] = df[col].fillna('')

df['request_full'] = df[cols_to_use].apply(lambda row: ' '.join(row.values.astype(str)), axis=1)

# --- THE FINAL FIX ---
# The 'classification' column already contains the 0s and 1s we need.
# We can use it directly as our label 'y'.
y = df['classification']
# --------------------

print("✅ 1. Dataset loaded and prepared.")


# --- 2. Feature Engineering with TF-IDF ---
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3), max_features=2000)
X = vectorizer.fit_transform(df['request_full'])
# 'y' is already defined above

print("✅ 2. Features extracted.")


# --- 3. Train the Model ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

print("✅ 3. Model training complete.")


# --- 4. Evaluate the Model ---
accuracy = model.score(X_test, y_test)
print(f"📈 Model Accuracy: {accuracy * 100:.2f}%")


# --- 5. Save the Model and Vectorizer ---
joblib.dump(model, 'ml_model/threat_model.pkl')
joblib.dump(vectorizer, 'ml_model/vectorizer.pkl')

print("✅ 5. Model and vectorizer saved successfully to 'ml_model/' folder!")