import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import re

# Load dataset (with no headers), force all columns to be string to avoid DtypeWarning
df = pd.read_csv("../data/csic_database.csv", header=None, dtype=str, low_memory=False)

# Label column: index 0
df['label'] = df[0].apply(lambda x: 0 if x == 'Normal' else 1)

# Request column: assume last column
df['request'] = df[df.columns[-1]].fillna('')  # Replace NaN with empty string

# Feature extraction
def extract_features(request):
    request = str(request)  # ensure it's string
    length = len(request)
    digits = sum(c.isdigit() for c in request)
    special_chars = len(re.findall(r'[^a-zA-Z0-9]', request))
    return [length, digits, special_chars]

# Apply feature extraction
X = df['request'].apply(extract_features).tolist()
y = df['label'].tolist()

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Print evaluation
print("\n Classification Report:\n")
print(classification_report(y_test, model.predict(X_test)))

# Save model
joblib.dump(model, "waf_model.pkl")
print("\n Model trained and saved as 'waf_model.pkl'")
