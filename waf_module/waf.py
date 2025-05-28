import re
import joblib
import numpy as np

# the main detection logic. It checks for patterns like SQL and XSS, 
# and also uses the trained AI model to predict anomalies.

# Load trained Isolation Forest model
model = joblib.load("model/waf_model.pkl")

# SQL Injection Detection Patterns
sql_injection_patterns = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  
    r"(\bOR\b|\bAND\b).*(=|>|<)",      
    r"(\bSELECT\b|\bUNION\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)"
]

# XSS Detection Patterns
xss_patterns = [
    r"(<script.*?>.*?</script>)",  
    r"(\bon\w+=)",  
    r"(javascript:)",  
    r"(alert\s*\()"
]

# Pattern-based detection
def detect_pattern(input_data):
    for pattern in xss_patterns:
        if re.search(pattern, input_data, re.IGNORECASE):
            return "XSS Attack"
    for pattern in sql_injection_patterns:
        if re.search(pattern, input_data, re.IGNORECASE):
            return "SQL Injection"
    return None

def extract_features(text):
    length = len(text)
    digits = sum(1 for c in text if c.isdigit())
    special_chars = sum(1 for c in text if not c.isalnum() and c != ' ')
    return [length, digits, special_chars]  # order must match training.py

def detect_ai_anomaly(user_input):
    features = extract_features(user_input)
    prediction = model.predict([features])[0]

    print("🔍 DEBUG INFO")
    print("Input:", user_input)
    print("Features:", features)
    print("Prediction:", prediction)

    # If model flags it, treat as suspicious
    if prediction == 1:
        return True

    # EXTRA HEURISTIC: If special characters + digits is too high, treat as suspicious
    length, num_special, num_digits = features
    if num_special >= 8 or num_digits >= 8:
        print("⚠️ Heuristic triggered: Too many special characters or digits")
        return True

    return False


