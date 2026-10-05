from flask import Flask, request, jsonify, render_template
import joblib
import os
import re

app = Flask(__name__)

model = joblib.load("sql_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Dangerous Injection attack patterns
SQLI_PATTERNS = re.compile(
    r"(\b(load_file|outfile|dumpfile|exec|concat)\b|[\';#]|\-\-|/\*|\*/|union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
    re.IGNORECASE
)

# Robust Regex to match Legitimate SELECT Queries
SAFE_SQL_PATTERN = re.compile(
    r"^\s*select\s+[\w\*\, \.\t\n\(\)]+\s+from\s+[\w\.]+(\s+where\s+[\w\.\= \'\"\-]+)?\s*;?\s*$",
    re.IGNORECASE
)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        raw_data = request.json.get("input", "").strip()
        
        if not raw_data:
            return jsonify({"error": "No input provided"}), 400

        # 1. Direct Dangerous Pattern Check (SQLi Attack)
        if SQLI_PATTERNS.search(raw_data):
            return jsonify({"result": "malicious"})

        # 2. Direct Safe SQL Query Check (Legitimate Query)
        if SAFE_SQL_PATTERN.match(raw_data):
            return jsonify({"result": "safe"})

        # 3. ML Model Fallback for unknown edge cases
        vector = vectorizer.transform([raw_data])
        result = model.predict(vector)
        
        prediction = "malicious" if result[0] == 1 else "safe"
        return jsonify({"result": prediction})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
