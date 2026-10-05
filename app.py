from flask import Flask, request, jsonify, render_template
import joblib
import os
import re

app = Flask(__name__)

# মডেল এবং ভেক্টরাইজার লোড করা
model = joblib.load("sql_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# SQL Injection প্যাটার্ন চেক করার জন্য Regex
SQLI_PATTERNS = re.compile(
    r"(\b(load_file|outfile|dumpfile|char|concat|exec|union|select|insert|update|delete|drop|alter|truncate)\b|[\';#]|\-\-)",
    re.IGNORECASE
)

def normalize_input(text):
    """অতিরিক্ত স্পেস সরিয়ে লোয়ারকেস করার ফাংশন"""
    # ফাংশন ও ব্র্যাকেটের ভেতরের স্পেস রিমুভ করে (যেমন: load_file ( -> load_file()
    text = re.sub(r'\s*\(\s*', '(', text)
    text = re.sub(r'\s*\)\s*', ')', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip().lower()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        raw_data = request.json.get("input", "")
        
        if not raw_data:
            return jsonify({"error": "No input provided"}), 400

        # ১. ইনপুট নরমালাইজেশন
        clean_data = normalize_input(raw_data)

        # ২. সরাসরি Regex দিয়ে ঝুঁকিপূর্ণ ক্যোয়ারি সনাক্তকরণ (Rule-based Check)
        if SQLI_PATTERNS.search(clean_data):
            return jsonify({"result": "malicious"})

        # ৩. AI/ML মডেলের মাধ্যমে প্রেডিকশন
        vector = vectorizer.transform([clean_data])
        result = model.predict(vector)
        
        prediction = "malicious" if result[0] == 1 else "safe"
        return jsonify({"result": prediction})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
