from flask import Flask, request, jsonify, render_template
import joblib
import os

app = Flask(__name__)

# মডেল এবং ভেক্টরাইজার লোড করা
model = joblib.load("sql_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # JSON রিকুয়েস্ট থেকে ইনপুট ডাটা নেওয়া
        data = request.json.get("input", "")
        
        if not data:
            return jsonify({"error": "No input provided"}), 400

        # ইনপুট ডাটাকে ভেক্টরাইজ করা
        vector = vectorizer.transform([data])
        
        # প্রেডিকশন করা
        result = model.predict(vector)
        
        # ফলাফল প্রদান
        prediction = "malicious" if result[0] == 1 else "safe"
        return jsonify({"result": prediction})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
