from flask import Flask, request, jsonify, render_template
import joblib
import os


app = Flask(__name__)


model = joblib.load("sql_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json["input"]
    vector = vectorizer.transform([data])
    result = model.predict(vector)
    return jsonify({"result": "malicious" if result[0] == 1 else "safe"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
