from flask import Flask, request, jsonify, render_template
import joblib

app = Flask(__name__)

# মডেল ও ভেক্টরাইজার লোড করো
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
    app.run(debug=True)
