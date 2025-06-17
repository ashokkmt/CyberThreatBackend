from flask import Flask, request, jsonify
from flask_cors import CORS
from detector.layer1_trie import load_trie_from_file
from detector.layer3_ml import extract_features
from detector.layer2_fsm import (
    is_valid_sql,
    contains_script_tag,
    contains_xss_patterns
)
import joblib

app = Flask(__name__)
CORS(app) 

model = joblib.load("attack_classifier.pkl")
trie = load_trie_from_file("short_signatures.json")


@app.route("/")
def home():
    print("home")
    return 'Hello Programmer, Visit our <a href="https://github.com/ashokkmt/CyberThreatBackend" target="_blank">GitHub</a>!'

@app.route("/activity", methods=["POST"])
def output():
    data = request.get_json()  
    # data = json.loads(data)
    print(data['data'])
    return jsonify({"message": "Data received", "received_data": data})

@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json()
    
    print(data['data'])
    user_input = data['data']
    found, matched = trie.search(user_input)
    if found:
        print("found in layer 1")
        return jsonify({
            "layer": 1,
            "result": f"⚠️'{matched}' Attack Detected (Layer 1 - Pattern)",
            "match": matched,
            "flag": True
        })

    # ------- Layer 2: FSM - XSS Script Tag -------
    if contains_script_tag(user_input):
        print("found in layer 2 script tag")
        return jsonify({
            "layer": 2,
            "result": "⚠️ XSS <script> tag detected by FSM",
            "match": "Suspicious <script> tag found",
            "flag": True
        })

    # ------- Layer 2: FSM - XSS Patterns -------
    found_xss, xss_match = contains_xss_patterns(user_input)
    if found_xss:
        print("found in layer 2 xss pattern")
        return jsonify({
            "layer": 2,
            "result": f"⚠️ XSS pattern '{xss_match}' detected by FSM",
            "match":xss_match,
            "flag": True
        })

    # ------- Layer 2: FSM - SQL Grammar -------
    if not is_valid_sql(user_input):
        print("found in layer 2 sql validation")
        return jsonify({
            "layer": 2,
            "result": "⚠️ SQL query structure invalid (FSM failed)",
            "match": "SQL structure violation",
            "flag": True
        })

    # ------- Layer 3: ML Classification -------   
    features = extract_features(user_input)
    prediction = model.predict([features])[0]
    label_map = {0: "Safe", 1: "XSS Attack", 2: "SQL Injection"}

    if prediction != 0:
        print("found in layer 3 ML")
        return jsonify({
            "layer": 3,
            "result": f"⚠️ {label_map[prediction]} detected by ML Classifier",
            "match": f"Predicted as: {label_map[prediction]}",
            "flag": True
        })

    # All Layers Passed
    return jsonify({
        "layer": 3,
        "result": "✅ Input passed all layers (Safe)",
        "match": "No attack detected",
        "flag": False
    })  


@app.route('/detect', methods=['POST'])
def detect_attack():
    data = request.get_json()
    user_input = data.get('input', '')
    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    features = extract_features(user_input)
    prediction = model.predict([features])[0]

    label_map = {0: "Safe", 1: "XSS Attack", 2: "SQL Injection"}

    return jsonify({
        "input": user_input,
        "prediction": int(prediction),
        "label": label_map[prediction]
    })


if __name__ == "__main__":
    app.run(debug=True)
