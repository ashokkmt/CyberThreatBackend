from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from detector.layer1_trie import load_trie_from_file
from detector.layer2_fsm import (
    is_valid_sql,
    contains_script_tag,
    contains_xss_patterns
)
import joblib
import math
import re
from collections import Counter

app = Flask(__name__)
CORS(app) 

model = joblib.load("attack_classifier.pkl")
trie = load_trie_from_file("short_signatures.json")

def shannon_entropy(s):
    if not s:
        return 0
    probabilities = [n_x / len(s) for x, n_x in Counter(s).items()]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_features(s):
    length = len(s)
    entropy = shannon_entropy(s)
    num_quotes = s.count("'") + s.count('"')
    has_script = 1 if "<script>" in s.lower() else 0
    has_sql_keywords = 1 if re.search(r"\b(SELECT|UNION|DROP|--|OR 1=1|INSERT|DELETE|UPDATE)\b", s, re.IGNORECASE) else 0
    special_char_ratio = len(re.findall(r"[^a-zA-Z0-9\s]", s)) / (length + 1e-6)
    return [length, entropy, num_quotes, has_script, has_sql_keywords, special_char_ratio]


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

    # If all layers passed
    return jsonify({
        "layer": 2,
        "result": "✅ Input passed Layer 1 and Layer 2 (no attack found)",
        "match": "Nothing suspicious found",
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
