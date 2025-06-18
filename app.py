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
            "match": xss_match,
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


@app.route('/api/detect2', methods=['POST'])
def detect_attack():
    data = request.get_json()

    fields_to_check = ['fname', 'message', 'email']  # only analyze these
    attack_detected = False
    highest_layer = 0
    combined_matches = []
    result_messages = []

    for field in fields_to_check:
        if field not in data:
            continue

        user_input = data[field]
        print(f"Checking field: {field} => {user_input}")

        # Layer 1: Trie Pattern
        found, matched = trie.search(user_input)
        if found:
            attack_detected = True
            highest_layer = max(highest_layer, 1)
            combined_matches.append(f"[{field}] {matched}")
            result_messages.append(
                f"⚠️ '{matched}' detected in '{field}' (Layer 1 - Pattern)")
            continue

        # Layer 2: Script Tag
        if contains_script_tag(user_input):
            attack_detected = True
            highest_layer = max(highest_layer, 2)
            combined_matches.append(f"[{field}] <script>")
            result_messages.append(
                f"⚠️ <script> tag in '{field}' detected by FSM")
            continue

        # Layer 2: XSS Pattern
        found_xss, xss_match = contains_xss_patterns(user_input)
        if found_xss:
            attack_detected = True
            highest_layer = max(highest_layer, 2)
            combined_matches.append(f"[{field}] {xss_match}")
            result_messages.append(
                f"⚠️ XSS pattern '{xss_match}' in '{field}' by FSM")
            continue

        # Layer 2: SQL Grammar
        if not is_valid_sql(user_input):
            attack_detected = True
            highest_layer = max(highest_layer, 2)
            combined_matches.append(f"[{field}] Invalid SQL")
            result_messages.append(
                f"⚠️ SQL structure invalid in '{field}' (FSM)")
            continue

        # Layer 3: ML Classifier
        features = extract_features(user_input)
        prediction = model.predict([features])[0]
        label_map = {0: "Safe", 1: "XSS Attack", 2: "SQL Injection"}

        if prediction != 0:
            attack_detected = True
            highest_layer = max(highest_layer, 3)
            attack_type = label_map[prediction]
            combined_matches.append(f"[{field}] {attack_type}")
            result_messages.append(
                f"⚠️ {attack_type} in '{field}' detected by ML")
            continue

        print(f"{field} is safe.")

    if attack_detected:
        return jsonify({
            "layer": highest_layer,
            "result": "\n".join(result_messages),
            "match": "; ".join(combined_matches),
            "flag": True
        })
    else:
        return jsonify({
            "layer": 3,
            "result": "✅ Name and Message passed all layers (Safe)",
            "match": "No attack detected",
            "flag": False
        })


if __name__ == "__main__":
    app.run(debug=True)
