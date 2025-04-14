from flask import Flask, request, jsonify
from flask_cors import CORS
import json
from detector.layer1_trie import load_trie_from_file
from detector.layer2_fsm import (
    is_valid_sql,
    contains_script_tag,
    contains_xss_patterns
)

app = Flask(__name__)
CORS(app) 

trie = load_trie_from_file("short_signatures.json")

@app.route("/activity", methods=["POST"])
def output():
    data = request.get_json()  
    # data = json.loads(data)
    print(data['data'])
    return jsonify({"message": "Data received", "received_data": data})

@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json()
    # input_text = data.get("input", "")
    
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


if __name__ == "__main__":
    app.run(debug=True)
