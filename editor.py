import json
import os
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)

DATA_FILE = "known.jsonl"

def load_entries():
    entries = []
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    return entries

def save_entries(entries):
    with open(DATA_FILE, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/entries", methods=["GET"])
def get_entries():
    return jsonify(load_entries())

@app.route("/api/entries/<int:entry_id>", methods=["PUT"])
def update_entry(entry_id):
    data = request.get_json()
    entries = load_entries()
    for i, entry in enumerate(entries):
        if entry["id"] == entry_id:
            entries[i] = data
            save_entries(entries)
            return jsonify({"success": True, "entry": entries[i]})
    return jsonify({"success": False, "error": "Entry not found"}), 404

if __name__ == "__main__":
    app.run(debug=False, port=5000)
