#!/usr/bin/env python3

import hmac
import json
import os
import sys
from functools import wraps

import dotenv
from flask import Flask, render_template, request, jsonify, send_from_directory, Response

dotenv.load_dotenv()

app = Flask(__name__)

DATA_FILE = "known.jsonl"

AUTH_USER = os.getenv("EDITOR_AUTH_USER", "admin")
AUTH_PASSWORD = os.getenv("EDITOR_AUTH_PASSWORD", "")

if not AUTH_PASSWORD:
    sys.exit("EDITOR_AUTH_PASSWORD is not set. Refusing to start without a password.")


def check_auth(username, password):
    return (hmac.compare_digest(username, AUTH_USER) and hmac.compare_digest(password, AUTH_PASSWORD))


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response(
                "Authentication required.", 401,
                {"WWW-Authenticate": 'Basic realm="LogWatcher Editor"'},
            )
        return f(*args, **kwargs)
    return decorated

def load_entries():
    seen = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    eid = entry.get("id")
                    if eid not in seen or entry.get("count", 0) > seen[eid].get("count", 0):
                        seen[eid] = entry
    return list(seen.values())

KEY_ORDER = ["id", "count", "severity", "original_message", "pattern_message", "analysis"]

def save_entries(entries):
    with open(DATA_FILE, "w") as f:
        for entry in entries:
            ordered = {k: entry[k] for k in KEY_ORDER if k in entry}
            ordered.update({k: entry[k] for k in entry if k not in KEY_ORDER})
            f.write(json.dumps(ordered) + "\n")

@app.route("/")
@require_auth
def index():
    return render_template("index.html")

@app.route("/api/entries", methods=["GET"])
@require_auth
def get_entries():
    return jsonify(load_entries())

@app.route("/api/entries/<int:entry_id>", methods=["PUT"])
@require_auth
def update_entry(entry_id):
    data = request.get_json()
    entries = load_entries()
    for i, entry in enumerate(entries):
        if entry["id"] == entry_id:
            entries[i] = data
            save_entries(entries)
            return jsonify({"success": True, "entry": entries[i]})
    return jsonify({"success": False, "error": "Entry not found"}), 404

@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
@require_auth
def delete_entry(entry_id):
    entries = load_entries()
    new_entries = [e for e in entries if e["id"] != entry_id]
    if len(new_entries) == len(entries):
        return jsonify({"success": False, "error": "Entry not found"}), 404
    save_entries(new_entries)
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=False, port=5000)
