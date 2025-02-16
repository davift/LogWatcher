#!/usr/bin/env python3

import json
import re
import sys
import signal
import requests
from jsonschema import validate, ValidationError
import os
import dotenv
dotenv.load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_KEY", "")

DEBUGGING = True
SYSTEMD = True
MAX_QUEUE_SIZE = 100

OLLAMA = True
OLLAMA_URL = "http://192.168.1.101:11434/api/generate"
MODELS = [
    # Recomment options.
    'hf.co/Nerdsking/nerdsking-python-coder-3B-i:Q8_0',   #0 Best Regex patterns but almost all there classified as INFO. 12 learned patterns.
    'yi-coder:9b',                                        #1 Best classification results. 12 learned patterns.
    'qwen2.5-coder:7b',                                   #2 Second best classification results. 12 learned patterns.
    # May perform better in other use cases.
    'hf.co/Nerdsking/Nerdsking-python-coder-7B-i:latest', #3 Hard-coded IP in pattern first time then generalized on the second encounter. 13 learned patterns.
    'deepseek-coder:6.7b',                                #4 Failed to create a proper Regex and extracting entities. 14 learned patterns.
    'qwen2.5-coder:3b',                                   #5 Failed to create a proper Regex and extracting entities. 14 learned patterns.
    # Definitely not recommended.
    'qwen2.5-coder:14b',                                  #6 Not too bad but too slow for my hardware (unusable). 12 learned patterns.
    'qwen2.5-coder:1.5b-base',                            #7 So bad that can't return most JSON with proper schema or even a valid JSON format. 16 learned patterns.
    'deepseek-coder:1.3b',                                #8 So bad that can't return any JSON with proper schema or even a valid JSON format. 0 learned patterns.
]
INDEX=0 if len(sys.argv) <= 1 else int(sys.argv[1])
MODEL = MODELS[INDEX]
KNOWN_PATTERNS_FILE = f"known.jsonl"
# Use the following if you wan to benchmark models.
# KNOWN_PATTERNS_FILE = f"known_model_{INDEX}.jsonl"
SCHEMA_FILE = 'schema.json'

class Colors:
    CRITICAL = '\033[91m'    # Red
    ERROR = '\033[38;5;208m' # Orange
    WARNING = '\033[93m'     # Yellow
    INFO = '\033[92m'        # Green
    DEBUG = '\033[90m'       # Grey
    RESET = '\033[0m'        # Reset

def get_color(severity):
    mapping = {
        "CRITICAL": Colors.CRITICAL,
        "ERROR": Colors.ERROR,
        "WARNING": Colors.WARNING,
        "INFO": Colors.INFO
    }
    return mapping.get(severity.upper(), Colors.RESET)

def signal_handler(sig, frame):
    print(f"\n{Colors.WARNING} [!] Interrupt received. Shutting down gracefully...{Colors.RESET}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def debug_print(message):
    if DEBUGGING:
        print(f"{Colors.DEBUG}[DEBUG] {message}{Colors.RESET}")

def load_json_schema():
    debug_print(f"Attempting to load schema from {SCHEMA_FILE}...")
    try:
        with open(SCHEMA_FILE, 'r') as f:
            schema = json.load(f)
            debug_print("Schema loaded successfully.")
            return schema
    except Exception as e:
        print(f"{Colors.CRITICAL}CRITICAL: Error loading {SCHEMA_FILE}: {e}{Colors.RESET}")
        return None

def load_known_patterns():
    debug_print(f"Reading knowledge base: {KNOWN_PATTERNS_FILE}")
    patterns = []
    try:
        with open(KNOWN_PATTERNS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    patterns.append(json.loads(line))
        debug_print(f"Loaded {len(patterns)} known patterns.")
    except FileNotFoundError:
        debug_print("No known patterns file found. Starting fresh.")
    return patterns

def save_jsonl(entry, filename):
    debug_print(f"Appending new pattern ID {entry['id']}")
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')

def update_pattern_count(pattern_id, filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = [json.loads(l) for l in f if l.strip()]

        for entry in lines:
            if entry.get("id") == pattern_id:
                entry["count"] += 1
                break

        with open(filename, 'w', encoding='utf-8') as f:
            for entry in lines:
                f.write(json.dumps(entry) + '\n')
    except Exception as e:
        debug_print(f"Failed updating count for id {pattern_id}: {e}")

def get_next_id(patterns):
    if not patterns:
        return 1
    return max(p.get("id", 0) for p in patterns) + 1

def ask_ai(log_message, schema_obj):
    prompt = f"""
    Analyze the following log line and return ONLY a valid JSON object.
    Do not include any explanation, comments, or markdown formatting.
    The field "original_message" must contain the log exactly as received with no modification.

    Severity rules:
    - If a log is related to security (authentication failures, brute-force attempts, unauthorized access, exploit indicators, etc), severity MUST be CRITICAL.
    - If it is related to hardware failure or kernel-related issues, severity MUST be ERROR.
    - If it is related to communication errors, timeouts, connection failures, or application crashes, severity MUST be WARNING.
    - If it is periodic noise, status messages, or informational output, severity MAY be INFO.

    Entity extraction rules:
    - Extract only entities that are explicitly present in the log.
    - Do NOT invent or infer entities that are not visible.
    - Typical entities include: IP addresses, ports, MAC addresses, usernames, hostnames, file paths, process names, PIDs, error codes, timestamps, and protocol names.

    Pattern generation rules:
    - "pattern_message" must be a regex that generalizes the log by replacing variable entities with capturing groups. Do not leave literal entities in the pattern.
    - Escape regex metacharacters where required.
    - Prefer explicit patterns for common entities (e.g., IPv4, usernames, file paths).
    - Anchor the pattern when possible (^ and $).

    Confidence score:
    - 1 = extremely uncertain interpretation
    - 9 = very clear and deterministic log meaning
    The score ten is reserved for human verification only.

    Expected JSON Structure:
    {{
        "severity": "INFO|WARNING|ERROR|CRITICAL",
        "original_message": "the exact log text",
        "pattern_message": "a regex pattern that generalizes logs by extracting the entities",
        "analysis": {{
            "confidence_score": 1-9,
            "reasoning": "short explanation of why the severity and entities were chosen",
            "detected_entities": ["list", "of", "strings"]
        }}
    }}
    """
    
    try:
        debug_print("Asking AI...\n")

        if OLLAMA:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": MODEL,
                    "prompt": f"{prompt}\n\nLog Line: {log_message}",
                    "stream": False,
                    "format": "json"
                },
                timeout=180
            )
            if DEBUGGING:
                print(f"[DEBUG] REQUEST: \n\n{log_message}\n")
                print(f"[DEBUG] RESPONSE ({response.elapsed.total_seconds():.0f}s): \n\n{response.json()['response']}\n")

            response.raise_for_status()
            ai_data = json.loads(response.json()['response'])
        else:
            if not OPENAI_KEY:
                print(f"{Colors.CRITICAL}CRITICAL: OPENAI_KEY not set.{Colors.RESET}")
                return None
            openai_url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {OPENAI_KEY}",
                "Content-Type": "application/json"
            }
            openai_model = "gpt-3.5-turbo"
            payload = {
                "model": openai_model,
                "messages": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"Log Line: {log_message}"}
                ],
                "temperature": 0.2,
                "max_tokens": 1024
            }
            response = requests.post(openai_url, headers=headers, json=payload, timeout=180)
            response.raise_for_status()
            result = response.json()
            if DEBUGGING:
                print(f"[DEBUG] OPENAI REQUEST: \n\n{log_message}\n")
                print(f"[DEBUG] OPENAI RESPONSE: \n\n{result}\n")
            content = result["choices"][0]["message"]["content"]
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:].strip()
                if content.endswith("```"):
                    content = content[:-3].strip()
            ai_data = json.loads(content)

        debug_print("Validating response against schema.json")
        if schema_obj:
            validate(instance=ai_data, schema=schema_obj)
        return ai_data
    except ValidationError as ve:
        print(f"{Colors.ERROR}[ERROR] AI JSON failed validation: {ve.message}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.ERROR}[ERROR] AI communication failure: {e}{Colors.RESET}")
        return None

def analyze_and_process_line(log_line, knowledge_base, schema_obj):
    if not log_line:
        return

    match_found = None
    for entry_kb in knowledge_base:
        if re.search(entry_kb['pattern_message'], log_line):
            match_found = entry_kb
            break

    if match_found:
        match_found["count"] += 1
        update_pattern_count(match_found["id"], KNOWN_PATTERNS_FILE)
        color = get_color(match_found['severity'])
        print(f"{color}[CACHED: {match_found['severity']}] {log_line}{Colors.RESET}")
    else:
        debug_print("No match in knowledge base.")
        full_ai_response = ask_ai(log_line, schema_obj)

        if full_ai_response:
            severity = full_ai_response.get("severity", "INFO")
            pattern = full_ai_response.get("pattern_message", "")

            try:
                if not pattern or not re.search(pattern, log_line):
                    pattern = re.escape(log_line)
            except re.error:
                pattern = re.escape(log_line)
            
            new_entry = {
                "id": get_next_id(knowledge_base),
                "count": 1,
                "severity": severity,
                "original_message": log_line,
                "pattern_message": pattern,
                "analysis": full_ai_response.get('analysis', {})
            }

            color = get_color(severity)
            print(f"{color}[NEW: {severity}] {log_line}{Colors.RESET}")
            save_jsonl(new_entry, KNOWN_PATTERNS_FILE)
            knowledge_base.append(new_entry)
        else:
            debug_print("AI processing failed. Log ignored.")

def process_journal_logs():
    knowledge_base = load_known_patterns()
    schema_obj = load_json_schema()

    if SYSTEMD:
        debug_print("Opening systemd journal reader...")
        import select
        from systemd import journal

        j = journal.Reader()
        j.log_level(journal.LOG_DEBUG)
        j.add_match(_SYSTEMD_UNIT="ssh.service")
        j.add_disjunction()
        j.add_match(_SYSTEMD_UNIT="sshd.service")
        j.seek_tail()
        j.get_previous()
        
        print(f"{Colors.INFO}Parser Active (Monitoring SSH via systemd-python). Press Ctrl+C to stop.{Colors.RESET}")
        
        while True:
            select.select([j], [], [])
            j.process()
            pending = []
            for entry in j:
                log_line = entry.get("MESSAGE", "").strip()
                if log_line:
                    pending.append(log_line)

            if len(pending) > MAX_QUEUE_SIZE:
                pruned = len(pending) - MAX_QUEUE_SIZE
                print(f"{Colors.WARNING}[!] Queue overflow: {len(pending)} lines received, pruning {pruned} oldest entries.{Colors.RESET}")
                pending = pending[-MAX_QUEUE_SIZE:]

            for log_line in pending:
                analyze_and_process_line(log_line, knowledge_base, schema_obj)
    else:
        debug_print("Opening journalctl stream...")
        import subprocess
        cmd = ["stdbuf", "-oL", "journalctl", "-u", "ssh", "-n", "0", "-f", "--output", "cat"]
        # cmd = ["tail", "-f", "/var/log/auth.log"]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except FileNotFoundError:
            print(f"{Colors.CRITICAL}CRITICAL: journalctl not found.{Colors.RESET}")
            return

        print(f"{Colors.INFO}Parser Active (Monitoring SSH via subprocess). Press Ctrl+C to stop.{Colors.RESET}")

        while True:
            line = process.stdout.readline()
            if not line:
                break
            analyze_and_process_line(line.strip(), knowledge_base, schema_obj)

if __name__ == "__main__":
    process_journal_logs()
