#!/usr/bin/env python3

import json
import re
import sys
import signal
import time
import atexit
import requests
from jsonschema import validate, ValidationError
import os
import dotenv
dotenv.load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_KEY", "")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_KEY", "")

DEBUGGING = int(os.getenv("DEBUGGING", 0))
SYSTEMD = int(os.getenv("SYSTEMD", 0))
LOG_HEADER_RE = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} ')
LOGID_RE = re.compile(r'\(logid:[0-9a-z]*\) ')
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", 100))
FLUSH_INTERVAL = int(os.getenv("FLUSH_INTERVAL", 15))

PROVIDER = os.getenv("PROVIDER", "ollama")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://192.168.1.101:11434/api/generate")
OLLAMA_MODELS = [
    # Recommended options.
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
OPENAI_MODELS = [
    'gpt-5.4-mini',      #0 Cheaper but not really useful.
    'gpt-5.4',           #1 Intermediate.
    'gpt-5.5',           #2 Expensive but slower.
]
ANTHROPIC_MODELS = [
    'claude-haiku-4-5',  #0 Cheaper and faster.
    'claude-sonnet-4-6', #1 Intermediate.
    'claude-opus-4-7',   #2 Expensive but slower.
]
INDEX=0 if len(sys.argv) <= 1 else int(sys.argv[1])

def _pick(models):
    return models[INDEX] if 0 <= INDEX < len(models) else models[0]

MODEL = _pick(OLLAMA_MODELS)
OPENAI_MODEL = _pick(OPENAI_MODELS)
ANTHROPIC_MODEL = _pick(ANTHROPIC_MODELS)

KNOWN_PATTERNS_FILE = "known.jsonl"
SCHEMA_FILE = 'schema.json'

modified = False
last_write = time.time()
lines_processed = 0
pattern_match_times = {}

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

def print_timing_summary():
    if not pattern_match_times:
        return
    sorted_times = sorted(pattern_match_times.items(), key=lambda x: x[1]["total"], reverse=True)
    print("\n\nTop #20 Pattern Matching Wasted Time:\n")
    for entry_id, times in sorted_times[:20]:
        print(f"{Colors.DEBUG}[{entry_id}]\ttotal={times['total']:.0f}s\tlast={times['last']*1000:.3f}ms{Colors.RESET}")

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
    patterns.sort(key=lambda p: p.get("count", 0), reverse=True)
    return patterns

def write_knowledge_base(patterns, filename):
    global modified, last_write
    sorted_for_disk = sorted(patterns, key=lambda p: p.get("original_message", ""))
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for entry in sorted_for_disk:
                f.write(json.dumps(entry) + '\n')
        debug_print(f"Knowledge base flushed to {filename} ({len(patterns)} patterns)")
    except Exception as e:
        debug_print(f"Failed writing knowledge base: {e}")
    modified = False
    last_write = time.time()

def maybe_flush(patterns, filename):
    global modified, last_write
    if modified and (time.time() - last_write >= FLUSH_INTERVAL):
        write_knowledge_base(patterns, filename)

def get_next_id(patterns):
    if not patterns:
        return 1
    return max(p.get("id", 0) for p in patterns) + 1

def write_offline_log(log_line):
    print(f"{Colors.WARNING} [!] OFFLINE MODE{Colors.RESET}")
    with open("offline.log", "a", encoding="utf-8") as f:
        f.write(log_line + "\n")

def is_in_offline_log(log_line):
    try:
        with open("offline.log", "r", encoding="utf-8") as f:
            return any(line.strip() == log_line for line in f)
    except FileNotFoundError:
        return False

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
        print("Asking AI...\n")

        if PROVIDER == "ollama":
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
            debug_print(f"[DEBUG] REQUEST: \n\n{log_message}\n")
            debug_print(f"[DEBUG] RESPONSE ({response.elapsed.total_seconds():.0f}s): \n\n{response.json()['response']}\n")

            response.raise_for_status()
            ai_data = json.loads(response.json()['response'])
        elif PROVIDER == "openai":
            if not OPENAI_KEY:
                print(f"{Colors.CRITICAL}CRITICAL: OPENAI_KEY not set.{Colors.RESET}")
                return None
            openai_url = "https://api.openai.com/v1/responses"
            headers = {
                "Authorization": f"Bearer {OPENAI_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": OPENAI_MODEL,
                "input": [
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"Log Line: {log_message}"}
                ],
                "max_output_tokens": 20480
            }
            response = requests.post(openai_url, headers=headers, json=payload, timeout=180)
            response.raise_for_status()
            result = response.json()
            debug_print(f"[DEBUG] OPENAI REQUEST: \n\n{log_message}\n")
            debug_print(f"[DEBUG] OPENAI RESPONSE: \n\n{result}\n")
            content = result["output"][0]["content"][0]["text"].strip()
            if content.startswith("```json"):
                content = content[7:].strip()
                if content.endswith("```"):
                    content = content[:-3].strip()
            ai_data = json.loads(content)
        elif PROVIDER == "anthropic":
            if not ANTHROPIC_KEY:
                print(f"{Colors.CRITICAL}CRITICAL: ANTHROPIC_KEY not set.{Colors.RESET}")
                return None
            anthropic_url = "https://api.anthropic.com/v1/messages"
            headers = {
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            }
            payload = {
                "model": ANTHROPIC_MODEL,
                "max_tokens": 20480,
                "system": prompt,
                "messages": [
                    {"role": "user", "content": f"Log Line: {log_message}"}
                ]
            }
            response = requests.post(anthropic_url, headers=headers, json=payload, timeout=180)
            response.raise_for_status()
            result = response.json()
            debug_print(f"[DEBUG] ANTHROPIC REQUEST: \n\n{log_message}\n")
            debug_print(f"[DEBUG] ANTHROPIC RESPONSE: \n\n{result}\n")
            content = result["content"][0]["text"].strip()
            if content.startswith("```json"):
                content = content[7:].strip()
                if content.endswith("```"):
                    content = content[:-3].strip()
            ai_data = json.loads(content)
        else:
            write_offline_log(log_message)
            return None

        debug_print("Validating response against schema.json")
        if schema_obj:
            validate(instance=ai_data, schema=schema_obj)
        return ai_data
    except ValidationError as ve:
        print(f"{Colors.ERROR}[ERROR] AI JSON failed validation: {ve.message}{Colors.RESET}")
        return None
    except Exception as e:
        msg = "AI communication failure:"
        e_str = str(e)
        if "429" in e_str or ("400" in e_str and "anthropic.com" in e_str):
            msg += " (quota may have exceeded)"
        print(f"{Colors.ERROR}[ERROR] {msg} {e}{Colors.RESET}")
        write_offline_log(log_message)
        return None

def analyze_and_process_line(log_line, knowledge_base, schema_obj):
    global lines_processed
    if not log_line:
        return

    content = LOG_HEADER_RE.sub('', log_line).strip()
    if not content:
        return

    lines_processed += 1
    if not DEBUGGING and lines_processed % 10000 == 0:
        print(f"{Colors.DEBUG}[INFO] Lines processed: {lines_processed}{Colors.RESET}", flush=True)

    match_found = None
    for entry_kb in knowledge_base:
        try:
            t0 = time.perf_counter()
            matched = re.search(entry_kb['pattern_message'], content)
            elapsed = time.perf_counter() - t0
            entry_id = entry_kb.get('id', 0)
            prev = pattern_match_times.get(entry_id, {"total": 0.0, "last": 0.0})
            pattern_match_times[entry_id] = {"total": prev["total"] + elapsed, "last": elapsed}
            if matched:
                match_found = entry_kb
                break
        except re.error as e:
            print(f"[WARN] Invalid regex in entry id={entry_kb.get('id')}: {e}", flush=True)
            continue

    if match_found:
        match_found["count"] += 1
        match_found["original_message"] = content
        knowledge_base.sort(key=lambda p: p.get("count", 0), reverse=True)
        global modified
        modified = True
        color = get_color(match_found['severity'])
        debug_print(f"{color}[CACHED: {match_found['severity']}] {content}{Colors.RESET}")
    else:
        debug_print("No match in knowledge base.")
        if is_in_offline_log(content):
            debug_print("Already queued in offline.log, skipping AI.")
            return

        logid_match = LOGID_RE.search(content)
        if logid_match:
            content_for_ai = content[logid_match.end():]
            logid_stripped = True
        else:
            content_for_ai = content
            logid_stripped = False

        full_ai_response = ask_ai(content_for_ai, schema_obj)

        if full_ai_response:
            severity = full_ai_response.get("severity", "INFO")
            pattern = full_ai_response.get("pattern_message", "")

            if logid_stripped and pattern.startswith("^"):
                pattern = pattern[1:]

            try:
                if not pattern or not re.search(pattern, content):
                    pattern = re.escape(content)
            except re.error:
                pattern = re.escape(content)

            new_entry = {
                "id": get_next_id(knowledge_base),
                "count": 1,
                "severity": severity,
                "original_message": content,
                "pattern_message": pattern,
                "analysis": full_ai_response.get('analysis', {})
            }

            color = get_color(severity)
            print(f"{color}[NEW: {severity}] {content}{Colors.RESET}")
            knowledge_base.append(new_entry)
            modified = True
        else:
            debug_print("AI processing failed. Log ignored.")

def process_journal_logs():
    knowledge_base = load_known_patterns()
    schema_obj = load_json_schema()

    atexit.register(lambda: write_knowledge_base(knowledge_base, KNOWN_PATTERNS_FILE) if modified else None)
    atexit.register(print_timing_summary)

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
        
        print(f"{Colors.INFO}Parser Active (via systemd-python). Press Ctrl+C to stop.{Colors.RESET}")

        while True:
            ready = select.select([j], [], [], 5.0)
            if not ready[0]:
                debug_print("Waiting for journal events...")
                maybe_flush(knowledge_base, KNOWN_PATTERNS_FILE)
                continue

            change_type = j.process()
            if change_type == journal.INVALIDATE:
                j.seek_tail()
                j.get_previous()
                continue
            if change_type != journal.APPEND:
                continue

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
            maybe_flush(knowledge_base, KNOWN_PATTERNS_FILE)
    else:
        # When SYSTEMD is set to False.
        debug_print("Opening stream...")
        import subprocess

        ##
        ## If not using the systemd-python approach, customize the command below to stream logs from any source.
        ##

        # Example for streaming via subprocess.
        # cmd = ["stdbuf", "-oL", "journalctl", "-u", "ssh", "-n", "0", "-f", "--output", "cat"]
        
        # Basic live monitoring of any log file.
        # cmd = ["tail", "-f", "/var/log/auth.log"]
        
        # Learning patterns from a static file instead of live monitoring.
        cmd = ["cat", "log.log"]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except FileNotFoundError:
            print(f"{Colors.CRITICAL}CRITICAL: streaming failed or command not found.{Colors.RESET}")
            return

        print(f"{Colors.INFO}Parser Active (streaming via subprocess). Press Ctrl+C to stop.{Colors.RESET}")

        while True:
            line = process.stdout.readline()
            if not line:
                break
            analyze_and_process_line(line.strip(), knowledge_base, schema_obj)
            maybe_flush(knowledge_base, KNOWN_PATTERNS_FILE)

if __name__ == "__main__":
    process_journal_logs()
