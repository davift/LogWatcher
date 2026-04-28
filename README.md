# LogWatcher

An AI-powered log monitoring tool that analyzes entries in real time, classifies them by severity, and builds a local pattern knowledge base for quick identification of patterns.

While it is recommended to watch outputs of a systemd unity (services or timers), it can monitor any source of logs.

![unknown pattern](https://github.com/davift/LogWatcher/blob/main/image01.png)

![known patterns](https://github.com/davift/LogWatcher/blob/main/image02.png)

## How It Works

1. **Reads log stream** from the systemd journal, `journalctl`, or even `tail`.
2. **Checks each log line** against a local knowledge base of known regex patterns.
3. **Hits a local LLM** for any unrecognized patterns to classify severity, extract entities, and generate a generalizing regex pattern.
4. **Caches the result** so future matching lines are resolved instantly without another AI call.
5. **Prints color-coded output** — red for CRITICAL, orange for ERROR, yellow for WARNING, green for INFO

## Requirements

- A running [Ollama](https://ollama.com) instance (default: `http://IP:11434`)
- `systemd-python` (for journal mode) or `journalctl` in PATH

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests jsonschema systemd-python dotenv flask prometheus-client
```

## Usage

Make sure the file `.env` is set and configured. Copy the template file `_env`.

```bash
python3 watcher.py <model_index>
```

```bash
python3 editor.py
```

## Metrics (Prometheus)

`exporter.py` exposes summarized knowledge-base metrics for each severity type.
It re-reads `known.jsonl` on every scrape, so it stays in sync with whatever
`watcher.py` flushes to disk — no shared state with the watcher process.

```bash
python3 exporter.py
# then scrape:
curl -s http://localhost:9847/metrics | grep logwatcher_
```

| Metric | Type | Description |
|---|---|---|
| `logwatcher_log_events_total{severity}` | counter | Total log lines matched, summed per severity |
| `logwatcher_known_patterns{severity}` | gauge | Distinct learned patterns per severity |
| `logwatcher_known_patterns_total` | gauge | Total distinct patterns in the KB |
| `logwatcher_log_events_grand_total` | gauge | Total matched lines across all severities |
| `logwatcher_kb_malformed_lines` | gauge | Unparseable KB lines on the last scrape |
| `logwatcher_kb_readable` | gauge | `1` if the KB file was readable, else `0` |
| `logwatcher_kb_last_scrape_timestamp_seconds` | gauge | Unix time of the last scrape |

Configurable via `.env`: `EXPORTER_PORT` (default `9847`), `EXPORTER_ADDR`
(default `0.0.0.0`), `KNOWN_PATTERNS_FILE` (default `known.jsonl`).

## Configuration

Edit the top of `watcher.py` to adjust:

| Variable | Description |
|---|---|
| `OLLAMA_URL` | Address of your Ollama API |
| `DEBUGGING` | Toggle verbose debug output |
| `SYSTEMD` | `True` = use `systemd-python`, `False` = use `journalctl` subprocess |

## Testing

`tester.sh` generates a variety of SSH events against a target host to exercise the watcher: normal logins, auth failures, brute-force bursts, credential stuffing, tunneling attempts, and more.

```bash
bash tester.sh
```

## Severity Levels

| Level | Color | Trigger |
|---|---|---|
| CRITICAL | 🔴 Red | Auth failures, brute-force, unauthorized access |
| ERROR | 🟠 Orange | Hardware/kernel issues |
| WARNING | 🟡 Yellow | Connection errors, timeouts, crashes |
| INFO | 🟢 Green | Routine status and noise |

## KB Editor

![unknown pattern](https://github.com/davift/LogWatcher/blob/main/image03.png)

![known patterns](https://github.com/davift/LogWatcher/blob/main/image04.png)

## Bonus

Trick to reset all counter in the KB to zero.

```bash
jq -c '.count = 0' known.jsonl > known.tmp && mv known.tmp known.jsonl
```

