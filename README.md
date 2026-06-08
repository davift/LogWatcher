# LogWatcher

![logs flowing](https://github.com/davift/LogWatcher/blob/main/image00.gif)

An AI-powered log monitoring tool that analyzes entries in real time, classifies
them by severity, and builds a local pattern knowledge base for instant, offline
re-matching. So, the AI is only ever consulted once per unique log pattern.

While it is recommended to watch the output of a systemd unit (services or timers),
it can monitor any source of logs.

![unknown pattern](https://github.com/davift/LogWatcher/blob/main/image01.png)
![known patterns](https://github.com/davift/LogWatcher/blob/main/image02.png)

## Architecture

LogWatcher is three independent modules around one shared knowledge base
(`known.jsonl`):

| Module | File | Role |
|---|---|---|
| **Watcher**  | `watcher.py`  | Reads the log stream, matches/classifies lines, grows the knowledge base. |
| **Exporter** | `exporter.py` | Exposes pattern/event counts per severity as Prometheus metrics (`:9101`). |
| **Editor**   | `editor.py`   | Flask web UI (`:5000`) to review, correct, and delete knowledge-base entries. |

## How It Works

1. **Reads a log stream** from the systemd journal (`systemd-python`), or any
   command such as `journalctl -f`, `tail -f`, or `cat` (configured in `watcher.py`).
2. **Matches each line** against `known.jsonl`, a local knowledge base of regex
   patterns. A hit is resolved instantly with no AI call.
3. **Asks the AI** for unrecognized lines to classify severity, extract entities,
   and generate a generalizing regex. Provider is chosen via `.env`:
   `ollama` (local), `openai`, `anthropic`, or `offline`.
4. **Validates** the AI response against `schema.json` and **caches** the new
   pattern so future matching lines resolve without another AI call.
5. **Prints color-coded output**  red CRITICAL, orange ERROR, yellow WARNING,
   green INFO, and periodically flushes the knowledge base to disk.

If the AI is unreachable or a provider is set to `offline`, unmatched lines are
queued in `offline.log` instead of being lost or re-sent.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/davift/LogWatcher/refs/heads/main/install.sh | sudo bash
```

## Configuration

Edit `.env` and set the provider, keys, and tuning values:

| Variable | Purpose |
|---|---|
| `PROVIDER` | `ollama`, `openai`, `anthropic`, or `offline`. |
| `SYSTEMD` | `1` reads the systemd journal; `0` streams from a subprocess command. |
| `OLLAMA_URL` / `OPENAI_KEY` / `ANTHROPIC_KEY` | Provider endpoint / credentials. |
| `FLUSH_INTERVAL`, `MAX_QUEUE_SIZE` | Disk-flush cadence and journal burst cap. |

## Observability

`exporter.py` exposes `logwatcher_known_patterns` and `logwatcher_events` per
severity for Prometheus. Import `dashboard.json` or `dashboard_25380.json` into
Grafana to visualize them.

![exporter dashboard](https://github.com/davift/LogWatcher/blob/main/image06.png)

Import the dashboard template num: `25380` (https://grafana.com/grafana/dashboards/25380-logwatcher/)

## Severity Levels

| Level | Trigger |
|---|---|
| CRITICAL | Auth failures, brute-force, unauthorized access. |
| ERROR | Hardware/kernel issues. |
| WARNING | Connection errors, timeouts, crashes. |
| INFO | Routine status and noise. |
| UNCLASSIFIED | Not matched in offline mode or AI failure. |

## KB Editor

A web editor for reviewing and correcting learned patterns (set
`confidence_score` to 10 to mark an entry as human-verified).

![editor list](https://github.com/davift/LogWatcher/blob/main/image03.png)
![editor entry](https://github.com/davift/LogWatcher/blob/main/image04.png)

## Bonus

When the `/watcher.py` is interrupted, it presents a list of the patterns that are taking much CPU time to perform the Regex pattern maching. This gives an admin the visibility on what Regex patterns need to be optimized for best performance.

![exporter dashboard](https://github.com/davift/LogWatcher/blob/main/image05.png)
