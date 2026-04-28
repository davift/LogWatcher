#!/usr/bin/env python3
import json
import os
import time
import dotenv
from prometheus_client import start_http_server, CollectorRegistry
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

dotenv.load_dotenv()

KNOWN_PATTERNS_FILE = os.getenv("KNOWN_PATTERNS_FILE", "known.jsonl")
OFFLINE_LOG_FILE = os.getenv("OFFLINE_LOG_FILE", "offline.log")
EXPORTER_ADDR = os.getenv("EXPORTER_ADDR", "0.0.0.0")
EXPORTER_PORT = int(os.getenv("EXPORTER_PORT", 9101))


class KnowledgeBaseCollector:
    def __init__(self, path, offline_path=OFFLINE_LOG_FILE):
        self.path = path
        self.offline_path = offline_path
        self.scrape_count = 0

    def count_unclassified(self):
        count = 0
        try:
            with open(self.offline_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
        except FileNotFoundError:
            pass
        return count

    def collect(self):
        self.scrape_count += 1
        rows = {}
        counts = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    severity = str(entry.get("severity", "INFO")).upper()
                    rows[severity] = rows.get(severity, 0) + 1
                    counts[severity] = counts.get(severity, 0) + int(entry.get("count", 0) or 0)
        except FileNotFoundError:
            pass

        unclassified = self.count_unclassified()
        rows["UNCLASSIFIED"] = unclassified
        counts["UNCLASSIFIED"] = unclassified

        patterns_metric = GaugeMetricFamily(
            "logwatcher_known_patterns",
            "Number of rows (distinct patterns) per severity.",
            labels=["severity"],
        )
        events_metric = CounterMetricFamily(
            "logwatcher_events",
            "Combined match counts per severity.",
            labels=["severity"],
        )
        for severity in sorted(rows):
            patterns_metric.add_metric([severity], rows[severity])
            events_metric.add_metric([severity], counts[severity])
        yield patterns_metric
        yield events_metric


def main():
    registry = CollectorRegistry()
    collector = KnowledgeBaseCollector(KNOWN_PATTERNS_FILE)
    registry.register(collector)
    start_http_server(EXPORTER_PORT, addr=EXPORTER_ADDR, registry=registry)
    print(f"Exporter on http://{EXPORTER_ADDR}:{EXPORTER_PORT}/metrics (KB: {KNOWN_PATTERNS_FILE})")
    try:
        while True:
            time.sleep(3600)
            print(f"Metrics scraped {collector.scrape_count} times so far.")
    except KeyboardInterrupt:
        print("\nShutting down exporter.")


if __name__ == "__main__":
    main()
