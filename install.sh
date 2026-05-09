#!/usr/bin/env bash
set -euo pipefail


REPO_URL="https://github.com/davift/LogWatcher.git"
INSTALL_DIR="/opt/LogWatcher"
VENV="$INSTALL_DIR/.venv"
PYTHON="$VENV/bin/python"

# G=green (ok), Y=yellow (warning), R=red (error), B=bold, X=reset back to normal.
G=$'\033[92m'; Y=$'\033[93m'; R=$'\033[91m'; B=$'\033[1m'; X=$'\033[0m'


if [ "$(id -u)" -ne 0 ]; then
    echo "${R}This installer must be run with root privileges.${X}" >&2
    exit 1
fi

for tool in git systemctl; do
    if ! command -v "$tool" >/dev/null; then
        echo "${R}Required '$tool' is not installed.${X}" >&2
        exit 1
    fi
done

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "${G}Updating existing install in: $INSTALL_DIR${X}"
    git -C "$INSTALL_DIR" pull --ff-only
else
    echo "${G}Downloading LogWatcher into $INSTALL_DIR${X}"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

if [ ! -f "$PYTHON" ]; then
    echo "${G}Creating Python virtual environment and installing dependencies.${X}"
    python3 -m venv "$VENV"
    "$PYTHON" -m pip install --quiet --upgrade pip
    "$PYTHON" -m pip install --quiet requests jsonschema systemd-python python-dotenv flask prometheus-client
fi

if [ -f "$INSTALL_DIR/.env" ]; then
    echo "${G}.env already exists.${X}"
elif [ -f "$INSTALL_DIR/_env" ]; then
    cp "$INSTALL_DIR/_env" "$INSTALL_DIR/.env"
    echo "${Y}Created $INSTALL_DIR/.env from template. Edit it before starting services.${X}"
fi

install_module() {
    local name="$1"
    local description="$2"
    local command="$3"
    local unit="logwatcher-$name.service"

    cat > "/etc/systemd/system/$unit" <<EOF
[Unit]
Description=$description
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=-$INSTALL_DIR/.env
ExecStart=$command
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo
    echo "${B}Service $name installed at /etc/systemd/system/$unit${X}"
    echo "  start now:     ${G}systemctl start $unit${X}"
    echo "  start on boot: ${G}systemctl enable $unit${X}"
    echo "  view logs:     ${G}journalctl -u $unit -f${X}"
    if [ "$name" = "watcher" ]; then
        touch $INSTALL_DIR/offline.log
        touch $INSTALL_DIR/known.jsonl
        echo "${Y}Remember to edit $INSTALL_DIR/.env before starting the service.${X}"
    fi
}

while true; do
    echo
    echo "${B}LogWatcher | choose a module to install:${X}"
    echo "  1) watcher   | reads logs, classifies and matches them."
    echo "  2) exporter  | exposes metrics to Prometheus."
    echo "  3) editor    | web editor for the knowledge base."
    echo "  4) exit"
    echo
    read -r -p "Selection [1-4]: " choice < /dev/tty || choice="4"

    case "$choice" in
        1|watcher)
            install_module watcher  "LogWatcher - Watcher"  "$PYTHON $INSTALL_DIR/watcher.py"
            ;;
        2|exporter)
            install_module exporter "LogWatcher - Exporter" "$PYTHON $INSTALL_DIR/exporter.py"
            ;;
        3|editor)
            install_module editor   "LogWatcher - Editor"   "$PYTHON $INSTALL_DIR/editor.py"
            ;;
        *)
            echo "${G}Exited${X}"
            exit 0
            ;;
    esac
done

