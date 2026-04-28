"""
VPN Config Manager — Textual TUI
Requires: pip install textual requests
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Input, Switch,
    Label, Log, TabbedContent, TabPane, ProgressBar, Digits
)
from textual.binding import Binding
from textual.reactive import reactive
from textual import work
from textual.worker import Worker, WorkerState
from textual.screen import ModalScreen

import asyncio
import threading
import socket
import base64
import json
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─────────────────────────────────────────────────────────────────────────────
#  Default config state
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_STATE = {
    "repo_api":     "https://api.github.com/repos/igareck/vpn-configs-for-russia/contents/",
    "base_raw":     "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/",
    "output_file":  "all_configs.txt",
    "timeout":      "1.5",
    "max_threads":  "50",
    "filter_russia": True,
    "server_port":  "8000",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Parser logic (runs in thread)
# ─────────────────────────────────────────────────────────────────────────────

VALID_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
BAD_KEYWORDS   = ["russia", "moscow", "ru", "russian", "россия", "москва", "🇷🇺"]


def get_txt_files(repo_api):
    r = requests.get(repo_api, timeout=10)
    r.raise_for_status()
    return [i["name"] for i in r.json() if i["name"].endswith(".txt")]


def download_file(base_raw, filename):
    r = requests.get(base_raw + filename, timeout=10)
    r.raise_for_status()
    return r.text


def is_not_russia(config):
    t = config.lower()
    return not any(w in t for w in BAD_KEYWORDS)


def extract_configs(text, filter_russia):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if filter_russia and not is_not_russia(line):
            continue
        if line.startswith(VALID_PREFIXES):
            out.append(line)
    return out


def parse_host_port(config):
    try:
        if config.startswith("vmess://"):
            data = base64.b64decode(config[8:] + "==").decode()
            j = json.loads(data)
            return j.get("add"), int(j.get("port"))
        parsed = urlparse(config)
        return parsed.hostname, parsed.port
    except:
        return None, None


def check_config(config, timeout):
    host, port = parse_host_port(config)
    if not host or not port:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return config
    except:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  Server logic
# ─────────────────────────────────────────────────────────────────────────────

_server_instance = None
_server_thread   = None


def make_handler(config_file):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # silence default logging

        def do_GET(self):
            if self.path == "/sub":
                try:
                    with open(config_file, "r", encoding="utf-8") as f:
                        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                    raw     = "\n".join(lines)
                    encoded = base64.b64encode(raw.encode()).decode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(encoded.encode())
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(e).encode())
            else:
                self.send_response(404)
                self.end_headers()
    return Handler


def start_server(port, config_file):
    global _server_instance, _server_thread
    if _server_instance:
        return False, "Сервер уже запущен"
    try:
        handler = make_handler(config_file)
        _server_instance = HTTPServer(("0.0.0.0", port), handler)
        _server_thread = threading.Thread(target=_server_instance.serve_forever, daemon=True)
        _server_thread.start()
        return True, f"http://localhost:{port}/sub"
    except Exception as e:
        return False, str(e)


def stop_server():
    global _server_instance, _server_thread
    if not _server_instance:
        return False, "Сервер не запущен"
    _server_instance.shutdown()
    _server_instance = None
    _server_thread   = None
    return True, "Сервер остановлен"


# ─────────────────────────────────────────────────────────────────────────────
#  Confirm modal
# ─────────────────────────────────────────────────────────────────────────────

class ConfirmModal(ModalScreen):
    CSS = """
    ConfirmModal {
        align: center middle;
    }
    #modal-box {
        width: 50;
        height: 10;
        background: $surface;
        border: double $accent;
        padding: 1 2;
    }
    #modal-msg { margin-bottom: 1; }
    #modal-btns { align: center middle; }
    """

    def __init__(self, message: str, **kwargs):
        super().__init__(**kwargs)
        self._message = message

    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label(self._message, id="modal-msg")
            with Horizontal(id="modal-btns"):
                yield Button("Да", id="yes", variant="error")
                yield Button("Нет", id="no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "yes")


# ─────────────────────────────────────────────────────────────────────────────
#  Status bar widget
# ─────────────────────────────────────────────────────────────────────────────

class StatusBar(Static):
    state = reactive("idle")

    STATE_MAP = {
        "idle":    ("●  Готов к работе",       "status-idle"),
        "running": ("⟳  Выполняется...",       "status-run"),
        "done":    ("✔  Завершено",             "status-done"),
        "error":   ("✖  Ошибка",               "status-err"),
        "server":  ("▶  Сервер запущен",        "status-srv"),
    }

    def render(self) -> str:
        label, _ = self.STATE_MAP.get(self.state, ("?", ""))
        return label

    def watch_state(self, state: str):
        for cls in ["status-idle", "status-run", "status-done", "status-err", "status-srv"]:
            self.remove_class(cls)
        _, cls = self.STATE_MAP.get(state, ("", "status-idle"))
        self.add_class(cls)


# ─────────────────────────────────────────────────────────────────────────────
#  Main App
# ─────────────────────────────────────────────────────────────────────────────

class VPNManagerApp(App):
    TITLE = "VPN Config Manager"

    CSS = """
    /* ── Palette ── */
    $bg:       #0d1117;
    $surface:  #161b22;
    $border:   #30363d;
    $accent:   #58a6ff;
    $green:    #3fb950;
    $yellow:   #d29922;
    $red:      #f85149;
    $text:     #c9d1d9;
    $muted:    #8b949e;

    /* ── App shell ── */
    Screen {
        background: $bg;
        color: $text;
    }

    Header {
        background: $surface;
        color: $accent;
        text-style: bold;
        border-bottom: solid $border;
        height: 3;
    }

    Footer {
        background: $surface;
        color: $muted;
        border-top: solid $border;
    }

    /* ── Tabs ── */
    TabbedContent {
        height: 1fr;
    }

    TabPane {
        padding: 1 2;
    }

    .tab-title {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }

    /* ── Sidebar ── */
    #sidebar {
        width: 28;
        background: $surface;
        border-right: solid $border;
        padding: 1;
    }

    .section-label {
        color: $muted;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 0;
    }

    /* ── Inputs ── */
    Input {
        background: $bg;
        border: solid $border;
        color: $text;
        margin-bottom: 1;
    }

    Input:focus {
        border: solid $accent;
    }

    .field-label {
        color: $muted;
        margin-bottom: 0;
    }

    /* ── Buttons ── */
    Button {
        margin: 0 1 1 0;
        min-width: 14;
    }

    Button.primary   { background: $accent; color: $bg; }
    Button.success   { background: $green;  color: $bg; }
    Button.danger    { background: $red;    color: $bg; }
    Button.warning   { background: $yellow; color: $bg; }

    /* ── Log ── */
    Log {
        background: $bg;
        border: solid $border;
        height: 1fr;
        scrollbar-color: $border;
        scrollbar-background: $bg;
    }

    /* ── Progress ── */
    ProgressBar {
        margin: 1 0;
    }

    ProgressBar > .bar--bar {
        color: $accent;
    }

    ProgressBar > .bar--complete {
        color: $green;
    }

    /* ── Status bar ── */
    StatusBar {
        height: 1;
        padding: 0 1;
        text-style: bold;
    }

    .status-idle { color: $muted; }
    .status-run  { color: $yellow; }
    .status-done { color: $green; }
    .status-err  { color: $red; }
    .status-srv  { color: $accent; }

    /* ── Stat cards ── */
    .stat-card {
        background: $surface;
        border: solid $border;
        padding: 0 1;
        height: 5;
        width: 1fr;
        margin-right: 1;
    }

    .stat-card:last-child { margin-right: 0; }

    .stat-num {
        color: $accent;
        text-style: bold;
        content-align: center middle;
        height: 3;
        width: 1fr;
    }

    .stat-lbl {
        color: $muted;
        content-align: center middle;
        width: 1fr;
    }

    /* ── Switch row ── */
    .switch-row {
        height: 3;
        margin-bottom: 1;
        align: left middle;
    }

    .switch-label {
        width: 1fr;
        content-align: left middle;
    }

    /* ── Server status panel ── */
    #server-status {
        background: $surface;
        border: solid $border;
        padding: 1 2;
        height: 7;
        margin-bottom: 1;
    }

    #server-url {
        color: $green;
        text-style: bold;
    }

    /* ── Divider ── */
    .divider {
        border-top: solid $border;
        margin: 1 0;
        height: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit",          "Выход"),
        Binding("ctrl+p", "run_parser",    "Парсер"),
        Binding("ctrl+s", "toggle_server", "Сервер"),
        Binding("ctrl+l", "clear_log",     "Очистить лог"),
        Binding("f1",     "show_tab('parser')", "Парсер"),
        Binding("f2",     "show_tab('server')", "Сервер"),
        Binding("f3",     "show_tab('log')",    "Лог"),
    ]

    # reactive counters
    _total_found  = reactive(0)
    _total_alive  = reactive(0)
    _server_on    = reactive(False)

    def __init__(self):
        super().__init__()
        self._state  = dict(DEFAULT_STATE)
        self._parser_worker: Worker | None = None

    # ── Layout ──────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent(initial="parser"):

            # ── Tab 1: Parser ──────────────────────────────────────────────
            with TabPane("⚙  Парсер", id="parser"):
                with Horizontal():

                    # sidebar settings
                    with Vertical(id="sidebar"):
                        yield Label("ИСТОЧНИК", classes="section-label")
                        yield Label("Repo API URL", classes="field-label")
                        yield Input(self._state["repo_api"],  id="repo_api",    placeholder="API URL")
                        yield Label("Raw Base URL",  classes="field-label")
                        yield Input(self._state["base_raw"],  id="base_raw",    placeholder="Raw URL")
                        yield Label("Выходной файл", classes="field-label")
                        yield Input(self._state["output_file"], id="output_file", placeholder="all_configs.txt")

                        yield Label("ПРОВЕРКА", classes="section-label")
                        yield Label("Таймаут (сек)", classes="field-label")
                        yield Input(self._state["timeout"],    id="timeout",     placeholder="1.5")
                        yield Label("Потоков",       classes="field-label")
                        yield Input(self._state["max_threads"], id="max_threads", placeholder="50")

                        yield Label("ФИЛЬТРЫ", classes="section-label")
                        with Horizontal(classes="switch-row"):
                            yield Label("Фильтр RU серверов", classes="switch-label")
                            yield Switch(value=self._state["filter_russia"], id="filter_russia")

                    # main area
                    with Vertical():
                        # stat cards
                        with Horizontal():
                            with Vertical(classes="stat-card"):
                                yield Static("0", id="stat-found", classes="stat-num")
                                yield Static("Найдено конфигов", classes="stat-lbl")
                            with Vertical(classes="stat-card"):
                                yield Static("0", id="stat-alive", classes="stat-num")
                                yield Static("Рабочих конфигов", classes="stat-lbl")
                            with Vertical(classes="stat-card"):
                                yield Static("—", id="stat-time", classes="stat-num")
                                yield Static("Время выполнения", classes="stat-lbl")

                        yield ProgressBar(total=100, show_eta=False, id="progress")

                        with Horizontal():
                            yield Button("▶  Запустить", id="btn-run",  classes="primary")
                            yield Button("⏹  Стоп",     id="btn-stop", classes="danger",   disabled=True)
                            yield Button("🗑  Очистить",  id="btn-clear-res", classes="warning")

                        yield StatusBar(id="status-bar", classes="status-idle")

                        yield Log(id="log-parser", auto_scroll=True)

            # ── Tab 2: Server ──────────────────────────────────────────────
            with TabPane("🌐  Сервер", id="server"):
                yield Label("SUBSCRIPTION SERVER", classes="tab-title")

                with Container(id="server-status"):
                    yield Static("Статус: ОСТАНОВЛЕН", id="srv-status-label")
                    yield Static("",                   id="server-url")

                yield Label("Порт", classes="field-label")
                yield Input(self._state["server_port"], id="server_port", placeholder="8000")
                yield Label("Файл конфигов", classes="field-label")
                yield Input(self._state["output_file"], id="srv_config_file", placeholder="all_configs.txt")

                with Horizontal():
                    yield Button("▶  Запустить сервер", id="btn-srv-start", classes="success")
                    yield Button("⏹  Остановить",       id="btn-srv-stop",  classes="danger", disabled=True)

                yield Log(id="log-server", auto_scroll=True)

            # ── Tab 3: Log ─────────────────────────────────────────────────
            with TabPane("📋  Лог", id="log"):
                yield Label("ПОЛНЫЙ ЛОГ СЕССИИ", classes="tab-title")
                yield Log(id="log-full", auto_scroll=True)

        yield Footer()

    def on_mount(self):
        self._log("VPN Config Manager запущен. Удачной охоты 🚀")

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _log(self, msg: str, level: str = "info"):
        prefix = {"info": "ℹ", "ok": "✔", "warn": "⚠", "err": "✖"}.get(level, "·")
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {prefix} {msg}"
        try:
            self.query_one("#log-parser", Log).write_line(line)
            self.query_one("#log-full",   Log).write_line(line)
        except Exception:
            pass

    def _srv_log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        try:
            self.query_one("#log-server", Log).write_line(f"[{ts}] {msg}")
            self.query_one("#log-full",   Log).write_line(f"[{ts}] [SRV] {msg}")
        except Exception:
            pass

    def _update_stats(self, found=None, alive=None):
        if found is not None:
            self._total_found = found
            self.query_one("#stat-found", Static).update(str(found))
        if alive is not None:
            self._total_alive = alive
            self.query_one("#stat-alive", Static).update(str(alive))

    def _set_status(self, state: str):
        self.query_one("#status-bar", StatusBar).state = state

    def _collect_settings(self):
        def v(id_): return self.query_one(f"#{id_}", Input).value.strip()
        self._state.update({
            "repo_api":    v("repo_api")    or DEFAULT_STATE["repo_api"],
            "base_raw":    v("base_raw")    or DEFAULT_STATE["base_raw"],
            "output_file": v("output_file") or DEFAULT_STATE["output_file"],
            "timeout":     v("timeout")     or DEFAULT_STATE["timeout"],
            "max_threads": v("max_threads") or DEFAULT_STATE["max_threads"],
            "server_port": v("server_port") or DEFAULT_STATE["server_port"],
            "filter_russia": self.query_one("#filter_russia", Switch).value,
        })

    # ── Button events ───────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id

        if bid == "btn-run":
            self.action_run_parser()

        elif bid == "btn-stop":
            if self._parser_worker:
                self._parser_worker.cancel()
            self._set_status("idle")
            self._log("Парсер остановлен пользователем", "warn")
            self.query_one("#btn-run",  Button).disabled = False
            self.query_one("#btn-stop", Button).disabled = True

        elif bid == "btn-clear-res":
            self._update_stats(0, 0)
            self.query_one("#stat-time", Static).update("—")
            self.query_one("#progress", ProgressBar).update(progress=0)
            self.query_one("#log-parser", Log).clear()

        elif bid == "btn-srv-start":
            self._collect_settings()
            port = int(self._state["server_port"])
            cfg  = self._state["output_file"]
            ok, msg = start_server(port, cfg)
            if ok:
                self._server_on = True
                self.query_one("#srv-status-label", Static).update("Статус: ✔ ЗАПУЩЕН")
                self.query_one("#server-url",       Static).update(f"URL → {msg}")
                self.query_one("#btn-srv-start", Button).disabled = True
                self.query_one("#btn-srv-stop",  Button).disabled = False
                self._srv_log(f"Сервер запущен → {msg}")
            else:
                self._srv_log(f"Ошибка: {msg}")

        elif bid == "btn-srv-stop":
            ok, msg = stop_server()
            self._server_on = False
            self.query_one("#srv-status-label", Static).update("Статус: ● ОСТАНОВЛЕН")
            self.query_one("#server-url",       Static).update("")
            self.query_one("#btn-srv-start", Button).disabled = False
            self.query_one("#btn-srv-stop",  Button).disabled = True
            self._srv_log(msg)

    # ── Actions ─────────────────────────────────────────────────────────────

    def action_run_parser(self):
        self._collect_settings()
        if not HAS_REQUESTS:
            self._log("Установите requests: pip install requests", "err")
            return
        self.query_one("#btn-run",  Button).disabled = True
        self.query_one("#btn-stop", Button).disabled = False
        self._set_status("running")
        self.query_one("#progress", ProgressBar).update(progress=0)
        self._update_stats(0, 0)
        self._parser_worker = self.run_parser()

    def action_toggle_server(self):
        if self._server_on:
            self.query_one("#btn-srv-stop", Button).press()
        else:
            self.query_one("#btn-srv-start", Button).press()

    def action_clear_log(self):
        self.query_one("#log-parser", Log).clear()
        self.query_one("#log-full",   Log).clear()

    def action_show_tab(self, tab_id: str):
        self.query_one(TabbedContent).active = tab_id

    # ── Worker ──────────────────────────────────────────────────────────────

    @work(exclusive=True, thread=True)
    def run_parser(self):
        t0   = time.time()
        cfg  = self._state
        tout = float(cfg["timeout"])
        thrd = int(cfg["max_threads"])

        try:
            self.call_from_thread(self._log, "Получаю список файлов...")
            files = get_txt_files(cfg["repo_api"])
            self.call_from_thread(self._log, f"Найдено файлов: {len(files)}", "ok")

            all_configs = []
            for fn in files:
                text = download_file(cfg["base_raw"], fn)
                cs   = extract_configs(text, cfg["filter_russia"])
                self.call_from_thread(self._log, f"  {fn}: {len(cs)} конфигов")
                all_configs.extend(cs)

            all_configs = list(dict.fromkeys(all_configs))
            total = len(all_configs)
            self.call_from_thread(self._update_stats, found=total)
            self.call_from_thread(self._log, f"Итого уникальных: {total}", "ok")
            self.call_from_thread(self._log, f"Проверяю {total} конфигов ({thrd} потоков)...")

            alive   = []
            checked = 0

            with ThreadPoolExecutor(max_workers=thrd) as ex:
                futures = {ex.submit(check_config, c, tout): c for c in all_configs}
                for f in as_completed(futures):
                    result = f.result()
                    checked += 1
                    if result:
                        alive.append(result)
                    pct = int(checked / total * 100) if total else 0
                    self.call_from_thread(
                        self.query_one("#progress", ProgressBar).update,
                        progress=pct
                    )
                    if checked % 50 == 0 or checked == total:
                        self.call_from_thread(self._update_stats, alive=len(alive))

            with open(cfg["output_file"], "w", encoding="utf-8") as f:
                f.write("\n".join(alive))

            elapsed = f"{time.time() - t0:.1f}s"
            self.call_from_thread(self.query_one("#stat-time", Static).update, elapsed)
            self.call_from_thread(self._update_stats, alive=len(alive))
            self.call_from_thread(
                self._log,
                f"Готово! Рабочих: {len(alive)}/{total}  [{elapsed}]  → {cfg['output_file']}",
                "ok"
            )
            self.call_from_thread(self._set_status, "done")

        except Exception as e:
            self.call_from_thread(self._log, f"Ошибка: {e}", "err")
            self.call_from_thread(self._set_status, "error")

        finally:
            self.call_from_thread(self.query_one("#btn-run",  Button).__setattr__, "disabled", False)
            self.call_from_thread(self.query_one("#btn-stop", Button).__setattr__, "disabled", True)


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    VPNManagerApp().run()