"""
VPN Config Manager — расширенная версия
Архитектура:
  - configs/user_config.yaml  — конфиг пользователя (список источников, фильтры)
  - data/raw_alive.txt        — всё что прошло TCP-проверку (парсер)
  - data/filtered.txt         — финальный список после всех фильтров (сервер / вручную)
"""

import os
import json
import re
import time
import base64
import socket
import shutil
import hashlib
import threading
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Input, Switch,
    Label, Log, TabbedContent, TabPane, ProgressBar,
    Collapsible, Select, TextArea
)
from textual.binding import Binding
from textual import work, on
from textual.screen import ModalScreen

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─────────────────────────────────────────────────────────────────────────────
# Пути
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_DIR = "configs"
DATA_DIR   = "data"
CONFIG_FILE       = os.path.join(CONFIG_DIR, "user_config.yaml")
CONFIG_DEFAULT    = os.path.join(CONFIG_DIR, "default_config.yaml")
RAW_ALIVE_FILE    = os.path.join(DATA_DIR, "raw_alive.txt")
FILTERED_FILE     = os.path.join(DATA_DIR, "filtered.txt")
CONFIG_HASH_FILE  = os.path.join(DATA_DIR, ".config_hash")

# ─────────────────────────────────────────────────────────────────────────────
# Дефолтная конфигурация (YAML как строка — не нужен файл)
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG_YAML = """# VPN Config Manager — конфиг пользователя
# Документация: все поля опциональны, если не указано — используются дефолты

# ─── Источники ───────────────────────────────────────────────────────────────
# Стратегии:
#   api     — GitHub API: получаем список файлов, потом качаем каждый
#   direct  — прямые URL: качаем конкретные файлы
#   base64  — как direct, но файл содержит base64-encoded данные
#   yaml    — YAML/JSON файл с полем 'proxies' (Clash-формат)
sources:
  - name: "igareck/vpn-configs-for-russia"
    enabled: true
    strategy: api
    api_url: "https://api.github.com/repos/igareck/vpn-configs-for-russia/contents/"
    raw_base: "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/"
    file_extensions: [".txt"]
    # subdirs: []  # если нужно смотреть в поддиректориях

  - name: "AvenCores/goida-vpn-configs"
    enabled: true
    strategy: api
    api_url: "https://api.github.com/repos/AvenCores/goida-vpn-configs/contents/"
    raw_base: "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/"
    file_extensions: [".txt"]

  - name: "ebrasha/free-v2ray-public-list"
    enabled: true
    strategy: api
    api_url: "https://api.github.com/repos/ebrasha/free-v2ray-public-list/contents/"
    raw_base: "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/"
    file_extensions: [".txt"]

  - name: "mahdibland/V2RayAggregator"
    enabled: true
    strategy: direct
    urls:
      - "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity"
      - "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt"

  - name: "barry-far/V2ray-Config"
    enabled: true
    strategy: direct
    urls:
      - "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt"
      - "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"
      - "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vmess.txt"
      - "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt"

  - name: "MatinGhanbari/v2ray-configs"
    enabled: true
    strategy: direct
    urls:
      - "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all.txt"

  - name: "Epodonios/v2ray-configs"
    enabled: true
    strategy: direct
    urls:
      - "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"

  - name: "ermaozi/get_subscribe"
    enabled: true
    strategy: base64
    urls:
      - "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"

  - name: "NiREvil/vless"
    enabled: true
    strategy: base64
    urls:
      - "https://raw.githubusercontent.com/NiREvil/vless/main/sub/sing-box"

  - name: "anaer/Sub"
    enabled: true
    strategy: base64
    urls:
      - "https://raw.githubusercontent.com/anaer/Sub/main/sub.txt"

  # Пример пользовательского источника:
  # - name: "my-custom-source"
  #   enabled: false
  #   strategy: direct
  #   urls:
  #     - "https://example.com/my-configs.txt"

# ─── GitHub токен (для обхода rate limit 60→5000 req/h) ─────────────────────
github:
  token: ""
  # Получить бесплатно: https://github.com/settings/tokens (без прав — только public)

# ─── Протоколы ───────────────────────────────────────────────────────────────
protocols:
  # Режим: whitelist — только указанные; blacklist — все кроме указанных; auto — любые ://
  mode: whitelist
  # Список разрешённых протоколов (только для whitelist):
  allowed:
    - vless
    - vmess
    - trojan
    - ss
    - ssr
    - tuic
    - hysteria
    - hysteria2
    - hy2
  # Список запрещённых (только для blacklist):
  # denied: []

# ─── TCP-чекер (первый этап — парсер) ───────────────────────────────────────
checker:
  enabled: true
  timeout: 1.5      # секунды
  max_threads: 50
  # Сохранять raw_alive даже при отключённом чекере:
  save_unchecked: true

# ─── Фильтры (второй этап — применяются к raw_alive при запросе) ────────────
filters:
  # Фильтрация по ключевым словам в строке конфига
  keyword_blacklist:
    enabled: true
    case_sensitive: false
    words:
      - russia
      - moscow
      - москва
      - россия
      - russian
      - "🇷🇺"
      - "-ru-"
      - ".ru:"

  # Фильтрация по стране через GeoIP (требует geoip2 + базу данных)
  # geoip:
  #   enabled: false
  #   deny_countries: [RU, BY, IR]
  #   db_path: "GeoLite2-Country.mmdb"

  # Лимит на количество конфигов в выдаче
  max_configs: 0   # 0 = без лимита

# ─── Локальный сервер (subscription endpoint) ────────────────────────────────
server:
  host: "0.0.0.0"
  port: 8000
  path: "/sub"
  # Формат ответа: base64 (стандарт V2Ray) или plain
  response_format: base64
  # Применять фильтры при каждом запросе к серверу:
  apply_filters_on_request: true
"""

# ─────────────────────────────────────────────────────────────────────────────
# Работа с конфигом
# ─────────────────────────────────────────────────────────────────────────────
def init_system():
    for d in [CONFIG_DIR, DATA_DIR]:
        os.makedirs(d, exist_ok=True)
    if not os.path.exists(CONFIG_DEFAULT):
        with open(CONFIG_DEFAULT, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_YAML)
    if not os.path.exists(CONFIG_FILE):
        shutil.copy(CONFIG_DEFAULT, CONFIG_FILE)

def load_config() -> dict:
    """Загружает YAML-конфиг. Если yaml не установлен — fallback на встроенный парсер."""
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        raw = f.read()
    if HAS_YAML:
        return yaml.safe_load(raw)
    # Минимальный fallback: вернуть дефолтную конфигурацию как dict
    return _minimal_config()

def _minimal_config() -> dict:
    """Минимальный конфиг если pyyaml не установлен."""
    return {
        "sources": [],
        "github": {"token": ""},
        "protocols": {"mode": "whitelist", "allowed": ["vless","vmess","trojan","ss","ssr"]},
        "checker": {"enabled": True, "timeout": 1.5, "max_threads": 50, "save_unchecked": True},
        "filters": {
            "keyword_blacklist": {"enabled": True, "case_sensitive": False,
                                  "words": ["russia","moscow","москва","россия","🇷🇺"]},
            "max_configs": 0
        },
        "server": {"host": "0.0.0.0", "port": 8000, "path": "/sub",
                   "response_format": "base64", "apply_filters_on_request": True}
    }

def get_config_hash() -> str:
    with open(CONFIG_FILE, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

def save_config_hash():
    with open(CONFIG_HASH_FILE, "w") as f:
        f.write(get_config_hash())

def config_changed_since_last_filter() -> bool:
    if not os.path.exists(CONFIG_HASH_FILE):
        return True
    with open(CONFIG_HASH_FILE) as f:
        saved = f.read().strip()
    return saved != get_config_hash()

# ─────────────────────────────────────────────────────────────────────────────
# Протоколы — автодетект
# ─────────────────────────────────────────────────────────────────────────────
# Известные протоколы (для информации в логах), но НЕ ограничение
KNOWN_PROTOCOLS = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "tuic", "hysteria", "hysteria2", "hy2",
    "trojan-go", "shadowsocks", "socks", "socks5",
    "http", "https", "naive", "brook",
}

def detect_protocol(line: str) -> str | None:
    """Автодетект протокола из строки конфига."""
    m = re.match(r'^([a-zA-Z0-9_\-]+)://', line)
    if m:
        return m.group(1).lower()
    return None

def is_protocol_allowed(proto: str, cfg: dict) -> bool:
    """Проверка протокола согласно настройкам конфига."""
    pcfg = cfg.get("protocols", {})
    mode = pcfg.get("mode", "auto")

    if mode == "auto":
        return True  # любой протокол с :// разрешён

    if mode == "whitelist":
        allowed = [p.lower() for p in pcfg.get("allowed", [])]
        return proto.lower() in allowed

    if mode == "blacklist":
        denied = [p.lower() for p in pcfg.get("denied", [])]
        return proto.lower() not in denied

    return True

# ─────────────────────────────────────────────────────────────────────────────
# Парсинг host/port из конфига
# ─────────────────────────────────────────────────────────────────────────────
def parse_host_port(config: str):
    try:
        proto = detect_protocol(config)
        if not proto:
            return None, None

        if proto == "vmess":
            # VMess: base64-encoded JSON
            b64 = config[len("vmess://"):]
            # Padding
            b64 += "=" * (4 - len(b64) % 4)
            try:
                data = base64.b64decode(b64).decode("utf-8", errors="ignore")
                j = json.loads(data)
                return j.get("add"), int(j.get("port", 0))
            except Exception:
                return None, None

        if proto in ("ss", "ssr"):
            # ss://BASE64@host:port  или  ss://BASE64  (старый формат)
            rest = config[len(f"{proto}://"):]
            if "@" in rest:
                host_part = rest.split("@")[-1].split("#")[0].split("?")[0]
                host, _, port = host_part.rpartition(":")
                return host, int(port) if port.isdigit() else None
            else:
                # Старый ss: всё base64
                try:
                    decoded = base64.b64decode(rest.split("#")[0] + "==").decode()
                    host_part = decoded.split("@")[-1] if "@" in decoded else ""
                    host, _, port = host_part.rpartition(":")
                    return host, int(port) if port.isdigit() else None
                except Exception:
                    return None, None

        # Универсальный парсинг через urlparse (vless, trojan, tuic, hysteria…)
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port
        if host and port:
            return host, int(port)

        return None, None
    except Exception:
        return None, None

def check_tcp(config: str, timeout: float) -> str | None:
    h, p = parse_host_port(config)
    if not h or not p:
        return None
    try:
        with socket.create_connection((h, p), timeout=timeout):
            return config
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────────────────────
# Декодирование base64-подписок
# ─────────────────────────────────────────────────────────────────────────────
def try_decode_base64(text: str) -> str:
    """Пробует декодировать как base64-subscription. Возвращает исходный текст если не удалось."""
    stripped = text.strip().replace("\n", "").replace("\r", "")
    for padding in [0, 1, 2, 3]:
        try:
            decoded = base64.b64decode(stripped + "=" * padding).decode("utf-8", errors="ignore")
            # Считаем что это подписка если в ней есть хоть один известный протокол
            if re.search(r'[a-z0-9]+://', decoded):
                return decoded
        except Exception:
            continue
    return text

# ─────────────────────────────────────────────────────────────────────────────
# Загрузка источников
# ─────────────────────────────────────────────────────────────────────────────
def fetch_source(source: dict, headers: dict, log_fn) -> list[str]:
    """Загружает конфиги из одного источника. Возвращает список сырых строк."""
    name     = source.get("name", "unknown")
    strategy = source.get("strategy", "direct")
    texts    = []

    try:
        if strategy == "api":
            texts = _fetch_api(source, headers, log_fn, name)
        elif strategy == "direct":
            texts = _fetch_direct(source, headers, log_fn, name)
        elif strategy == "base64":
            texts = _fetch_base64(source, headers, log_fn, name)
        elif strategy == "yaml":
            texts = _fetch_yaml_clash(source, headers, log_fn, name)
        else:
            log_fn(f"[{name}] ⚠ Неизвестная стратегия: {strategy}")
    except Exception as e:
        log_fn(f"[{name}] ✗ Критическая ошибка: {e}")

    return texts

def _fetch_api(source, headers, log_fn, name) -> list[str]:
    api_url    = source.get("api_url", "")
    raw_base   = source.get("raw_base", "")
    extensions = source.get("file_extensions", [".txt"])
    subdirs    = source.get("subdirs", [None])  # None = корень

    texts = []
    for subdir in subdirs:
        url = api_url + (subdir.rstrip("/") + "/" if subdir else "")
        try:
            r = requests.get(url, headers=headers, timeout=10)
            r.raise_for_status()
            items = r.json()
        except Exception as e:
            log_fn(f"[{name}] ✗ API ошибка ({url}): {e}")
            continue

        files = [it["name"] for it in items
                 if it.get("type") == "file"
                 and any(it["name"].endswith(ext) for ext in extensions)]

        log_fn(f"[{name}] API: найдено {len(files)} файлов" +
               (f" в {subdir}" if subdir else ""))

        for fname in files:
            file_url = raw_base + (subdir + "/" if subdir else "") + fname
            try:
                resp = requests.get(file_url, headers=headers, timeout=15)
                resp.raise_for_status()
                texts.append(resp.text)
                log_fn(f"[{name}] ✓ {fname} ({len(resp.text)} байт)")
            except Exception as e:
                log_fn(f"[{name}] ✗ {fname}: {e}")

    return texts

def _fetch_direct(source, headers, log_fn, name) -> list[str]:
    texts = []
    for url in source.get("urls", []):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            texts.append(r.text)
            fname = url.split("/")[-1] or url
            log_fn(f"[{name}] ✓ {fname} ({len(r.text)} байт)")
        except Exception as e:
            log_fn(f"[{name}] ✗ {url.split('/')[-1]}: {e}")
    return texts

def _fetch_base64(source, headers, log_fn, name) -> list[str]:
    texts = []
    for url in source.get("urls", []):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            decoded = try_decode_base64(r.text)
            fname = url.split("/")[-1] or url
            if decoded != r.text:
                log_fn(f"[{name}] ✓ {fname} — base64 декодирован ({len(decoded)} байт)")
            else:
                log_fn(f"[{name}] ✓ {fname} — plain текст ({len(decoded)} байт)")
            texts.append(decoded)
        except Exception as e:
            log_fn(f"[{name}] ✗ {url.split('/')[-1]}: {e}")
    return texts

def _fetch_yaml_clash(source, headers, log_fn, name) -> list[str]:
    """Clash YAML: читаем поле proxies и конвертируем в URI."""
    texts = []
    for url in source.get("urls", []):
        try:
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            if HAS_YAML:
                data = yaml.safe_load(r.text)
                proxies = data.get("proxies", [])
                # Простейший конвертер: берём только ss/trojan/vless как URI если есть
                uris = []
                for p in proxies:
                    t = p.get("type", "")
                    if t == "ss":
                        cipher = p.get("cipher", "")
                        pw     = p.get("password", "")
                        server = p.get("server", "")
                        port   = p.get("port", "")
                        auth   = base64.b64encode(f"{cipher}:{pw}".encode()).decode()
                        uris.append(f"ss://{auth}@{server}:{port}")
                    elif t in ("trojan", "vless"):
                        server = p.get("server", "")
                        port   = p.get("port", "")
                        pw     = p.get("password", p.get("uuid", ""))
                        uris.append(f"{t}://{pw}@{server}:{port}")
                texts.append("\n".join(uris))
                log_fn(f"[{name}] ✓ Clash YAML: {len(uris)} прокси")
            else:
                log_fn(f"[{name}] ⚠ pyyaml не установлен, Clash YAML пропущен")
        except Exception as e:
            log_fn(f"[{name}] ✗ {url}: {e}")
    return texts

# ─────────────────────────────────────────────────────────────────────────────
# Извлечение конфигов из текста (без фильтров)
# ─────────────────────────────────────────────────────────────────────────────
def extract_raw_configs(text: str, cfg: dict) -> list[str]:
    """Извлекает строки конфигов из текста. Проверяет только протокол."""
    configs = []
    proto_stats = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        proto = detect_protocol(line)
        if not proto:
            continue

        # Проверяем разрешён ли протокол
        if not is_protocol_allowed(proto, cfg):
            continue

        proto_stats[proto] = proto_stats.get(proto, 0) + 1

        # Проверяем что это вообще похоже на конфиг (хост + порт парсятся)
        h, p = parse_host_port(line)
        if not h or not p:
            continue

        configs.append(line)

    return configs

# ─────────────────────────────────────────────────────────────────────────────
# Применение фильтров (второй этап)
# ─────────────────────────────────────────────────────────────────────────────
def apply_filters(configs: list[str], cfg: dict, log_fn=None) -> list[str]:
    """Применяет все фильтры к списку конфигов. Возвращает отфильтрованный список."""
    f_cfg = cfg.get("filters", {})
    result = configs[:]

    # --- Keyword blacklist ---
    kw_cfg = f_cfg.get("keyword_blacklist", {})
    if kw_cfg.get("enabled", True):
        words = kw_cfg.get("words", [])
        case  = kw_cfg.get("case_sensitive", False)
        before = len(result)
        result = [
            c for c in result
            if not any(
                (w if case else w.lower()) in (c if case else c.lower())
                for w in words
            )
        ]
        removed = before - len(result)
        if log_fn and removed:
            log_fn(f"[Фильтр] Keyword blacklist: удалено {removed} конфигов")

    # --- Протокол (повторная проверка на случай изменения конфига) ---
    before = len(result)
    result = [c for c in result if is_protocol_allowed(detect_protocol(c) or "", cfg)]
    removed = before - len(result)
    if log_fn and removed:
        log_fn(f"[Фильтр] Протоколы: удалено {removed} конфигов")

    # --- Лимит ---
    max_c = f_cfg.get("max_configs", 0)
    if max_c and max_c > 0 and len(result) > max_c:
        result = result[:max_c]
        if log_fn:
            log_fn(f"[Фильтр] Лимит: оставлено {max_c} конфигов")

    return result

def rebuild_filtered(cfg: dict, log_fn=None):
    """Перечитывает raw_alive.txt, применяет фильтры, сохраняет filtered.txt."""
    if not os.path.exists(RAW_ALIVE_FILE):
        if log_fn:
            log_fn("[Фильтр] raw_alive.txt не найден — сначала запустите парсер")
        return 0

    with open(RAW_ALIVE_FILE, "r", encoding="utf-8") as f:
        raw = [l.strip() for l in f if l.strip()]

    if log_fn:
        log_fn(f"[Фильтр] Загружено {len(raw)} конфигов из raw_alive.txt")

    filtered = apply_filters(raw, cfg, log_fn)

    with open(FILTERED_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(filtered))

    save_config_hash()

    if log_fn:
        log_fn(f"[Фильтр] filtered.txt: {len(filtered)} конфигов (было {len(raw)})")

    return len(filtered)

# ─────────────────────────────────────────────────────────────────────────────
# Глобальный инстанс сервера
# ─────────────────────────────────────────────────────────────────────────────
_server_instance = None

# ─────────────────────────────────────────────────────────────────────────────
# TUI — Диалоги
# ─────────────────────────────────────────────────────────────────────────────
class ConfirmModal(ModalScreen):
    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Label(self.message)
            with Horizontal(classes="modal-btns"):
                yield Button("Да", id="yes", variant="error")
                yield Button("Нет", id="no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss(event.button.id == "yes")


# ─────────────────────────────────────────────────────────────────────────────
# TUI — Основное приложение
# ─────────────────────────────────────────────────────────────────────────────
class VPNManagerApp(App):
    TITLE = "VPN Config Manager v2"

    CSS = """
    Screen { background: #0d1117; }

    /* Модальное окно */
    #modal-box {
        align: center middle; padding: 2 3;
        background: #161b22; border: thick $accent;
        width: 55; height: auto; margin: 8 30;
    }
    .modal-btns { height: 3; align: center middle; margin-top: 1; }
    .modal-btns Button { margin: 0 1; }

    /* Настройки */
    .setting-item { height: 3; align: left middle; padding: 0 1; }
    .label-w30 { width: 30; color: #8b949e; }
    .label-w20 { width: 20; color: #8b949e; }

    /* Логи */
    Log { background: #000; border: solid #30363d; height: 1fr; margin: 1; }

    /* Статистика */
    .stat-box {
        background: #161b22; border: solid #30363d;
        height: 5; content-align: center middle;
        margin: 1; width: 1fr;
    }
    .stat-val { color: cyan; text-style: bold; }
    .stat-label { color: #8b949e; }

    /* Прочее */
    Collapsible { background: #161b22; margin: 0 1; border-top: solid #30363d; }
    Input { width: 1fr; }
    TextArea { height: 20; margin: 1; }
    .button-row { height: 3; margin: 1; }
    #srv-status { margin: 1; text-style: bold; }
    .status-off { color: red; }
    .status-on  { color: green; }
    .warn-label { color: yellow; margin: 1; }
    .info-label { color: cyan; margin: 0 1; }
    Select { width: 1fr; }
    """

    BINDINGS = [
        Binding("f1", "show_tab('parser')",   "Парсер"),
        Binding("f2", "show_tab('settings')", "Настройки"),
        Binding("f3", "show_tab('config')",   "Конфиг"),
        Binding("f4", "show_tab('server')",   "Сервер"),
        Binding("f5", "rebuild_filter",        "Обновить фильтр"),
        Binding("q",  "quit",                  "Выход"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="tabs"):

            # ── ПАРСЕР ────────────────────────────────────────────────────────
            with TabPane("🚀 ПАРСЕР", id="parser"):
                with Horizontal():
                    with Vertical(classes="stat-box"):
                        yield Static("0", id="st-sources",  classes="stat-val")
                        yield Label("Источников",            classes="stat-label")
                    with Vertical(classes="stat-box"):
                        yield Static("0", id="st-found",    classes="stat-val")
                        yield Label("Извлечено",             classes="stat-label")
                    with Vertical(classes="stat-box"):
                        yield Static("0", id="st-alive",    classes="stat-val")
                        yield Label("TCP живых",             classes="stat-label")
                    with Vertical(classes="stat-box"):
                        yield Static("0", id="st-filtered", classes="stat-val")
                        yield Label("После фильтров",        classes="stat-label")

                yield ProgressBar(total=100, id="progress", show_eta=False)

                with Horizontal(classes="button-row"):
                    yield Button("▶ ЗАПУСК",       id="btn-run",    variant="success")
                    yield Button("⏹ СТОП",         id="btn-stop",   variant="error",   disabled=True)
                    yield Button("🔄 Фильтр",       id="btn-filter", variant="primary")
                    yield Button("🚪 ВЫХОД",        id="btn-exit",   variant="default")

                yield Static("", id="parser-hint", classes="info-label")
                yield Log(id="log-parser")

            # ── НАСТРОЙКИ ─────────────────────────────────────────────────────
            with TabPane("⚙ НАСТРОЙКИ", id="settings"):
                with ScrollableContainer():
                    with Collapsible(title="🌐 GitHub", collapsed=False):
                        yield from self._field("GitHub Token", "cfg-token")

                    with Collapsible(title="🛡 Протоколы", collapsed=False):
                        with Horizontal(classes="setting-item"):
                            yield Label("Режим", classes="label-w20")
                            yield Select(
                                [("auto — любые ://", "auto"),
                                 ("whitelist — только разрешённые", "whitelist"),
                                 ("blacklist — все кроме запрещённых", "blacklist")],
                                id="cfg-proto-mode", value="whitelist"
                            )
                        yield from self._field("Разрешённые (через запятую)", "cfg-proto-allowed")
                        yield from self._field("Запрещённые (через запятую)",  "cfg-proto-denied")

                    with Collapsible(title="🔍 Фильтры", collapsed=False):
                        with Horizontal(classes="setting-item"):
                            yield Label("Keyword blacklist вкл", classes="label-w30")
                            yield Switch(id="cfg-kw-enabled", value=True)
                        with Horizontal(classes="setting-item"):
                            yield Label("Учитывать регистр", classes="label-w30")
                            yield Switch(id="cfg-kw-case", value=False)
                        yield from self._field("Слова (через запятую)", "cfg-kw-words")
                        yield from self._field("Макс. конфигов (0=всё)", "cfg-max-configs")

                    with Collapsible(title="⚡ TCP-чекер", collapsed=False):
                        with Horizontal(classes="setting-item"):
                            yield Label("Включён", classes="label-w30")
                            yield Switch(id="cfg-check-enabled", value=True)
                        yield from self._field("Таймаут (сек)", "cfg-timeout")
                        yield from self._field("Потоков",        "cfg-threads")

                    with Collapsible(title="🖥 Сервер", collapsed=False):
                        yield from self._field("Хост", "cfg-srv-host")
                        yield from self._field("Порт", "cfg-srv-port")
                        with Horizontal(classes="setting-item"):
                            yield Label("Фильтровать при запросе", classes="label-w30")
                            yield Switch(id="cfg-srv-filter", value=True)
                        with Horizontal(classes="setting-item"):
                            yield Label("Формат ответа", classes="label-w30")
                            yield Select(
                                [("base64 (V2Ray/Clash совместимый)", "base64"),
                                 ("plain text", "plain")],
                                id="cfg-srv-format", value="base64"
                            )

                    with Horizontal(classes="button-row"):
                        yield Button("💾 СОХРАНИТЬ", id="btn-save",  variant="success")
                        yield Button("🔄 СБРОС",     id="btn-reset", variant="primary")

            # ── КОНФИГ (RAW YAML) ─────────────────────────────────────────────
            with TabPane("📝 КОНФИГ", id="config"):
                yield Label(
                    "Прямое редактирование YAML-конфига. "
                    "Здесь можно добавить свои источники. "
                    "Сохраните и нажмите F5 для применения фильтров.",
                    classes="info-label"
                )
                yield TextArea(id="cfg-raw", language="yaml")
                with Horizontal(classes="button-row"):
                    yield Button("💾 СОХРАНИТЬ YAML", id="btn-save-yaml",  variant="success")
                    yield Button("🔄 ПЕРЕЗАГРУЗИТЬ",  id="btn-reload-yaml", variant="primary")
                    yield Button("↩ СБРОС",           id="btn-reset-yaml",  variant="default")

            # ── СЕРВЕР ────────────────────────────────────────────────────────
            with TabPane("🌐 СЕРВЕР", id="server"):
                yield Static("СТАТУС: ВЫКЛЮЧЕН", id="srv-status", classes="status-off")
                yield Static("", id="srv-info", classes="info-label")
                with Horizontal(classes="button-row"):
                    yield Button("▶ ВКЛЮЧИТЬ",  id="btn-srv-start", variant="success")
                    yield Button("⏹ ВЫКЛЮЧИТЬ", id="btn-srv-stop",  variant="error", disabled=True)
                yield Log(id="log-server")

        yield Footer()

    def _field(self, label: str, id: str):
        with Horizontal(classes="setting-item"):
            yield Label(label, classes="label-w30")
            yield Input(id=id)

    # ─────────────────────────────────────────────────────────────────────────
    # Инициализация
    # ─────────────────────────────────────────────────────────────────────────
    def on_mount(self):
        init_system()
        if not HAS_REQUESTS:
            self.notify("⚠ requests не установлен: pip install requests", severity="warning")
        if not HAS_YAML:
            self.notify("⚠ pyyaml не установлен: pip install pyyaml", severity="warning")
        self._load_ui_from_config()
        self._load_raw_yaml()
        self._check_filter_status()

    def _check_filter_status(self):
        """Показывает предупреждение если конфиг изменился с последней фильтрации."""
        if config_changed_since_last_filter() and os.path.exists(RAW_ALIVE_FILE):
            self.query_one("#parser-hint").update(
                "⚠ Конфиг изменился — нажмите F5 или кнопку '🔄 Фильтр' чтобы обновить filtered.txt"
            )

    def _log(self, msg: str, tab: str = "parser"):
        self.query_one(f"#log-{tab}", Log).write_line(
            f"[{time.strftime('%H:%M:%S')}] {msg}"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Загрузка / Сохранение настроек UI
    # ─────────────────────────────────────────────────────────────────────────
    def _load_ui_from_config(self):
        try:
            c = load_config()
            self.query_one("#cfg-token").value   = str(c.get("github", {}).get("token", ""))

            pc = c.get("protocols", {})
            self.query_one("#cfg-proto-mode").value    = pc.get("mode", "whitelist")
            self.query_one("#cfg-proto-allowed").value = ", ".join(pc.get("allowed", []))
            self.query_one("#cfg-proto-denied").value  = ", ".join(pc.get("denied", []))

            kw = c.get("filters", {}).get("keyword_blacklist", {})
            self.query_one("#cfg-kw-enabled").value = kw.get("enabled", True)
            self.query_one("#cfg-kw-case").value    = kw.get("case_sensitive", False)
            words = kw.get("words", [])
            self.query_one("#cfg-kw-words").value   = ", ".join(str(w) for w in words)
            self.query_one("#cfg-max-configs").value = str(c.get("filters", {}).get("max_configs", 0))

            chk = c.get("checker", {})
            self.query_one("#cfg-check-enabled").value = chk.get("enabled", True)
            self.query_one("#cfg-timeout").value       = str(chk.get("timeout", 1.5))
            self.query_one("#cfg-threads").value       = str(chk.get("max_threads", 50))

            srv = c.get("server", {})
            self.query_one("#cfg-srv-host").value   = str(srv.get("host", "0.0.0.0"))
            self.query_one("#cfg-srv-port").value   = str(srv.get("port", 8000))
            self.query_one("#cfg-srv-filter").value = srv.get("apply_filters_on_request", True)
            self.query_one("#cfg-srv-format").value = srv.get("response_format", "base64")

            # Статистика
            n_src = len([s for s in c.get("sources", []) if s.get("enabled", True)])
            self.query_one("#st-sources").update(str(n_src))

        except Exception as e:
            self.notify(f"Ошибка загрузки настроек: {e}", severity="error")

    def _load_raw_yaml(self):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                self.query_one("#cfg-raw").load_text(f.read())
        except Exception as e:
            self.notify(f"Ошибка чтения YAML: {e}", severity="error")

    @on(Button.Pressed, "#btn-save")
    def save_settings_ui(self):
        """Сохраняет настройки из формы в YAML-конфиг (НЕ перезаписывает sources!)."""
        try:
            c = load_config()

            c.setdefault("github", {})["token"] = self.query_one("#cfg-token").value

            c.setdefault("protocols", {})["mode"]    = str(self.query_one("#cfg-proto-mode").value)
            c["protocols"]["allowed"] = [x.strip() for x in self.query_one("#cfg-proto-allowed").value.split(",") if x.strip()]
            c["protocols"]["denied"]  = [x.strip() for x in self.query_one("#cfg-proto-denied").value.split(",")  if x.strip()]

            kw = c.setdefault("filters", {}).setdefault("keyword_blacklist", {})
            kw["enabled"]        = self.query_one("#cfg-kw-enabled").value
            kw["case_sensitive"] = self.query_one("#cfg-kw-case").value
            kw["words"]          = [x.strip() for x in self.query_one("#cfg-kw-words").value.split(",") if x.strip()]
            c["filters"]["max_configs"] = int(self.query_one("#cfg-max-configs").value or 0)

            chk = c.setdefault("checker", {})
            chk["enabled"]     = self.query_one("#cfg-check-enabled").value
            chk["timeout"]     = float(self.query_one("#cfg-timeout").value or 1.5)
            chk["max_threads"] = int(self.query_one("#cfg-threads").value or 50)

            srv = c.setdefault("server", {})
            srv["host"]                    = self.query_one("#cfg-srv-host").value
            srv["port"]                    = int(self.query_one("#cfg-srv-port").value or 8000)
            srv["apply_filters_on_request"]= self.query_one("#cfg-srv-filter").value
            srv["response_format"]         = str(self.query_one("#cfg-srv-format").value)

            if HAS_YAML:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    yaml.dump(c, f, allow_unicode=True, sort_keys=False, indent=2)
            else:
                self.notify("pyyaml не установлен — используйте вкладку КОНФИГ", severity="warning")
                return

            self._load_raw_yaml()
            self.notify("Настройки сохранены ✅")
            self._check_filter_status()
        except Exception as e:
            self.notify(f"Ошибка сохранения: {e}", severity="error")

    @on(Button.Pressed, "#btn-reset")
    def reset_settings(self):
        def do_reset(confirmed):
            if confirmed:
                shutil.copy(CONFIG_DEFAULT, CONFIG_FILE)
                self._load_ui_from_config()
                self._load_raw_yaml()
                self.notify("Настройки сброшены к дефолту")
        self.push_screen(ConfirmModal("Сбросить настройки к значениям по умолчанию?"), do_reset)

    @on(Button.Pressed, "#btn-save-yaml")
    def save_raw_yaml(self):
        try:
            raw = self.query_one("#cfg-raw").text
            # Валидация
            if HAS_YAML:
                yaml.safe_load(raw)  # Проверка синтаксиса
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(raw)
            self._load_ui_from_config()
            self.notify("YAML сохранён ✅")
            self._check_filter_status()
        except Exception as e:
            self.notify(f"Ошибка YAML: {e}", severity="error")

    @on(Button.Pressed, "#btn-reload-yaml")
    def reload_raw_yaml(self):
        self._load_raw_yaml()
        self._load_ui_from_config()
        self.notify("YAML перезагружен")

    @on(Button.Pressed, "#btn-reset-yaml")
    def reset_raw_yaml(self):
        def do_reset(confirmed):
            if confirmed:
                shutil.copy(CONFIG_DEFAULT, CONFIG_FILE)
                self._load_raw_yaml()
                self._load_ui_from_config()
                self.notify("YAML сброшен к дефолту")
        self.push_screen(ConfirmModal("Сбросить YAML к значениям по умолчанию?"), do_reset)

    # ─────────────────────────────────────────────────────────────────────────
    # Парсер
    # ─────────────────────────────────────────────────────────────────────────
    @on(Button.Pressed, "#btn-run")
    def start_parsing(self):
        if not HAS_REQUESTS:
            self.notify("requests не установлен!", severity="error")
            return
        self.query_one("#btn-run").disabled  = True
        self.query_one("#btn-stop").disabled = False
        self.query_one("#progress").progress = 0
        cfg = load_config()
        self._worker = self.parser_task(cfg)

    @on(Button.Pressed, "#btn-stop")
    def stop_parsing(self):
        if hasattr(self, "_worker"):
            self._worker.cancel()

    @on(Button.Pressed, "#btn-exit")
    def quit_app(self):
        self.exit()

    @on(Button.Pressed, "#btn-filter")
    def manual_rebuild_filter(self):
        self._do_rebuild_filter()

    def action_rebuild_filter(self):
        self._do_rebuild_filter()

    def _do_rebuild_filter(self):
        cfg = load_config()
        n = rebuild_filtered(cfg, lambda m: self.call_from_thread(self._log, m) if False else self._log(m))
        self.query_one("#st-filtered").update(str(n))
        self.query_one("#parser-hint").update(f"✓ filtered.txt обновлён: {n} конфигов")

    @work(exclusive=True, thread=True)
    def parser_task(self, cfg: dict):
        try:
            token = cfg.get("github", {}).get("token", "")
            headers = {"Authorization": f"token {token}"} if token else {}

            sources = [s for s in cfg.get("sources", []) if s.get("enabled", True)]
            self.call_from_thread(self._log, f"━━ Запуск парсера: {len(sources)} источников ━━")

            if not sources:
                self.call_from_thread(self._log, "✗ Нет активных источников в конфиге")
                return

            self.call_from_thread(self.query_one("#st-sources").update, str(len(sources)))

            all_raw = []
            for i, source in enumerate(sources):
                name = source.get("name", f"source_{i}")
                self.call_from_thread(self._log, f"── [{i+1}/{len(sources)}] {name}")

                texts = fetch_source(source, headers,
                                     lambda m: self.call_from_thread(self._log, m))
                source_configs = []
                for text in texts:
                    source_configs.extend(extract_raw_configs(text, cfg))

                self.call_from_thread(self._log,
                    f"[{name}] Итого: {len(source_configs)} конфигов")
                all_raw.extend(source_configs)

                progress = int((i + 1) / len(sources) * 40)
                self.call_from_thread(self.query_one("#progress").update, progress=progress)

            # Дедупликация
            before_dedup = len(all_raw)
            all_raw = list(dict.fromkeys(all_raw))
            self.call_from_thread(self._log,
                f"━━ Дедупликация: {before_dedup} → {len(all_raw)} уникальных")
            self.call_from_thread(self.query_one("#st-found").update, str(len(all_raw)))

            # Статистика протоколов
            proto_stat = {}
            for c in all_raw:
                p = detect_protocol(c) or "unknown"
                proto_stat[p] = proto_stat.get(p, 0) + 1
            for p, n in sorted(proto_stat.items(), key=lambda x: -x[1]):
                is_known = p in KNOWN_PROTOCOLS
                flag = "" if is_known else " ⭐ НОВЫЙ"
                self.call_from_thread(self._log, f"  {p}: {n} конфигов{flag}")

            # TCP-проверка
            chk_cfg = cfg.get("checker", {})
            alive = []
            if chk_cfg.get("enabled", True) and all_raw:
                timeout = chk_cfg.get("timeout", 1.5)
                threads = chk_cfg.get("max_threads", 50)
                self.call_from_thread(self._log,
                    f"━━ TCP-проверка: {len(all_raw)} конфигов "
                    f"(timeout={timeout}s, threads={threads}) ━━")

                with ThreadPoolExecutor(max_workers=threads) as pool:
                    futures = {pool.submit(check_tcp, c, timeout): c for c in all_raw}
                    for i, f in enumerate(as_completed(futures)):
                        res = f.result()
                        if res:
                            alive.append(res)
                        if i % 50 == 0:
                            progress = 40 + int((i + 1) / len(all_raw) * 50)
                            self.call_from_thread(self.query_one("#progress").update, progress=progress)
                        self.call_from_thread(self.query_one("#st-alive").update, str(len(alive)))

                self.call_from_thread(self._log,
                    f"━━ TCP: живых {len(alive)} из {len(all_raw)} ━━")
            else:
                alive = all_raw
                if chk_cfg.get("save_unchecked", True):
                    self.call_from_thread(self._log, "TCP-проверка отключена, сохраняем всё")

            # Сохраняем raw_alive.txt
            with open(RAW_ALIVE_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(alive))
            self.call_from_thread(self._log,
                f"✓ raw_alive.txt сохранён: {len(alive)} конфигов")

            # Применяем фильтры → filtered.txt
            self.call_from_thread(self._log, "━━ Применяем фильтры ━━")
            n_filtered = rebuild_filtered(cfg, lambda m: self.call_from_thread(self._log, m))
            self.call_from_thread(self.query_one("#st-filtered").update, str(n_filtered))

            self.call_from_thread(self._log, f"━━ ГОТОВО ━━")
            self.call_from_thread(self._log,
                f"  raw_alive.txt  → {len(alive)} (TCP живые)")
            self.call_from_thread(self._log,
                f"  filtered.txt   → {n_filtered} (после всех фильтров)")

        except Exception as e:
            self.call_from_thread(self._log, f"✗ Критическая ошибка: {e}")
        finally:
            self.call_from_thread(self._parsing_done)

    def _parsing_done(self):
        self.query_one("#btn-run").disabled  = False
        self.query_one("#btn-stop").disabled = True
        self.query_one("#progress").update(progress=100)
        self.query_one("#parser-hint").update("✓ Парсинг завершён")

    # ─────────────────────────────────────────────────────────────────────────
    # Сервер
    # ─────────────────────────────────────────────────────────────────────────
    @on(Button.Pressed, "#btn-srv-start")
    def server_start(self):
        global _server_instance
        try:
            cfg   = load_config()
            s_cfg = cfg.get("server", {})
            host  = s_cfg.get("host", "0.0.0.0")
            port  = s_cfg.get("port", 8000)
            fmt   = s_cfg.get("response_format", "base64")
            apply_filters_flag = s_cfg.get("apply_filters_on_request", True)

            app_ref = self  # ссылка для использования внутри класса

            class SubHandler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass  # Отключаем стандартный лог

                def do_GET(self):
                    path = s_cfg.get("path", "/sub")
                    if self.path.split("?")[0] != path:
                        self.send_error(404)
                        return

                    try:
                        # Определяем что отдавать
                        if apply_filters_flag:
                            # Перестраиваем filtered если конфиг изменился
                            if config_changed_since_last_filter():
                                c = load_config()
                                rebuild_filtered(c)

                            src_file = FILTERED_FILE
                        else:
                            src_file = RAW_ALIVE_FILE

                        if not os.path.exists(src_file):
                            self.send_error(503, "No configs available")
                            return

                        with open(src_file, "r", encoding="utf-8") as f:
                            data = f.read().strip()

                        if fmt == "base64":
                            body = base64.b64encode(data.encode("utf-8"))
                            ct   = "text/plain; charset=utf-8"
                        else:
                            body = data.encode("utf-8")
                            ct   = "text/plain; charset=utf-8"

                        n_configs = len([l for l in data.splitlines() if l.strip()])
                        client_ip = self.client_address[0]

                        self.send_response(200)
                        self.send_header("Content-Type", ct)
                        self.send_header("X-Config-Count", str(n_configs))
                        self.end_headers()
                        self.wfile.write(body)

                        app_ref.call_from_thread(
                            app_ref._log,
                            f"GET {self.path} ← {client_ip} → {n_configs} конфигов",
                            "server"
                        )
                    except Exception as e:
                        self.send_error(500, str(e))
                        app_ref.call_from_thread(
                            app_ref._log, f"Ошибка запроса: {e}", "server"
                        )

            _server_instance = HTTPServer((host, port), SubHandler)
            t = threading.Thread(target=_server_instance.serve_forever, daemon=True)
            t.start()

            srv_url = f"http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}{s_cfg.get('path', '/sub')}"

            st = self.query_one("#srv-status")
            st.update(f"СТАТУС: ЗАПУЩЕН")
            st.remove_class("status-off")
            st.add_class("status-on")

            self.query_one("#srv-info").update(
                f"Endpoint: {srv_url}  |  Формат: {fmt}  |  Фильтры: {'вкл' if apply_filters_flag else 'выкл'}"
            )

            self.query_one("#btn-srv-start").disabled = True
            self.query_one("#btn-srv-stop").disabled  = False

            self._log(f"✓ Сервер запущен: {srv_url}", "server")
            self._log(f"  Формат: {fmt}, фильтры: {apply_filters_flag}", "server")

        except Exception as e:
            self._log(f"✗ Ошибка запуска сервера: {e}", "server")

    @on(Button.Pressed, "#btn-srv-stop")
    def server_stop(self):
        global _server_instance
        if _server_instance:
            _server_instance.shutdown()
            _server_instance = None

        st = self.query_one("#srv-status")
        st.update("СТАТУС: ВЫКЛЮЧЕН")
        st.remove_class("status-on")
        st.add_class("status-off")
        self.query_one("#srv-info").update("")
        self.query_one("#btn-srv-start").disabled = False
        self.query_one("#btn-srv-stop").disabled  = True
        self._log("Сервер остановлен", "server")


if __name__ == "__main__":
    VPNManagerApp().run()