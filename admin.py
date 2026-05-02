"""
admin.py — Painel de Administração Remota
Sistema de administração remota para uso exclusivo em ambiente de laboratório
controlado, desenvolvido para fins educacionais e de pesquisa em segurança da
informação. Todos os testes são realizados em ambiente virtualizado com máquinas
que pertencem ao desenvolvedor.

Autor: Projeto Educacional - CEH/OSCP/CompTIA Security+
Uso: python admin.py
"""

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import asyncio
import websockets
import base64
import datetime
import json
import logging
import os
import platform
import queue
import socket
import struct
import sys
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import (
    QAbstractTableModel,
    QByteArray,
    QModelIndex,
    QMutex,
    QObject,
    QRect,
    QRunnable,
    QSize,
    Qt,
    QThread,
    QThreadPool,
    QTimer,
    Signal,
    Slot,
    QSortFilterProxyModel,
    QPoint,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QFontDatabase,
    QIcon,
    QKeySequence,
    QPainter,
    QPen,
    QPixmap,
    QBrush,
    QPalette,
    QLinearGradient,
    QCursor,
    QClipboard,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTabBar,
    QTabWidget,
    QTableView,
    QTextEdit,
    QToolBar,
    QToolButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
    QSpinBox,
    QDoubleSpinBox,
    QListWidget,
    QListWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QInputDialog,
    QToolTip,
    QStyleFactory,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES GLOBAIS
# ─────────────────────────────────────────────────────────────────────────────
APP_VERSION: str = "1.0.0"
APP_NAME: str = "RemoteAdmin Pro"

# Rede
LISTEN_HOST: str = "0.0.0.0"
LISTEN_PORT: int = 9999
AUTH_TOKEN: str = "auracorelabv33333"
HEARTBEAT_INTERVAL: float = 5.0
RECV_BUFFER: int = 65536
MAX_PAYLOAD_SIZE: int = 128 * 1024 * 1024  # 128 MB

# Header de protocolo: msg_type (4B) + payload_hi (2B) + payload_lo (4B) = 10B
HEADER_FORMAT: str = ">IHI"
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)  # 10 bytes

# Histórico de dados
HISTORY_LEN: int = 60  # 60 pontos para gráficos

# Paleta de Cores (estilo AnyDesk/Fluent UI)
class Colors:
    BG_BASE       = "#F5F6FA"
    BG_WHITE      = "#FFFFFF"
    SIDEBAR_BG    = "#1A2B4A"
    SIDEBAR_TEXT  = "#FFFFFF"
    SIDEBAR_HOVER = "#243B5E"
    SIDEBAR_ACTIVE= "#2D4A73"
    TOPBAR_BG     = "#FFFFFF"
    ACCENT        = "#0078D4"
    ACCENT_HOVER  = "#006BBD"
    ACCENT_PRESSED= "#005EA2"
    SUCCESS       = "#107C10"
    ERROR         = "#D13438"
    WARNING       = "#FFB900"
    TEXT_PRIMARY  = "#1A1A1A"
    TEXT_SECONDARY= "#605E5C"
    TEXT_MUTED    = "#A19F9D"
    BORDER        = "#E1E1E1"
    TABLE_ALT     = "#FAFAFA"
    CARD_SHADOW   = "rgba(0,0,0,0.08)"
    BADGE_ONLINE_BG  = "#DFF6DD"
    BADGE_ONLINE_FG  = "#107C10"
    BADGE_OFFLINE_BG = "#FDE7E9"
    BADGE_OFFLINE_FG = "#D13438"
    BADGE_WARN_BG    = "#FFF4CE"
    BADGE_WARN_FG    = "#7D5700"

# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOLO — TIPOS DE MENSAGEM
# ─────────────────────────────────────────────────────────────────────────────
class MsgType(IntEnum):
    # Autenticação
    AUTH_HELLO   = 0x0001
    AUTH_OK      = 0x0002
    AUTH_ERROR   = 0x0003

    # Heartbeat
    HEARTBEAT    = 0x0010
    HEARTBEAT_ACK= 0x0011

    # Sistema
    SYS_INFO_REQ = 0x0020
    SYS_INFO_RES = 0x0021
    METRICS_REQ  = 0x0022
    METRICS_RES  = 0x0023

    # Processos
    PROC_LIST_REQ= 0x0030
    PROC_LIST_RES= 0x0031
    PROC_KILL_REQ= 0x0032
    PROC_KILL_RES= 0x0033
    PROC_SUSPEND_REQ = 0x0034
    PROC_SUSPEND_RES = 0x0035
    PROC_RESUME_REQ  = 0x0036
    PROC_RESUME_RES  = 0x0037

    # Arquivos
    FILE_LIST_REQ   = 0x0040
    FILE_LIST_RES   = 0x0041
    FILE_DOWNLOAD_REQ= 0x0042
    FILE_DOWNLOAD_RES= 0x0043
    FILE_UPLOAD_REQ  = 0x0044
    FILE_UPLOAD_RES  = 0x0045
    FILE_DELETE_REQ  = 0x0046
    FILE_DELETE_RES  = 0x0047
    FILE_RENAME_REQ  = 0x0048
    FILE_RENAME_RES  = 0x0049
    FILE_MKDIR_REQ   = 0x004A
    FILE_MKDIR_RES   = 0x004B
    FILE_READ_REQ    = 0x004C
    FILE_READ_RES    = 0x004D
    FILE_SEARCH_REQ  = 0x004E
    FILE_SEARCH_RES  = 0x004F
    FILE_MOVE_REQ    = 0x0050
    FILE_MOVE_RES    = 0x0051

    # Terminal
    TERM_CMD_REQ = 0x0060
    TERM_CMD_RES = 0x0061
    TERM_STREAM  = 0x0062

    # Screenshot
    SCREEN_REQ   = 0x0070
    SCREEN_RES   = 0x0071

    # Lock de tela
    LOCK_REQ     = 0x0080
    LOCK_RES     = 0x0081
    UNLOCK_REQ   = 0x0082
    UNLOCK_RES   = 0x0083

    # Rede
    NET_INFO_REQ = 0x0090
    NET_INFO_RES = 0x0091
    NET_PING_REQ = 0x0092
    NET_PING_RES = 0x0093

    # Logs
    LOG_REQ      = 0x00A0
    LOG_RES      = 0x00A1
    LOG_STREAM   = 0x00A2

    # Ações rápidas
    ACTION_RESTART_AGENT  = 0x00B0
    ACTION_STOP_AGENT     = 0x00B1
    ACTION_CLIPBOARD_GET  = 0x00B2
    ACTION_CLIPBOARD_RES  = 0x00B3
    ACTION_CLIPBOARD_SET  = 0x00B4
    ACTION_CLIPBOARD_SET_RES = 0x00B5
    ACTION_POPUP_MSG      = 0x00B6
    ACTION_POPUP_RES      = 0x00B7
    ACTION_OPEN_URL       = 0x00B8
    ACTION_OPEN_URL_RES   = 0x00B9
    ACTION_SHUTDOWN       = 0x00BA
    ACTION_SHUTDOWN_RES   = 0x00BB
    ACTION_REBOOT         = 0x00BC
    ACTION_REBOOT_RES     = 0x00BD

    # Erros genéricos
    GENERIC_ERROR= 0xFFFF


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configura o sistema de logging com arquivo e console."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"admin_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    logger = logging.getLogger("RemoteAdmin")
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


log = setup_logging()


# ─────────────────────────────────────────────────────────────────────────────
# CODEC DE PROTOCOLO
# ─────────────────────────────────────────────────────────────────────────────
def encode_message(msg_type: MsgType, payload: bytes = b"") -> bytes:
    """
    Codifica uma mensagem no formato de protocolo binário.
    Header: >IHI = msg_type(4B) + payload_len_hi(2B) + payload_len_lo(4B)
    Total header = 10 bytes.
    """
    length = len(payload)
    if length > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload muito grande: {length} bytes (max {MAX_PAYLOAD_SIZE})")
    payload_hi = (length >> 32) & 0xFFFF
    payload_lo = length & 0xFFFFFFFF
    header = struct.pack(HEADER_FORMAT, int(msg_type), payload_hi, payload_lo)
    return header + payload


def decode_header(data: bytes) -> Tuple[int, int]:
    """
    Decodifica o header de 10 bytes.
    Retorna (msg_type, payload_length).
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Header incompleto: {len(data)} bytes")
    msg_type, payload_hi, payload_lo = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    payload_len = (payload_hi << 32) | payload_lo
    if payload_len > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload declarado muito grande: {payload_len}")
    return msg_type, payload_len


def recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Recebe exatamente n bytes do socket, bloqueando até completar."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(min(RECV_BUFFER, n - len(buf)))
        except OSError as e:
            raise ConnectionError(f"Falha ao receber dados: {e}") from e
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo peer")
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock: socket.socket) -> Tuple[int, bytes]:
    """
    Recebe uma mensagem completa do socket.
    Retorna (msg_type, payload).
    """
    header_data = recv_exactly(sock, HEADER_SIZE)
    msg_type, payload_len = decode_header(header_data)
    payload = b""
    if payload_len > 0:
        payload = recv_exactly(sock, payload_len)
    return msg_type, payload


def encode_json_payload(data: dict) -> bytes:
    """Serializa dict para JSON e codifica em UTF-8."""
    return json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")


def decode_json_payload(payload: bytes) -> dict:
    """Decodifica payload JSON."""
    return json.loads(payload.decode("utf-8"))


def xor_encrypt(data: bytes, key: str) -> bytes:
    """XOR simples para dados sensíveis (senhas de lock)."""
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def encrypt_password(password: str) -> str:
    """Criptografa senha com XOR + base64."""
    encrypted = xor_encrypt(password.encode("utf-8"), AUTH_TOKEN[:16])
    return base64.b64encode(encrypted).decode("ascii")


# ─────────────────────────────────────────────────────────────────────────────
# DATACLASSES DE ESTADO
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ClientInfo:
    """Informações de um client conectado."""
    client_id: str
    sock: socket.socket
    addr: Tuple[str, int]
    connected_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    hostname: str = "desconhecido"
    os_info: str = ""
    ip: str = ""
    ping_ms: float = -1.0
    last_seen: datetime.datetime = field(default_factory=datetime.datetime.now)
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    send_queue: queue.Queue = field(default_factory=queue.Queue)
    is_alive: bool = True
    cpu_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))
    ram_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))
    ping_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))
    bytes_sent: int = 0
    bytes_recv: int = 0

    def __post_init__(self):
        self.ram_history = deque(maxlen=HISTORY_LEN)
        self.ip = self.addr[0]

    @property
    def display_name(self) -> str:
        if self.hostname and self.hostname != "desconhecido":
            return f"{self.hostname} ({self.ip})"
        return self.ip

    @property
    def ping_str(self) -> str:
        if self.ping_ms < 0:
            return "N/A"
        return f"{self.ping_ms:.1f} ms"


@dataclass
class PendingRequest:
    """Requisição pendente aguardando resposta do client."""
    request_id: str
    msg_type: MsgType
    callback: Optional[Callable]
    created_at: float = field(default_factory=time.time)
    timeout: float = 30.0


# ─────────────────────────────────────────────────────────────────────────────
# WORKER DE REDE — THREAD POR CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class ClientWorker(QObject):
    """
    Worker que gerencia a comunicação com um único client.
    Roda em thread separada. Usa Qt Signals para comunicação thread-safe com a UI.
    """
    # Signals emitidos para a UI (thread-safe)
    sig_disconnected      = Signal(str)                  # client_id
    sig_auth_ok           = Signal(str, dict)            # client_id, sys_info
    sig_auth_error        = Signal(str, str)             # client_id, motivo
    sig_sys_info          = Signal(str, dict)            # client_id, info
    sig_metrics           = Signal(str, dict)            # client_id, metrics
    sig_proc_list         = Signal(str, list)            # client_id, processos
    sig_proc_result       = Signal(str, str, bool, str)  # client_id, ação, ok, msg
    sig_file_list         = Signal(str, str, list)       # client_id, path, entries
    sig_file_download     = Signal(str, str, bytes)      # client_id, filename, data
    sig_file_upload_res   = Signal(str, bool, str)       # client_id, ok, msg
    sig_file_delete_res   = Signal(str, bool, str)
    sig_file_rename_res   = Signal(str, bool, str)
    sig_file_mkdir_res    = Signal(str, bool, str)
    sig_file_read_res     = Signal(str, str, str)        # client_id, filename, content
    sig_file_search_res   = Signal(str, list)            # client_id, results
    sig_file_move_res     = Signal(str, bool, str)
    sig_term_output       = Signal(str, str, str)        # client_id, stdout, stderr
    sig_term_stream       = Signal(str, str)             # client_id, chunk
    sig_screen_res        = Signal(str, bytes)           # client_id, jpeg_data
    sig_lock_res          = Signal(str, bool, str)
    sig_unlock_res        = Signal(str, bool, str)
    sig_net_info          = Signal(str, dict)
    sig_net_ping_res      = Signal(str, float)
    sig_log_res           = Signal(str, list)
    sig_log_stream        = Signal(str, str, str)        # client_id, level, msg
    sig_action_res        = Signal(str, str, bool, str)  # client_id, ação, ok, msg
    sig_clipboard_res     = Signal(str, str)             # client_id, conteúdo
    sig_heartbeat         = Signal(str, float)           # client_id, ping_ms
    sig_error             = Signal(str, str)             # client_id, msg_erro

    def __init__(self, client_info: ClientInfo, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.ci = client_info
        self._running = True
        self._pending: Dict[str, PendingRequest] = {}
        self._pending_lock = threading.Lock()
        self._req_counter = 0
        self._hb_sent_at: float = 0.0

    def _next_req_id(self) -> str:
        self._req_counter += 1
        return f"{self.ci.client_id}_{self._req_counter}"

    # ── ENVIO ──────────────────────────────────────────────────────────────
    def send(self, msg_type: MsgType, payload: bytes = b"") -> bool:
        """Envia mensagem para o client de forma thread-safe."""
        if not self.ci.is_alive:
            return False
        try:
            data = encode_message(msg_type, payload)
            with self.ci.send_lock:
                total_sent = 0
                while total_sent < len(data):
                    sent = self.ci.sock.send(data[total_sent:])
                    if sent == 0:
                        raise ConnectionError("Socket fechado")
                    total_sent += sent
            self.ci.bytes_sent += len(data)
            return True
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro ao enviar {msg_type.name}: {e}")
            self._disconnect(str(e))
            return False

    def send_json(self, msg_type: MsgType, data: dict) -> bool:
        return self.send(msg_type, encode_json_payload(data))

    # ── LOOP PRINCIPAL ─────────────────────────────────────────────────────
    @Slot()
    def run(self) -> None:
        """Loop principal de recebimento de mensagens."""
        log.info(f"[{self.ci.client_id}] Worker iniciado para {self.ci.addr}")
        try:
            self._do_auth()
            if not self.ci.is_alive:
                return
            self._recv_loop()
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro fatal no worker: {e}\n{traceback.format_exc()}")
            self._disconnect(str(e))

    def _do_auth(self) -> None:
        """Realiza handshake de autenticação."""
        try:
            self.ci.sock.settimeout(15.0)
            msg_type, payload = recv_message(self.ci.sock)
            if msg_type != MsgType.AUTH_HELLO:
                self.send_json(MsgType.AUTH_ERROR, {"motivo": "Esperando AUTH_HELLO"})
                self._disconnect("Auth: tipo errado")
                return
            try:
                data = decode_json_payload(payload)
            except Exception:
                self.send_json(MsgType.AUTH_ERROR, {"motivo": "Payload inválido"})
                self._disconnect("Auth: payload inválido")
                return
            token = data.get("token", "")
            if token != AUTH_TOKEN:
                self.send_json(MsgType.AUTH_ERROR, {"motivo": "Token inválido"})
                self._disconnect("Auth: token inválido")
                self.sig_auth_error.emit(self.ci.client_id, "Token inválido")
                return
            # Token OK — enviar AUTH_OK com info do servidor
            server_info = {
                "status": "ok",
                "server_version": APP_VERSION,
                "timestamp": time.time(),
            }
            self.send_json(MsgType.AUTH_OK, server_info)
            # Receber info do sistema do client
            sys_info = data.get("sys_info", {})
            self.ci.hostname = sys_info.get("hostname", self.ci.ip)
            self.ci.os_info  = sys_info.get("os", "")
            log.info(f"[{self.ci.client_id}] Auth OK — {self.ci.hostname} ({self.ci.os_info})")
            self.sig_auth_ok.emit(self.ci.client_id, sys_info)
            self.ci.sock.settimeout(None)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro na autenticação: {e}")
            self._disconnect(f"Auth error: {e}")

    def _recv_loop(self) -> None:
        """Loop de recebimento de mensagens após autenticação."""
        self.ci.sock.settimeout(HEARTBEAT_INTERVAL * 3)
        while self._running and self.ci.is_alive:
            try:
                msg_type_int, payload = recv_message(self.ci.sock)
                self.ci.last_seen = datetime.datetime.now()
                self.ci.bytes_recv += HEADER_SIZE + len(payload)
                try:
                    msg_type = MsgType(msg_type_int)
                except ValueError:
                    log.warning(f"[{self.ci.client_id}] Tipo desconhecido: 0x{msg_type_int:04X}")
                    continue
                self._dispatch(msg_type, payload)
            except socket.timeout:
                log.warning(f"[{self.ci.client_id}] Timeout — sem dados por {HEARTBEAT_INTERVAL*3:.0f}s")
                self._disconnect("Timeout")
                break
            except ConnectionError as e:
                log.info(f"[{self.ci.client_id}] Conexão encerrada: {e}")
                self._disconnect(str(e))
                break
            except Exception as e:
                log.error(f"[{self.ci.client_id}] Erro no loop de recv: {e}\n{traceback.format_exc()}")
                self._disconnect(str(e))
                break

    def _dispatch(self, msg_type: MsgType, payload: bytes) -> None:
        """Despacha mensagem recebida para o handler correto."""
        try:
            handlers = {
                MsgType.HEARTBEAT_ACK:  self._handle_heartbeat_ack,
                MsgType.SYS_INFO_RES:   self._handle_sys_info,
                MsgType.METRICS_RES:    self._handle_metrics,
                MsgType.PROC_LIST_RES:  self._handle_proc_list,
                MsgType.PROC_KILL_RES:  self._handle_proc_kill_res,
                MsgType.PROC_SUSPEND_RES: self._handle_proc_suspend_res,
                MsgType.PROC_RESUME_RES:  self._handle_proc_resume_res,
                MsgType.FILE_LIST_RES:  self._handle_file_list,
                MsgType.FILE_DOWNLOAD_RES: self._handle_file_download,
                MsgType.FILE_UPLOAD_RES: self._handle_file_upload_res,
                MsgType.FILE_DELETE_RES: self._handle_file_delete_res,
                MsgType.FILE_RENAME_RES: self._handle_file_rename_res,
                MsgType.FILE_MKDIR_RES:  self._handle_file_mkdir_res,
                MsgType.FILE_READ_RES:   self._handle_file_read_res,
                MsgType.FILE_SEARCH_RES: self._handle_file_search_res,
                MsgType.FILE_MOVE_RES:   self._handle_file_move_res,
                MsgType.TERM_CMD_RES:    self._handle_term_cmd_res,
                MsgType.TERM_STREAM:     self._handle_term_stream,
                MsgType.SCREEN_RES:      self._handle_screen_res,
                MsgType.LOCK_RES:        self._handle_lock_res,
                MsgType.UNLOCK_RES:      self._handle_unlock_res,
                MsgType.NET_INFO_RES:    self._handle_net_info,
                MsgType.NET_PING_RES:    self._handle_net_ping_res,
                MsgType.LOG_RES:         self._handle_log_res,
                MsgType.LOG_STREAM:      self._handle_log_stream,
                MsgType.ACTION_CLIPBOARD_RES:     self._handle_clipboard_res,
                MsgType.ACTION_CLIPBOARD_SET_RES: self._handle_action_res_generic,
                MsgType.ACTION_POPUP_RES:    self._handle_action_res_generic,
                MsgType.ACTION_OPEN_URL_RES: self._handle_action_res_generic,
                MsgType.ACTION_SHUTDOWN_RES: self._handle_action_res_generic,
                MsgType.ACTION_REBOOT_RES:   self._handle_action_res_generic,
                MsgType.GENERIC_ERROR:   self._handle_generic_error,
            }
            handler = handlers.get(msg_type)
            if handler:
                handler(payload)
            else:
                log.debug(f"[{self.ci.client_id}] Msg sem handler: {msg_type.name}")
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro no dispatch de {msg_type.name}: {e}\n{traceback.format_exc()}")

    # ── HANDLERS DE RESPOSTA ───────────────────────────────────────────────
    def _handle_heartbeat_ack(self, payload: bytes) -> None:
        rtt = (time.time() - self._hb_sent_at) * 1000
        self.ci.ping_ms = rtt
        self.ci.ping_history.append(rtt)
        self.sig_heartbeat.emit(self.ci.client_id, rtt)

    def _handle_sys_info(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.ci.hostname = data.get("hostname", self.ci.hostname)
            self.sig_sys_info.emit(self.ci.client_id, data)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro ao processar SYS_INFO: {e}")

    def _handle_metrics(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            cpu = data.get("cpu", 0.0)
            ram = data.get("ram_percent", 0.0)
            self.ci.cpu_history.append(cpu)
            self.ci.ram_history.append(ram)
            self.sig_metrics.emit(self.ci.client_id, data)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro ao processar METRICS: {e}")

    def _handle_proc_list(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            procs = data.get("processes", [])
            self.sig_proc_list.emit(self.ci.client_id, procs)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro ao processar PROC_LIST: {e}")

    def _handle_proc_kill_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            ok = data.get("ok", False)
            msg = data.get("msg", "")
            self.sig_proc_result.emit(self.ci.client_id, "kill", ok, msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro proc_kill_res: {e}")

    def _handle_proc_suspend_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            ok = data.get("ok", False)
            msg = data.get("msg", "")
            self.sig_proc_result.emit(self.ci.client_id, "suspend", ok, msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro proc_suspend_res: {e}")

    def _handle_proc_resume_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            ok = data.get("ok", False)
            msg = data.get("msg", "")
            self.sig_proc_result.emit(self.ci.client_id, "resume", ok, msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro proc_resume_res: {e}")

    def _handle_file_list(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            path = data.get("path", "/")
            entries = data.get("entries", [])
            self.sig_file_list.emit(self.ci.client_id, path, entries)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_list: {e}")

    def _handle_file_download(self, payload: bytes) -> None:
        try:
            # Primeiros 256 bytes = metadados JSON, resto = dados binários
            meta_raw = payload[:256].rstrip(b"\x00")
            file_data = payload[256:]
            meta = json.loads(meta_raw.decode("utf-8", errors="replace"))
            filename = meta.get("filename", "arquivo")
            self.sig_file_download.emit(self.ci.client_id, filename, file_data)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_download: {e}")

    def _handle_file_upload_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_file_upload_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_upload_res: {e}")

    def _handle_file_delete_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_file_delete_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_delete_res: {e}")

    def _handle_file_rename_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_file_rename_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_rename_res: {e}")

    def _handle_file_mkdir_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_file_mkdir_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_mkdir_res: {e}")

    def _handle_file_read_res(self, payload: bytes) -> None:
        try:
            meta_raw = payload[:256].rstrip(b"\x00")
            content_raw = payload[256:]
            meta = json.loads(meta_raw.decode("utf-8", errors="replace"))
            filename = meta.get("filename", "")
            content = content_raw.decode("utf-8", errors="replace")
            self.sig_file_read_res.emit(self.ci.client_id, filename, content)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_read_res: {e}")

    def _handle_file_search_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            results = data.get("results", [])
            self.sig_file_search_res.emit(self.ci.client_id, results)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_search_res: {e}")

    def _handle_file_move_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_file_move_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro file_move_res: {e}")

    def _handle_term_cmd_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            stdout = data.get("stdout", "")
            stderr = data.get("stderr", "")
            self.sig_term_output.emit(self.ci.client_id, stdout, stderr)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro term_cmd_res: {e}")

    def _handle_term_stream(self, payload: bytes) -> None:
        try:
            chunk = payload.decode("utf-8", errors="replace")
            self.sig_term_stream.emit(self.ci.client_id, chunk)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro term_stream: {e}")

    def _handle_screen_res(self, payload: bytes) -> None:
        import base64 as _b64_mod
        client_id = self.ci.client_id

        if not payload:
            log.error(f"[{client_id}] SCREEN_RES: payload vazio")
            self.sig_error.emit(client_id, "Screenshot: payload vazio")
            return

        jpeg_data = None

        # Caminho 1: JSON com campo "_b64" (padrão atual do client3.py)
        try:
            data = json.loads(payload.decode("utf-8"))

            if not data.get("ok", True):
                msg = data.get("msg", "Erro desconhecido no client")
                log.error(f"[{client_id}] SCREEN_RES: client reportou falha — {msg}")
                self.sig_error.emit(client_id, f"Screenshot falhou no client: {msg}")
                return

            if "_b64" in data:
                b64_str = data["_b64"]
                if "," in b64_str:
                    b64_str = b64_str.split(",", 1)[1]
                jpeg_data = _b64_mod.b64decode(b64_str)
                log.info(f"[{client_id}] SCREEN_RES OK — "
                        f"{len(jpeg_data)} bytes, backend={data.get('backend','?')}")

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # não é JSON, tenta fallback abaixo
        except Exception as e:
            log.error(f"[{client_id}] SCREEN_RES: erro ao decodificar _b64 — {e}")
            self.sig_error.emit(client_id, f"Screenshot: erro de decodificação — {e}")
            return

        # Caminho 2: fallback legado (payload binário com 256 bytes de header)
        if jpeg_data is None and len(payload) > 256:
            try:
                jpeg_data = payload[256:]
                log.info(f"[{client_id}] SCREEN_RES (fallback legado): {len(jpeg_data)} bytes")
            except Exception as e:
                log.warning(f"[{client_id}] SCREEN_RES: fallback falhou — {e}")
                jpeg_data = payload

        if jpeg_data:
            self.sig_screen_res.emit(client_id, jpeg_data)
        else:
            log.error(f"[{client_id}] SCREEN_RES: falha total ao extrair imagem")
            self.sig_error.emit(client_id, "Screenshot: falha ao extrair imagem")

    def _handle_lock_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_lock_res.emit(self.ci.client_id, data.get("ok", False), data.get("msg", ""))
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro lock_res: {e}")

    def _handle_unlock_res(self, payload: bytes) -> None:
        try:
            data     = decode_json_payload(payload)
            ok       = data.get("ok", False)
            msg      = data.get("msg", "")
            by_user  = data.get("by_user", False)
            # Passa by_user na mensagem para a UI distinguir a origem
            full_msg = f"[CLIENTE] {msg}" if by_user else msg
            self.sig_unlock_res.emit(self.ci.client_id, ok, full_msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro unlock_res: {e}")

    def _handle_net_info(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            self.sig_net_info.emit(self.ci.client_id, data)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro net_info: {e}")

    def _handle_net_ping_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            rtt = data.get("rtt_ms", -1.0)
            self.sig_net_ping_res.emit(self.ci.client_id, rtt)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro net_ping_res: {e}")

    def _handle_log_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            entries = data.get("entries", [])
            self.sig_log_res.emit(self.ci.client_id, entries)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro log_res: {e}")

    def _handle_log_stream(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            level = data.get("level", "INFO")
            msg = data.get("msg", "")
            self.sig_log_stream.emit(self.ci.client_id, level, msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro log_stream: {e}")

    def _handle_clipboard_res(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            content = data.get("content", "")
            self.sig_clipboard_res.emit(self.ci.client_id, content)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro clipboard_res: {e}")

    def _handle_action_res_generic(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            action = data.get("action", "")
            ok = data.get("ok", False)
            msg = data.get("msg", "")
            self.sig_action_res.emit(self.ci.client_id, action, ok, msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro action_res_generic: {e}")

    def _handle_generic_error(self, payload: bytes) -> None:
        try:
            data = decode_json_payload(payload)
            error_msg = data.get("error", "Erro desconhecido")
            log.warning(f"[{self.ci.client_id}] GENERIC_ERROR: {error_msg}")
            self.sig_error.emit(self.ci.client_id, error_msg)
        except Exception as e:
            log.error(f"[{self.ci.client_id}] Erro ao processar GENERIC_ERROR: {e}")

    # ── COMANDOS PARA O CLIENT ─────────────────────────────────────────────
    def request_sys_info(self) -> None:
        self.send(MsgType.SYS_INFO_REQ, b"")

    def request_metrics(self) -> None:
        self.send(MsgType.METRICS_REQ, b"")

    def request_proc_list(self) -> None:
        self.send(MsgType.PROC_LIST_REQ, b"")

    def request_proc_kill(self, pid: int) -> None:
        self.send_json(MsgType.PROC_KILL_REQ, {"pid": pid})

    def request_proc_suspend(self, pid: int) -> None:
        self.send_json(MsgType.PROC_SUSPEND_REQ, {"pid": pid})

    def request_proc_resume(self, pid: int) -> None:
        self.send_json(MsgType.PROC_RESUME_REQ, {"pid": pid})

    def request_file_list(self, path: str) -> None:
        self.send_json(MsgType.FILE_LIST_REQ, {"path": path})

    def request_file_download(self, path: str) -> None:
        self.send_json(MsgType.FILE_DOWNLOAD_REQ, {"path": path})

    def request_file_upload(self, dest_path: str, filename: str, data: bytes) -> None:
        meta = json.dumps({"dest_path": dest_path, "filename": filename}).encode("utf-8")
        meta_padded = meta.ljust(256, b"\x00")[:256]
        payload = meta_padded + data
        self.send(MsgType.FILE_UPLOAD_REQ, payload)

    def request_file_delete(self, path: str) -> None:
        self.send_json(MsgType.FILE_DELETE_REQ, {"path": path})

    def request_file_rename(self, old_path: str, new_name: str) -> None:
        self.send_json(MsgType.FILE_RENAME_REQ, {"old_path": old_path, "new_name": new_name})

    def request_file_mkdir(self, path: str, name: str) -> None:
        self.send_json(MsgType.FILE_MKDIR_REQ, {"path": path, "name": name})

    def request_file_read(self, path: str) -> None:
        self.send_json(MsgType.FILE_READ_REQ, {"path": path})

    def request_file_search(self, base_path: str, query: str) -> None:
        self.send_json(MsgType.FILE_SEARCH_REQ, {"base_path": base_path, "query": query})

    def request_file_move(self, src: str, dst: str) -> None:
        self.send_json(MsgType.FILE_MOVE_REQ, {"src": src, "dst": dst})

    def request_term_cmd(self, cmd: str) -> None:
        self.send_json(MsgType.TERM_CMD_REQ, {"cmd": cmd})

    def request_screenshot(self, quality: int = 70) -> None:
        self.send_json(MsgType.SCREEN_REQ, {"quality": quality})

    def request_lock(self, password_encrypted: str, message: str) -> None:
        self.send_json(MsgType.LOCK_REQ, {"password": password_encrypted, "message": message})

    def request_unlock(self) -> None:
        self.send(MsgType.UNLOCK_REQ, b"")

    def request_net_info(self) -> None:
        self.send(MsgType.NET_INFO_REQ, b"")

    def request_net_ping(self, host: str) -> None:
        self.send_json(MsgType.NET_PING_REQ, {"host": host})

    def request_logs(self, level: str = "DEBUG", limit: int = 500) -> None:
        self.send_json(MsgType.LOG_REQ, {"level": level, "limit": limit})

    def send_heartbeat(self) -> None:
        self._hb_sent_at = time.time()
        self.send(MsgType.HEARTBEAT, b"")

    def request_restart_agent(self) -> None:
        self.send(MsgType.ACTION_RESTART_AGENT, b"")

    def request_stop_agent(self) -> None:
        self.send(MsgType.ACTION_STOP_AGENT, b"")

    def request_clipboard_get(self) -> None:
        self.send(MsgType.ACTION_CLIPBOARD_GET, b"")

    def request_clipboard_set(self, text: str) -> None:
        self.send_json(MsgType.ACTION_CLIPBOARD_SET, {"text": text})

    def request_popup_msg(self, title: str, body: str) -> None:
        self.send_json(MsgType.ACTION_POPUP_MSG, {"title": title, "body": body})

    def request_open_url(self, url: str) -> None:
        self.send_json(MsgType.ACTION_OPEN_URL, {"url": url})

    def request_shutdown(self) -> None:
        self.send(MsgType.ACTION_SHUTDOWN, b"")

    def request_reboot(self) -> None:
        self.send(MsgType.ACTION_REBOOT, b"")

    def stop(self) -> None:
        self._running = False
        self.ci.is_alive = False
        try:
            self.ci.sock.close()
        except Exception:
            pass

    def _disconnect(self, reason: str) -> None:
        if self.ci.is_alive:
            self.ci.is_alive = False
            log.info(f"[{self.ci.client_id}] Desconectado: {reason}")
            self.sig_disconnected.emit(self.ci.client_id)
        self._running = False


# ─────────────────────────────────────────────────────────────────────────────
# HEARTBEAT TIMER POR CLIENT
# ─────────────────────────────────────────────────────────────────────────────
class HeartbeatManager(QObject):
    """Gerencia o envio periódico de heartbeats para todos os clients."""

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._workers: Dict[str, ClientWorker] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(int(HEARTBEAT_INTERVAL * 1000))
        self._timer.timeout.connect(self._send_all)

    def register(self, worker: ClientWorker) -> None:
        self._workers[worker.ci.client_id] = worker
        if not self._timer.isActive():
            self._timer.start()

    def unregister(self, client_id: str) -> None:
        self._workers.pop(client_id, None)
        if not self._workers:
            self._timer.stop()

    @Slot()
    def _send_all(self) -> None:
        for cid, worker in list(self._workers.items()):
            if worker.ci.is_alive:
                try:
                    worker.send_heartbeat()
                except Exception as e:
                    log.error(f"Heartbeat falhou para {cid}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# SERVIDOR TCP
# ─────────────────────────────────────────────────────────────────────────────

class _WSSocketAdapter:
    """Adapta WebSocket para parecer um socket TCP para o ClientWorker."""
    def __init__(self, ws, loop):
        self._ws = ws
        self._loop = loop
        self._recv_buf = b""
        self._closed = asyncio.Event()
        self._queue = queue.Queue()
        import threading
        threading.Thread(target=self._recv_task, daemon=True).start()

    def _recv_task(self):
        async def _read():
            try:
                async for msg in self._ws:
                    if isinstance(msg, str):
                        # JSON do cliente — converte para binário
                        try:
                            data = json.loads(msg)
                            msg_type = data.get("type", 0)
                            payload = data.get("payload", {})
                            payload_bytes = json.dumps(payload).encode("utf-8") if payload else b""
                            packet = encode_message(MsgType(msg_type), payload_bytes)
                            self._queue.put(packet)
                        except Exception:
                            self._queue.put(msg.encode())
                    else:
                        self._queue.put(msg)
            except Exception:
                pass
            finally:
                self._closed.set()
        asyncio.run_coroutine_threadsafe(_read(), self._loop)

    def recv(self, n):
        # Bloqueia até ter dados suficientes no buffer
        while len(self._recv_buf) < n:
            try:
                chunk = self._queue.get(timeout=60)
                self._recv_buf += chunk
            except Exception:
                raise ConnectionError("WebSocket fechado")
        data = self._recv_buf[:n]
        self._recv_buf = self._recv_buf[n:]
        return data

    def send(self, data: bytes) -> int:
        if len(data) < 10:
            return len(data)
        try:
            import struct as _st, base64 as _b64, json as _js
            msg_type, hi, lo = _st.unpack(">IHI", data[:10])
            payload = data[10:]

            try:
                payload_obj = _js.loads(payload.decode("utf-8")) if payload else {}
                is_binary   = False
                # Payload é JSON válido (inclui screenshot com _b64 já dentro)
                # NÃO marca como binary=True para o admin não tentar decodificar de novo
            except (UnicodeDecodeError, _js.JSONDecodeError):
                # Binário puro (ex: download de arquivo)
                payload_obj = {"_b64": _b64.b64encode(payload).decode("ascii")}
                is_binary   = True

            msg_out = _js.dumps({
                "type":    msg_type,
                "payload": payload_obj,
                "binary":  is_binary,
            })
            asyncio.run_coroutine_threadsafe(
                self._ws.send(msg_out), self._loop
            )
        except Exception as e:
            log.error(f"_WSSocketAdapter.send erro: {e}")
        return len(data)

    def close(self):
        asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)

    def setsockopt(self, *args): pass
    def settimeout(self,*args): pass
    def shutdown(self, *args): pass

    async def wait_closed(self):
        await self._closed.wait()

class ServerListener(QObject):
    """
    Thread que escuta na porta TCP e emite signal para cada nova conexão.
    Roda em QThread separada.
    """
    sig_new_connection = Signal(object, tuple)  # (socket, addr)
    sig_error          = Signal(str)
    sig_started        = Signal()
    sig_stopped        = Signal()

    def __init__(self, host: str, port: int, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self._running = False
        self._sock: Optional[socket.socket] = None

    @Slot()
    def run(self) -> None:
        import asyncio
        import websockets

        self._running = True
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def _serve():
            log.info(f"WebSocket aguardando na porta 3000...")
            self.sig_started.emit()
            async with websockets.serve(self._ws_handler, "0.0.0.0", 3000):
                await asyncio.Future()

        self._loop.run_until_complete(_serve())

    async def _ws_handler(self, ws):
        import socket as _s
        addr = (ws.remote_address[0], ws.remote_address[1])
        conn = _WSSocketAdapter(ws, self._loop)
        self.sig_new_connection.emit(conn, addr)
        await conn.wait_closed()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# GERENCIADOR DE CLIENTS (Controller)
# ─────────────────────────────────────────────────────────────────────────────
class ClientManager(QObject):
    """
    Coordena todos os clients conectados.
    Centraliza o servidor TCP, cria workers e threads.
    """
    sig_client_connected    = Signal(str)          # client_id
    sig_client_disconnected = Signal(str)          # client_id
    sig_client_authenticated= Signal(str, dict)    # client_id, sys_info
    sig_server_error        = Signal(str)
    sig_server_started      = Signal()

    # Proxy de todos os signals dos workers
    sig_metrics        = Signal(str, dict)
    sig_sys_info       = Signal(str, dict)
    sig_proc_list      = Signal(str, list)
    sig_proc_result    = Signal(str, str, bool, str)
    sig_file_list      = Signal(str, str, list)
    sig_file_download  = Signal(str, str, bytes)
    sig_file_upload_res= Signal(str, bool, str)
    sig_file_delete_res= Signal(str, bool, str)
    sig_file_rename_res= Signal(str, bool, str)
    sig_file_mkdir_res = Signal(str, bool, str)
    sig_file_read_res  = Signal(str, str, str)
    sig_file_search_res= Signal(str, list)
    sig_file_move_res  = Signal(str, bool, str)
    sig_term_output    = Signal(str, str, str)
    sig_term_stream    = Signal(str, str)
    sig_screen_res     = Signal(str, bytes)
    sig_lock_res       = Signal(str, bool, str)
    sig_unlock_res     = Signal(str, bool, str)
    sig_net_info       = Signal(str, dict)
    sig_net_ping_res   = Signal(str, float)
    sig_log_res        = Signal(str, list)
    sig_log_stream     = Signal(str, str, str)
    sig_action_res     = Signal(str, str, bool, str)
    sig_clipboard_res  = Signal(str, str)
    sig_heartbeat      = Signal(str, float)
    sig_worker_error   = Signal(str, str)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._clients: Dict[str, ClientInfo] = {}
        self._workers: Dict[str, ClientWorker] = {}
        self._threads: Dict[str, QThread] = {}
        self._lock = threading.Lock()
        self._client_counter = 0
        self._hb_manager = HeartbeatManager(self)

        # Servidor TCP
        self._listener = ServerListener(LISTEN_HOST, LISTEN_PORT)
        self._listener_thread = QThread(self)
        self._listener.moveToThread(self._listener_thread)
        self._listener_thread.started.connect(self._listener.run)
        self._listener.sig_new_connection.connect(self._on_new_connection)
        self._listener.sig_error.connect(self.sig_server_error)
        self._listener.sig_started.connect(self.sig_server_started)

    def start_server(self) -> None:
        """Inicia o servidor TCP."""
        self._listener_thread.start()

    def stop_server(self) -> None:
        """Para o servidor TCP e desconecta todos os clients."""
        self._listener.stop()
        for cid in list(self._clients.keys()):
            self.disconnect_client(cid)
        self._listener_thread.quit()
        self._listener_thread.wait(3000)

    @Slot(object, tuple)
    def _on_new_connection(self, sock: socket.socket, addr: tuple) -> None:
        """Chamado quando um novo client se conecta (thread-safe via signal)."""
        with self._lock:
            self._client_counter += 1
            client_id = f"client_{self._client_counter:04d}"
        ci = ClientInfo(client_id=client_id, sock=sock, addr=addr)
        worker = ClientWorker(ci)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)

        # Conectar todos os signals do worker ao manager
        worker.sig_disconnected.connect(self._on_worker_disconnected)
        worker.sig_auth_ok.connect(self._on_auth_ok)
        worker.sig_auth_error.connect(self._on_auth_error)
        worker.sig_sys_info.connect(self.sig_sys_info)
        worker.sig_metrics.connect(self.sig_metrics)
        worker.sig_proc_list.connect(self.sig_proc_list)
        worker.sig_proc_result.connect(self.sig_proc_result)
        worker.sig_file_list.connect(self.sig_file_list)
        worker.sig_file_download.connect(self.sig_file_download)
        worker.sig_file_upload_res.connect(self.sig_file_upload_res)
        worker.sig_file_delete_res.connect(self.sig_file_delete_res)
        worker.sig_file_rename_res.connect(self.sig_file_rename_res)
        worker.sig_file_mkdir_res.connect(self.sig_file_mkdir_res)
        worker.sig_file_read_res.connect(self.sig_file_read_res)
        worker.sig_file_search_res.connect(self.sig_file_search_res)
        worker.sig_file_move_res.connect(self.sig_file_move_res)
        worker.sig_term_output.connect(self.sig_term_output)
        worker.sig_term_stream.connect(self.sig_term_stream)
        worker.sig_screen_res.connect(self.sig_screen_res)
        worker.sig_lock_res.connect(self.sig_lock_res)
        worker.sig_unlock_res.connect(self.sig_unlock_res)
        worker.sig_net_info.connect(self.sig_net_info)
        worker.sig_net_ping_res.connect(self.sig_net_ping_res)
        worker.sig_log_res.connect(self.sig_log_res)
        worker.sig_log_stream.connect(self.sig_log_stream)
        worker.sig_action_res.connect(self.sig_action_res)
        worker.sig_clipboard_res.connect(self.sig_clipboard_res)
        worker.sig_heartbeat.connect(self.sig_heartbeat)
        worker.sig_error.connect(self.sig_worker_error)

        with self._lock:
            self._clients[client_id] = ci
            self._workers[client_id] = worker
            self._threads[client_id] = thread

        thread.start()
        self._hb_manager.register(worker)
        log.info(f"Client {client_id} registrado — {addr}")
        self.sig_client_connected.emit(client_id)

    @Slot(str, dict)
    def _on_auth_ok(self, client_id: str, sys_info: dict) -> None:
        self.sig_client_authenticated.emit(client_id, sys_info)

    @Slot(str, str)
    def _on_auth_error(self, client_id: str, reason: str) -> None:
        log.warning(f"Auth falhou para {client_id}: {reason}")
        self.disconnect_client(client_id)

    @Slot(str)
    def _on_worker_disconnected(self, client_id: str) -> None:
        self._cleanup_client(client_id)
        self.sig_client_disconnected.emit(client_id)

    def _cleanup_client(self, client_id: str) -> None:
        self._hb_manager.unregister(client_id)
        worker = self._workers.get(client_id)
        if worker:
            worker.stop()
        thread = self._threads.get(client_id)
        if thread and thread.isRunning():
            thread.quit()
            thread.wait(3000)
        with self._lock:
            self._clients.pop(client_id, None)
            self._workers.pop(client_id, None)
            self._threads.pop(client_id, None)

    def disconnect_client(self, client_id: str) -> None:
        """Força desconexão de um client."""
        worker = self._workers.get(client_id)
        if worker:
            worker.stop()
        self._cleanup_client(client_id)

    def get_worker(self, client_id: str) -> Optional[ClientWorker]:
        return self._workers.get(client_id)

    def get_client_info(self, client_id: str) -> Optional[ClientInfo]:
        return self._clients.get(client_id)

    def get_all_clients(self) -> List[ClientInfo]:
        with self._lock:
            return list(self._clients.values())

    def client_count(self) -> int:
        return len(self._clients)


# ─────────────────────────────────────────────────────────────────────────────
# UTILITÁRIOS DE UI
# ─────────────────────────────────────────────────────────────────────────────
def make_label(text: str, bold: bool = False, color: str = Colors.TEXT_PRIMARY,
               size: int = 13, align: Qt.AlignmentFlag = Qt.AlignLeft) -> QLabel:
    """Cria um QLabel estilizado."""
    lbl = QLabel(text)
    font = lbl.font()
    font.setPointSize(size)
    if bold:
        font.setBold(True)
    lbl.setFont(font)
    lbl.setStyleSheet(f"color: {color}; background: transparent;")
    lbl.setAlignment(align | Qt.AlignVCenter)
    return lbl


def make_button(text: str, primary: bool = False, danger: bool = False,
                icon_text: str = "", tooltip: str = "") -> QPushButton:
    """Cria um QPushButton estilizado."""
    btn = QPushButton(text)
    if icon_text:
        btn.setText(f"{icon_text}  {text}" if text else icon_text)

    if primary:
        style = f"""
            QPushButton {{
                background: {Colors.ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 13px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background: {Colors.ACCENT_HOVER}; }}
            QPushButton:pressed {{ background: {Colors.ACCENT_PRESSED}; }}
            QPushButton:disabled {{ background: #CCCCCC; color: #888888; }}
        """
    elif danger:
        style = f"""
            QPushButton {{
                background: {Colors.ERROR};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 13px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background: #B02020; }}
            QPushButton:pressed {{ background: #9A1C1C; }}
            QPushButton:disabled {{ background: #CCCCCC; color: #888888; }}
        """
    else:
        style = f"""
            QPushButton {{
                background: {Colors.BG_WHITE};
                color: {Colors.TEXT_PRIMARY};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 13px;
            }}
            QPushButton:hover {{ background: #F0F0F0; border-color: #CCCCCC; }}
            QPushButton:pressed {{ background: #E8E8E8; }}
            QPushButton:disabled {{ background: #F5F5F5; color: #AAAAAA; }}
        """
    btn.setStyleSheet(style)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def make_card(title: str = "") -> QGroupBox:
    """Cria um GroupBox estilo card."""
    gb = QGroupBox(title)
    gb.setStyleSheet(f"""
        QGroupBox {{
            background: {Colors.BG_WHITE};
            border: 1px solid {Colors.BORDER};
            border-radius: 6px;
            margin-top: 8px;
            padding: 8px;
            font-size: 12px;
            font-weight: 600;
            color: {Colors.TEXT_SECONDARY};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            padding: 0 4px;
            left: 8px;
        }}
    """)
    return gb


def make_separator(horizontal: bool = True) -> QFrame:
    """Cria um separador fino."""
    sep = QFrame()
    sep.setFrameShape(QFrame.HLine if horizontal else QFrame.VLine)
    sep.setStyleSheet(f"color: {Colors.BORDER}; background: {Colors.BORDER};")
    sep.setMaximumHeight(1 if horizontal else 9999)
    return sep


def format_bytes(b: int) -> str:
    """Formata bytes de forma legível."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def format_uptime(seconds: float) -> str:
    """Formata uptime em string legível."""
    try:
        seconds = int(seconds)
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        mins, secs = divmod(rem, 60)
        if days > 0:
            return f"{days}d {hours:02d}h {mins:02d}m"
        return f"{hours:02d}h {mins:02d}m {secs:02d}s"
    except Exception:
        return "N/A"


def pct_color(value: float) -> str:
    """Retorna cor baseada em percentual."""
    if value >= 90:
        return Colors.ERROR
    if value >= 70:
        return Colors.WARNING
    return Colors.SUCCESS


# ─────────────────────────────────────────────────────────────────────────────
# WIDGET DE GRÁFICO DE LINHA
# ─────────────────────────────────────────────────────────────────────────────
class LineChartWidget(QWidget):
    """
    Gráfico de linha leve para exibir histórico de métricas.
    Desenhado com QPainter — sem dependências externas.
    """
    def __init__(self, title: str = "", unit: str = "%",
                 color: str = Colors.ACCENT, max_val: float = 100.0,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.title = title
        self.unit = unit
        self.color = QColor(color)
        self.max_val = max_val
        self._data: deque = deque(maxlen=HISTORY_LEN)
        self.setMinimumHeight(80)
        self.setMinimumWidth(120)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet(f"background: {Colors.BG_WHITE}; border-radius: 4px;")

    def push(self, value: float) -> None:
        self._data.append(max(0.0, min(self.max_val, value)))
        self.update()

    def clear_data(self) -> None:
        self._data.clear()
        self.update()

    def paintEvent(self, event) -> None:
        if not self._data:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        pad_l, pad_r, pad_t, pad_b = 36, 8, 20, 20

        # Fundo
        painter.fillRect(0, 0, w, h, QColor(Colors.BG_WHITE))

        # Título
        painter.setPen(QColor(Colors.TEXT_MUTED))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(pad_l, pad_t - 4, self.title)

        # Grade
        grid_color = QColor(Colors.BORDER)
        grid_pen = QPen(grid_color)
        grid_pen.setStyle(Qt.DotLine)
        painter.setPen(grid_pen)
        chart_h = h - pad_t - pad_b
        chart_w = w - pad_l - pad_r
        for i in range(5):
            y_ratio = i / 4
            y = pad_t + int(chart_h * y_ratio)
            painter.drawLine(pad_l, y, w - pad_r, y)
            # Label Y
            val_label = f"{self.max_val * (1 - y_ratio):.0f}"
            painter.setPen(QColor(Colors.TEXT_MUTED))
            painter.drawText(0, y + 4, pad_l - 2, 12, Qt.AlignRight, val_label)
            painter.setPen(grid_pen)

        # Linha de dados
        data_list = list(self._data)
        n = len(data_list)
        if n < 2:
            return

        # Área preenchida
        fill_color = QColor(self.color)
        fill_color.setAlpha(30)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(fill_color))

        pts = []
        for i, val in enumerate(data_list):
            x = pad_l + int(i * chart_w / (HISTORY_LEN - 1))
            y = pad_t + int(chart_h * (1 - val / self.max_val))
            pts.append((x, y))

        from PySide6.QtGui import QPolygon
        poly_pts = [(pts[0][0], pad_t + chart_h)]
        poly_pts += pts
        poly_pts += [(pts[-1][0], pad_t + chart_h)]
        polygon = QPolygon([QPoint(x, y) for x, y in poly_pts])
        painter.drawPolygon(polygon)

        # Linha
        line_pen = QPen(self.color)
        line_pen.setWidth(2)
        painter.setPen(line_pen)
        painter.setBrush(Qt.NoBrush)
        for i in range(1, len(pts)):
            x0, y0 = pts[i-1]
            x1, y1 = pts[i]
            painter.drawLine(x0, y0, x1, y1)

        # Valor atual
        current = data_list[-1]
        painter.setPen(QColor(Colors.TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 10, QFont.Bold))
        painter.drawText(pad_l, h - 4, f"{current:.1f}{self.unit}")

        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# WIDGET DE BARRA DE PROGRESSO CUSTOMIZADO
# ─────────────────────────────────────────────────────────────────────────────
class MetricBar(QWidget):
    """Barra de métricas compacta com label, valor e barra visual."""

    def __init__(self, label: str, color: str = Colors.ACCENT, parent=None):
        super().__init__(parent)
        self._label = label
        self._color = color
        self._value = 0.0
        self._text = "0%"
        self.setFixedHeight(32)
        self.setMinimumWidth(100)

    def set_value(self, value: float, text: str = "") -> None:
        self._value = max(0.0, min(100.0, value))
        self._text = text or f"{value:.1f}%"
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()

        # Label
        painter.setPen(QColor(Colors.TEXT_SECONDARY))
        painter.setFont(QFont("Segoe UI", 9))
        label_w = 60
        painter.drawText(0, 0, label_w, h, Qt.AlignVCenter | Qt.AlignLeft, self._label)

        # Barra
        bar_x = label_w + 4
        bar_w = w - bar_x - 50
        bar_h = 8
        bar_y = (h - bar_h) // 2

        # Fundo
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#E8E8E8"))
        painter.drawRoundedRect(bar_x, bar_y, bar_w, bar_h, 4, 4)

        # Preenchimento
        fill_w = int(bar_w * self._value / 100.0)
        if fill_w > 0:
            color = QColor(pct_color(self._value))
            painter.setBrush(color)
            painter.drawRoundedRect(bar_x, bar_y, fill_w, bar_h, 4, 4)

        # Texto do valor
        painter.setPen(QColor(Colors.TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 9, QFont.Bold))
        painter.drawText(bar_x + bar_w + 4, 0, 46, h, Qt.AlignVCenter | Qt.AlignRight, self._text)
        painter.end()


# ─────────────────────────────────────────────────────────────────────────────
# CARD DE MÉTRICA NUMÉRICA
# ─────────────────────────────────────────────────────────────────────────────
class MetricCard(QFrame):
    """Card compacto para exibir uma métrica principal com label."""

    def __init__(self, label: str, icon: str = "", parent=None):
        super().__init__(parent)
        self._label = label
        self.setFrameShape(QFrame.NoFrame)
        self.setStyleSheet(f"""
            QFrame {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 6px;
            }}
        """)
        self.setFixedHeight(80)
        self.setMinimumWidth(110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        header = QHBoxLayout()
        if icon:
            icon_lbl = make_label(icon, size=16)
            header.addWidget(icon_lbl)
        lbl = make_label(label, color=Colors.TEXT_SECONDARY, size=10)
        header.addWidget(lbl)
        header.addStretch()
        layout.addLayout(header)

        self.value_lbl = make_label("—", bold=True, size=20, color=Colors.TEXT_PRIMARY)
        self.value_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layout.addWidget(self.value_lbl)

        self.sub_lbl = make_label("", color=Colors.TEXT_MUTED, size=9)
        layout.addWidget(self.sub_lbl)

    def set_value(self, value: str, sub: str = "", color: str = Colors.TEXT_PRIMARY) -> None:
        self.value_lbl.setText(value)
        self.value_lbl.setStyleSheet(f"color: {color}; background: transparent; font-size: 20px; font-weight: bold;")
        if sub:
            self.sub_lbl.setText(sub)


# ─────────────────────────────────────────────────────────────────────────────
# BANNER DE NOTIFICAÇÃO (dispensável)
# ─────────────────────────────────────────────────────────────────────────────
class NotificationBanner(QFrame):
    """Banner de notificação que aparece no topo e pode ser dispensado."""

    def __init__(self, message: str, level: str = "info", parent=None):
        super().__init__(parent)
        colors = {
            "info":    (Colors.ACCENT,   "#EBF3FC", "#004E9B"),
            "success": (Colors.SUCCESS,  "#DFF6DD", "#0A4F0A"),
            "warning": (Colors.WARNING,  "#FFF4CE", "#7D5700"),
            "error":   (Colors.ERROR,    "#FDE7E9", "#6E1317"),
        }
        border_c, bg_c, text_c = colors.get(level, colors["info"])
        self.setStyleSheet(f"""
            QFrame {{
                background: {bg_c};
                border: 1px solid {border_c};
                border-radius: 4px;
                padding: 2px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        icons = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗"}
        icon = make_label(icons.get(level, "ℹ"), bold=True, color=border_c, size=13)
        layout.addWidget(icon)
        msg_lbl = make_label(message, color=text_c, size=12)
        msg_lbl.setWordWrap(True)
        layout.addWidget(msg_lbl, 1)
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(20, 20)
        close_btn.setStyleSheet(f"QPushButton {{ background: transparent; border: none; color: {text_c}; font-size: 11px; }} QPushButton:hover {{ background: rgba(0,0,0,0.1); border-radius: 3px; }}")
        close_btn.clicked.connect(self.hide)
        layout.addWidget(close_btn)
        self.setMaximumHeight(50)

    def show_timed(self, ms: int = 5000) -> None:
        self.show()
        QTimer.singleShot(ms, self.hide)


# ─────────────────────────────────────────────────────────────────────────────
# STATUS PILL
# ─────────────────────────────────────────────────────────────────────────────
class StatusPill(QLabel):
    """Pill colorida de status."""

    def __init__(self, text: str = "Online", status: str = "online", parent=None):
        super().__init__(text, parent)
        self.set_status(status, text)

    def set_status(self, status: str, text: str = "") -> None:
        configs = {
            "online":    (Colors.BADGE_ONLINE_BG,  Colors.BADGE_ONLINE_FG),
            "offline":   (Colors.BADGE_OFFLINE_BG, Colors.BADGE_OFFLINE_FG),
            "warning":   (Colors.BADGE_WARN_BG,    Colors.BADGE_WARN_FG),
            "info":      ("#EBF3FC", Colors.ACCENT),
        }
        bg, fg = configs.get(status, configs["info"])
        if text:
            self.setText(text)
        self.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border-radius: 10px;
                padding: 2px 10px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
class SidebarItem(QWidget):
    """Item clicável da sidebar."""
    clicked = Signal(str)

    def __init__(self, page_id: str, icon: str, label: str, parent=None):
        super().__init__(parent)
        self.page_id = page_id
        self._active = False
        self.setFixedHeight(42)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setToolTip(label)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 12, 0)
        layout.setSpacing(10)

        self.icon_lbl = QLabel(icon)
        self.icon_lbl.setFixedWidth(18)
        self.icon_lbl.setStyleSheet("background: transparent; color: #AABBCC; font-size: 15px;")
        layout.addWidget(self.icon_lbl)

        self.text_lbl = QLabel(label)
        self.text_lbl.setStyleSheet("background: transparent; color: #B0C0D4; font-size: 12px;")
        layout.addWidget(self.text_lbl, 1)

        self._update_style()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._update_style()

    def _update_style(self) -> None:
        if self._active:
            self.setStyleSheet(f"background: {Colors.SIDEBAR_ACTIVE}; border-radius: 4px;")
            self.icon_lbl.setStyleSheet("background: transparent; color: white; font-size: 15px;")
            self.text_lbl.setStyleSheet("background: transparent; color: white; font-size: 12px; font-weight: 600;")
        else:
            self.setStyleSheet("background: transparent; border-radius: 4px;")
            self.icon_lbl.setStyleSheet("background: transparent; color: #8899BB; font-size: 15px;")
            self.text_lbl.setStyleSheet("background: transparent; color: #B0C0D4; font-size: 12px;")

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.page_id)
        super().mousePressEvent(event)

    def enterEvent(self, event) -> None:
        if not self._active:
            self.setStyleSheet(f"background: {Colors.SIDEBAR_HOVER}; border-radius: 4px;")
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._update_style()
        super().leaveEvent(event)


class Sidebar(QWidget):
    """Sidebar de navegação principal."""
    page_changed = Signal(str)

    PAGES = [
        ("dashboard",  "⊞",  "Dashboard"),
        ("processes",  "⚙",  "Processos"),
        ("files",      "📁",  "Arquivos"),
        ("terminal",   "⬛",  "Terminal"),
        ("screen",     "🖥",  "Tela Remota"),
        ("lock",       "🔒",  "Lock de Tela"),
        ("network",    "🌐",  "Rede"),
        ("logs",       "📋",  "Logs"),
        ("actions",    "⚡",  "Ações Rápidas"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(190)
        self.setStyleSheet(f"background: {Colors.SIDEBAR_BG};")
        self._items: Dict[str, SidebarItem] = {}
        self._current = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 0, 8, 8)
        layout.setSpacing(0)

        # Logo/Header
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {Colors.SIDEBAR_BG};")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(12, 0, 12, 0)
        logo_dot = QLabel("●")
        logo_dot.setStyleSheet(f"color: {Colors.ACCENT}; font-size: 10px; background: transparent;")
        h_layout.addWidget(logo_dot)
        app_name = QLabel(APP_NAME)
        app_name.setStyleSheet("color: white; font-size: 13px; font-weight: bold; background: transparent;")
        h_layout.addWidget(app_name, 1)
        layout.addWidget(header)

        sep = make_separator()
        sep.setStyleSheet(f"background: #2A3D5C; max-height: 1px;")
        layout.addWidget(sep)
        layout.addSpacing(8)

        # Grupo principal
        section_lbl = QLabel("NAVEGAÇÃO")
        section_lbl.setStyleSheet("color: #5A7090; font-size: 9px; font-weight: bold; background: transparent; padding-left: 16px;")
        section_lbl.setFixedHeight(22)
        layout.addWidget(section_lbl)

        for page_id, icon, label in self.PAGES:
            item = SidebarItem(page_id, icon, label)
            item.clicked.connect(self._on_item_clicked)
            self._items[page_id] = item
            layout.addWidget(item)
            if page_id in ("screen", "network"):
                layout.addSpacing(4)

        layout.addStretch()

        # Versão no rodapé
        ver_lbl = QLabel(f"v{APP_VERSION}")
        ver_lbl.setStyleSheet("color: #3A5070; font-size: 9px; background: transparent; padding-left: 16px;")
        layout.addWidget(ver_lbl)

    def _on_item_clicked(self, page_id: str) -> None:
        self.switch_to(page_id)
        self.page_changed.emit(page_id)

    def switch_to(self, page_id: str) -> None:
        if self._current:
            self._items.get(self._current, SidebarItem("", "", "")).set_active(False)
        self._current = page_id
        item = self._items.get(page_id)
        if item:
            item.set_active(True)

    def current_page(self) -> str:
        return self._current


# ─────────────────────────────────────────────────────────────────────────────
# TOPBAR COM ABAS DE CLIENTS
# ─────────────────────────────────────────────────────────────────────────────
class ClientTab(QFrame):
    """Aba de client na topbar."""
    selected = Signal(str)
    closed   = Signal(str)

    def __init__(self, client_id: str, hostname: str, ip: str, parent=None):
        super().__init__(parent)
        self.client_id = client_id
        self._active = False
        self.setFixedHeight(36)
        self.setMinimumWidth(140)
        self.setMaximumWidth(240)
        self.setCursor(QCursor(Qt.PointingHandCursor))

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 6, 0)
        layout.setSpacing(6)

        self.status_dot = QLabel("●")
        self.status_dot.setFixedWidth(10)
        self.status_dot.setStyleSheet(f"color: {Colors.SUCCESS}; font-size: 8px; background: transparent;")
        layout.addWidget(self.status_dot)

        self.name_lbl = QLabel(hostname or ip)
        self.name_lbl.setStyleSheet(f"color: {Colors.TEXT_PRIMARY}; font-size: 12px; background: transparent;")
        layout.addWidget(self.name_lbl, 1)

        self.ping_lbl = QLabel("...")
        self.ping_lbl.setStyleSheet(f"color: {Colors.TEXT_MUTED}; font-size: 10px; background: transparent;")
        layout.addWidget(self.ping_lbl)

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(16, 16)
        close_btn.setStyleSheet(f"""
            QPushButton {{ background: transparent; border: none; color: {Colors.TEXT_MUTED}; font-size: 10px; }}
            QPushButton:hover {{ background: {Colors.ERROR}; color: white; border-radius: 3px; }}
        """)
        close_btn.clicked.connect(lambda: self.closed.emit(self.client_id))
        layout.addWidget(close_btn)

        self._update_style()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._update_style()

    def set_ping(self, ms: float) -> None:
        if ms < 0:
            self.ping_lbl.setText("N/A")
        else:
            color = Colors.SUCCESS if ms < 50 else Colors.WARNING if ms < 150 else Colors.ERROR
            self.ping_lbl.setText(f"{ms:.0f}ms")
            self.ping_lbl.setStyleSheet(f"color: {color}; font-size: 10px; background: transparent;")

    def set_hostname(self, hostname: str) -> None:
        self.name_lbl.setText(hostname)

    def set_offline(self) -> None:
        self.status_dot.setStyleSheet(f"color: {Colors.ERROR}; font-size: 8px; background: transparent;")
        self.ping_lbl.setText("offline")

    def _update_style(self) -> None:
        if self._active:
            self.setStyleSheet(f"""
                QFrame {{
                    background: {Colors.BG_WHITE};
                    border-bottom: 2px solid {Colors.ACCENT};
                    border-top: none;
                    border-left: 1px solid {Colors.BORDER};
                    border-right: 1px solid {Colors.BORDER};
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QFrame {{
                    background: {Colors.BG_BASE};
                    border-bottom: 1px solid {Colors.BORDER};
                    border-top: none;
                    border-left: none;
                    border-right: 1px solid {Colors.BORDER};
                }}
                QFrame:hover {{ background: #EBEBEE; }}
            """)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.selected.emit(self.client_id)
        super().mousePressEvent(event)


class TopBar(QWidget):
    """Barra superior com abas de clients e informações globais."""
    client_selected    = Signal(str)
    client_close_req   = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        self.setStyleSheet(f"background: {Colors.TOPBAR_BG}; border-bottom: 1px solid {Colors.BORDER};")
        self._tabs: Dict[str, ClientTab] = {}
        self._active_client = ""

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Linha superior: info e status
        top_row = QHBoxLayout()
        top_row.setContentsMargins(16, 4, 16, 0)
        top_row.setSpacing(12)

        self.server_status = StatusPill("Servidor Ativo", "online")
        top_row.addWidget(self.server_status)

        self.server_addr_lbl = make_label(f"⊛ {LISTEN_HOST}:{LISTEN_PORT}", color=Colors.TEXT_MUTED, size=10)
        top_row.addWidget(self.server_addr_lbl)

        top_row.addStretch()

        self.total_clients_lbl = make_label("0 clients", color=Colors.TEXT_MUTED, size=10)
        top_row.addWidget(self.total_clients_lbl)

        self.time_lbl = make_label("", color=Colors.TEXT_MUTED, size=10)
        top_row.addWidget(self.time_lbl)
        timer = QTimer(self)
        timer.timeout.connect(self._update_time)
        timer.start(1000)
        self._update_time()

        main_layout.addLayout(top_row)

        # Linha inferior: abas de clients
        self.tabs_area = QWidget()
        self.tabs_layout = QHBoxLayout(self.tabs_area)
        self.tabs_layout.setContentsMargins(16, 0, 0, 0)
        self.tabs_layout.setSpacing(0)

        self.no_clients_lbl = make_label("Nenhum client conectado — aguardando...",
                                         color=Colors.TEXT_MUTED, size=11)
        self.tabs_layout.addWidget(self.no_clients_lbl)
        self.tabs_layout.addStretch()

        main_layout.addWidget(self.tabs_area)

    @Slot()
    def _update_time(self) -> None:
        self.time_lbl.setText(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

    def add_client(self, client_id: str, hostname: str, ip: str) -> None:
        if client_id in self._tabs:
            return
        tab = ClientTab(client_id, hostname, ip)
        tab.selected.connect(self._on_tab_selected)
        tab.closed.connect(self.client_close_req)

        # Remover label "nenhum client"
        if self.no_clients_lbl.isVisible():
            self.no_clients_lbl.hide()

        self.tabs_layout.insertWidget(self.tabs_layout.count() - 1, tab)
        self._tabs[client_id] = tab
        self._update_count()

        # Auto-selecionar se for o primeiro
        if len(self._tabs) == 1:
            self._on_tab_selected(client_id)

    def remove_client(self, client_id: str) -> None:
        tab = self._tabs.pop(client_id, None)
        if tab:
            tab.set_offline()
            QTimer.singleShot(800, tab.deleteLater)

        if self._active_client == client_id:
            remaining = list(self._tabs.keys())
            if remaining:
                self._on_tab_selected(remaining[0])
            else:
                self._active_client = ""
                self.client_selected.emit("")

        if not self._tabs:
            self.no_clients_lbl.show()
        self._update_count()

    def update_client(self, client_id: str, hostname: str, ping: float) -> None:
        tab = self._tabs.get(client_id)
        if tab:
            tab.set_hostname(hostname)
            tab.set_ping(ping)

    def _on_tab_selected(self, client_id: str) -> None:
        if self._active_client:
            old_tab = self._tabs.get(self._active_client)
            if old_tab:
                old_tab.set_active(False)
        self._active_client = client_id
        new_tab = self._tabs.get(client_id)
        if new_tab:
            new_tab.set_active(True)
        self.client_selected.emit(client_id)

    def _update_count(self) -> None:
        n = len(self._tabs)
        self.total_clients_lbl.setText(f"{n} client{'s' if n != 1 else ''} conectado{'s' if n != 1 else ''}")

    def set_server_offline(self) -> None:
        self.server_status.set_status("offline", "Servidor Inativo")

    def active_client(self) -> str:
        return self._active_client


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA BASE
# ─────────────────────────────────────────────────────────────────────────────
class BasePage(QWidget):
    """
    Classe base para todas as páginas do painel.
    Fornece referência ao manager e ao client ativo.
    """

    def __init__(self, manager: ClientManager, parent=None):
        super().__init__(parent)
        self.manager = manager
        self._active_client: Optional[str] = None
        self.setStyleSheet(f"background: {Colors.BG_BASE};")
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        """Subclasses implementam a UI aqui."""
        pass

    def _connect_signals(self) -> None:
        """Subclasses conectam signals do manager aqui."""
        pass

    def set_active_client(self, client_id: str) -> None:
        """Chamado quando o client ativo muda."""
        self._active_client = client_id
        self.on_client_changed(client_id)

    def on_client_changed(self, client_id: str) -> None:
        """Override nas subclasses para reagir à mudança de client."""
        pass

    def get_worker(self) -> Optional[ClientWorker]:
        """Retorna o worker do client ativo."""
        if not self._active_client:
            return None
        return self.manager.get_worker(self._active_client)

    def get_client_info(self) -> Optional[ClientInfo]:
        if not self._active_client:
            return None
        return self.manager.get_client_info(self._active_client)

    def _no_client_msg(self) -> bool:
        """Retorna True se não há client ativo (e exibe mensagem)."""
        if not self._active_client:
            QMessageBox.warning(self, "Sem client", "Nenhum client selecionado.")
            return True
        return False

    def _show_notification(self, container: QVBoxLayout, msg: str, level: str = "info") -> None:
        """Exibe um banner de notificação em um container."""
        banner = NotificationBanner(msg, level)
        container.insertWidget(0, banner)
        banner.show_timed(5000)


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
class DashboardPage(BasePage):
    """Página principal com métricas, gráficos e informações do sistema."""

    def _setup_ui(self) -> None:
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(16, 12, 16, 12)
        self.main_layout.setSpacing(10)

        # Título e controles
        header_row = QHBoxLayout()
        title = make_label("Dashboard", bold=True, size=16)
        header_row.addWidget(title)
        header_row.addStretch()

        self.auto_refresh_cb = QCheckBox("Auto-refresh")
        self.auto_refresh_cb.setChecked(True)
        self.auto_refresh_cb.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        self.auto_refresh_cb.toggled.connect(self._toggle_auto_refresh)
        header_row.addWidget(self.auto_refresh_cb)

        interval_lbl = make_label("Intervalo:", color=Colors.TEXT_MUTED, size=11)
        header_row.addWidget(interval_lbl)

        self.interval_combo = QComboBox()
        self.interval_combo.addItems(["5s", "10s", "30s"])
        self.interval_combo.setStyleSheet(f"""
            QComboBox {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
                min-width: 70px;
            }}
        """)
        self.interval_combo.currentTextChanged.connect(self._change_interval)
        header_row.addWidget(self.interval_combo)

        refresh_btn = make_button("⟳ Atualizar", tooltip="Forçar atualização das métricas (F5)")
        refresh_btn.clicked.connect(self._refresh)
        refresh_btn.setShortcut(QKeySequence("F5"))
        header_row.addWidget(refresh_btn)

        self.main_layout.addLayout(header_row)

        # Banner de notificações
        self.banner_container = QVBoxLayout()
        self.banner_container.setSpacing(4)
        self.main_layout.addLayout(self.banner_container)

        # Cards de métricas — linha 1
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self.card_cpu    = MetricCard("CPU", "⚙")
        self.card_ram    = MetricCard("RAM", "🔷")
        self.card_disk   = MetricCard("Disco", "💾")
        self.card_uptime = MetricCard("Uptime", "⏱")
        self.card_procs  = MetricCard("Processos", "⊞")
        self.card_ping   = MetricCard("Latência", "📡")
        for c in [self.card_cpu, self.card_ram, self.card_disk,
                  self.card_uptime, self.card_procs, self.card_ping]:
            cards_row.addWidget(c)
        self.main_layout.addLayout(cards_row)

        # Área principal dividida: gráficos + info sistema
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #E1E1E1; width: 1px; }")

        # Coluna esquerda: gráficos
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        charts_card = make_card("Histórico (60s)")
        charts_layout = QVBoxLayout()
        charts_layout.setSpacing(8)

        cpu_row = QHBoxLayout()
        cpu_lbl = make_label("CPU  ", color=Colors.TEXT_SECONDARY, size=11)
        cpu_row.addWidget(cpu_lbl)
        self.cpu_chart = LineChartWidget("CPU", "%", Colors.ACCENT)
        cpu_row.addWidget(self.cpu_chart, 1)
        charts_layout.addLayout(cpu_row)

        ram_row = QHBoxLayout()
        ram_lbl = make_label("RAM  ", color=Colors.TEXT_SECONDARY, size=11)
        ram_row.addWidget(ram_lbl)
        self.ram_chart = LineChartWidget("RAM", "%", "#107C10")
        ram_row.addWidget(self.ram_chart, 1)
        charts_layout.addLayout(ram_row)

        charts_card.setLayout(charts_layout)
        left_layout.addWidget(charts_card, 1)

        # Barras de métricas
        bars_card = make_card("Uso Atual")
        bars_layout = QVBoxLayout()
        bars_layout.setSpacing(6)
        self.bar_cpu  = MetricBar("CPU")
        self.bar_ram  = MetricBar("RAM", Colors.SUCCESS)
        self.bar_disk = MetricBar("Disco", Colors.WARNING)
        bars_layout.addWidget(self.bar_cpu)
        bars_layout.addWidget(self.bar_ram)
        bars_layout.addWidget(self.bar_disk)
        bars_layout.addStretch()
        bars_card.setLayout(bars_layout)
        left_layout.addWidget(bars_card)

        splitter.addWidget(left_widget)

        # Coluna direita: info do sistema
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        sysinfo_card = make_card("Informações do Sistema")
        sysinfo_inner = QVBoxLayout()
        sysinfo_inner.setSpacing(0)

        self.sysinfo_rows: Dict[str, QLabel] = {}
        fields = [
            ("Hostname",       "hostname"),
            ("Sistema Op.",    "os"),
            ("Arquitetura",    "arch"),
            ("CPU",            "cpu_model"),
            ("Núcleos Fís.",   "cpu_physical"),
            ("Núcleos Lóg.",   "cpu_logical"),
            ("RAM Total",      "ram_total"),
            ("IP Local",       "ip"),
            ("MAC",            "mac"),
            ("Boot",           "boot_time"),
        ]
        for label_text, key in fields:
            row = QHBoxLayout()
            row.setContentsMargins(0, 3, 0, 3)
            lbl = make_label(label_text, color=Colors.TEXT_SECONDARY, size=11)
            lbl.setFixedWidth(110)
            val = make_label("—", color=Colors.TEXT_PRIMARY, size=11)
            val.setWordWrap(True)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            self.sysinfo_rows[key] = val
            sysinfo_inner.addLayout(row)
            sysinfo_inner.addWidget(make_separator())

        sysinfo_card.setLayout(sysinfo_inner)
        right_layout.addWidget(sysinfo_card)

        # Histórico de ping
        ping_card = make_card("Latência")
        ping_layout = QVBoxLayout()
        self.ping_chart = LineChartWidget("Ping", "ms", "#FF8C00", max_val=200.0)
        self.ping_chart.setMinimumHeight(70)
        ping_layout.addWidget(self.ping_chart)
        ping_card.setLayout(ping_layout)
        right_layout.addWidget(ping_card)

        right_layout.addStretch()
        splitter.addWidget(right_widget)
        splitter.setSizes([600, 350])

        self.main_layout.addWidget(splitter, 1)

        # Timer de auto-refresh
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start(5000)

    def _connect_signals(self) -> None:
        self.manager.sig_metrics.connect(self._on_metrics)
        self.manager.sig_sys_info.connect(self._on_sys_info)
        self.manager.sig_heartbeat.connect(self._on_heartbeat)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._refresh()
            # Preencher dados do histórico já existente
            ci = self.manager.get_client_info(client_id)
            if ci:
                for v in ci.cpu_history:
                    self.cpu_chart.push(v)
                for v in ci.ram_history:
                    self.ram_chart.push(v)
                for v in ci.ping_history:
                    self.ping_chart.push(v)
        else:
            self._clear_display()

    def _clear_display(self) -> None:
        self.cpu_chart.clear_data()
        self.ram_chart.clear_data()
        self.ping_chart.clear_data()
        for val_lbl in self.sysinfo_rows.values():
            val_lbl.setText("—")
        self.card_cpu.set_value("—")
        self.card_ram.set_value("—")
        self.card_disk.set_value("—")
        self.card_uptime.set_value("—")
        self.card_procs.set_value("—")
        self.card_ping.set_value("—")

    @Slot()
    def _refresh(self) -> None:
        worker = self.get_worker()
        if worker:
            worker.request_metrics()
            worker.request_sys_info()

    @Slot(bool)
    def _toggle_auto_refresh(self, checked: bool) -> None:
        if checked:
            self._change_interval(self.interval_combo.currentText())
        else:
            self._refresh_timer.stop()

    @Slot(str)
    def _change_interval(self, text: str) -> None:
        intervals = {"5s": 5000, "10s": 10000, "30s": 30000}
        ms = intervals.get(text, 5000)
        self._refresh_timer.setInterval(ms)
        if self.auto_refresh_cb.isChecked():
            self._refresh_timer.start()

    @Slot(str, dict)
    def _on_metrics(self, client_id: str, data: dict) -> None:
        if client_id != self._active_client:
            return
        cpu = data.get("cpu", 0.0)
        ram_pct = data.get("ram_percent", 0.0)
        ram_used = data.get("ram_used", 0)
        ram_total = data.get("ram_total", 0)
        disk_pct = data.get("disk_percent", 0.0)
        disk_used = data.get("disk_used", 0)
        disk_total = data.get("disk_total", 0)
        procs = data.get("process_count", 0)
        uptime = data.get("uptime", 0)

        self.cpu_chart.push(cpu)
        self.ram_chart.push(ram_pct)

        self.bar_cpu.set_value(cpu, f"{cpu:.1f}%")
        self.bar_ram.set_value(ram_pct, f"{format_bytes(ram_used)} / {format_bytes(ram_total)}")
        self.bar_disk.set_value(disk_pct, f"{format_bytes(disk_used)} / {format_bytes(disk_total)}")

        self.card_cpu.set_value(f"{cpu:.1f}%", color=pct_color(cpu))
        self.card_ram.set_value(f"{ram_pct:.1f}%", sub=format_bytes(ram_used), color=pct_color(ram_pct))
        self.card_disk.set_value(f"{disk_pct:.1f}%", sub=format_bytes(disk_used), color=pct_color(disk_pct))
        self.card_uptime.set_value(format_uptime(uptime))
        self.card_procs.set_value(str(procs))

    @Slot(str, dict)
    def _on_sys_info(self, client_id: str, data: dict) -> None:
        if client_id != self._active_client:
            return
        mapping = {
            "hostname":     data.get("hostname", "—"),
            "os":           data.get("os", "—"),
            "arch":         data.get("arch", "—"),
            "cpu_model":    data.get("cpu_model", "—"),
            "cpu_physical": str(data.get("cpu_physical", "—")),
            "cpu_logical":  str(data.get("cpu_logical", "—")),
            "ram_total":    format_bytes(data.get("ram_total", 0)),
            "ip":           data.get("ip", "—"),
            "mac":          data.get("mac", "—"),
            "boot_time":    data.get("boot_time", "—"),
        }
        for key, val in mapping.items():
            lbl = self.sysinfo_rows.get(key)
            if lbl:
                lbl.setText(val)

    @Slot(str, float)
    def _on_heartbeat(self, client_id: str, ping_ms: float) -> None:
        if client_id != self._active_client:
            return
        self.ping_chart.push(min(ping_ms, 200.0))
        color = Colors.SUCCESS if ping_ms < 50 else Colors.WARNING if ping_ms < 150 else Colors.ERROR
        self.card_ping.set_value(f"{ping_ms:.1f}ms", color=color)


# ─────────────────────────────────────────────────────────────────────────────
# MODELO DE TABELA DE PROCESSOS
# ─────────────────────────────────────────────────────────────────────────────
class ProcessTableModel(QAbstractTableModel):
    """Modelo de dados para a tabela de processos."""
    COLUMNS = ["PID", "Nome", "Status", "CPU%", "RAM (MB)", "Usuário", "Threads"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[dict] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._data):
            return None
        row = self._data[index.row()]
        col = index.column()
        keys = ["pid", "name", "status", "cpu_percent", "memory_mb", "username", "num_threads"]
        if role == Qt.DisplayRole:
            val = row.get(keys[col], "")
            if col == 3:  # CPU
                return f"{float(val):.1f}" if val else "0.0"
            if col == 4:  # RAM MB
                return f"{float(val):.1f}" if val else "0.0"
            return str(val)
        if role == Qt.ForegroundRole:
            if col == 2:  # Status
                status = row.get("status", "")
                if status == "running":
                    return QColor(Colors.SUCCESS)
                if status in ("sleeping", "disk-sleep"):
                    return QColor(Colors.TEXT_MUTED)
                if status in ("stopped", "zombie"):
                    return QColor(Colors.ERROR)
            if col == 3:  # CPU alto
                try:
                    v = float(row.get("cpu_percent", 0))
                    if v >= 80:
                        return QColor(Colors.ERROR)
                    if v >= 40:
                        return QColor(Colors.WARNING)
                except Exception:
                    pass
        if role == Qt.BackgroundRole:
            if index.row() % 2 == 1:
                return QColor(Colors.TABLE_ALT)
        if role == Qt.TextAlignmentRole:
            if col in (0, 3, 4, 6):
                return Qt.AlignCenter
        return None

    def update_data(self, processes: List[dict]) -> None:
        self.beginResetModel()
        self._data = processes
        self.endResetModel()

    def get_row_data(self, row: int) -> Optional[dict]:
        if 0 <= row < len(self._data):
            return self._data[row]
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: PROCESSOS
# ─────────────────────────────────────────────────────────────────────────────
class ProcessesPage(BasePage):
    """Página de gerenciamento de processos do client."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = make_label("Processos", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()

        self.auto_cb = QCheckBox("Auto-refresh")
        self.auto_cb.setChecked(False)
        self.auto_cb.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        self.auto_cb.toggled.connect(self._toggle_auto)
        header.addWidget(self.auto_cb)

        refresh_btn = make_button("⟳ Atualizar")
        refresh_btn.setShortcut(QKeySequence("F5"))
        refresh_btn.clicked.connect(self._refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        # Banner
        self.banner_layout = QVBoxLayout()
        self.banner_layout.setSpacing(4)
        layout.addLayout(self.banner_layout)

        # Toolbar de ações
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Filtrar por nome ou PID...")
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
                min-width: 220px;
            }}
        """)
        self.search_input.textChanged.connect(self._filter_changed)
        toolbar.addWidget(self.search_input)

        toolbar.addStretch()

        self.kill_btn = make_button("✕ Encerrar", danger=True, tooltip="Matar processo selecionado (Delete)")
        self.kill_btn.setShortcut(QKeySequence("Delete"))
        self.kill_btn.clicked.connect(self._kill_selected)
        toolbar.addWidget(self.kill_btn)

        self.suspend_btn = make_button("⏸ Suspender", tooltip="Suspender processo selecionado")
        self.suspend_btn.clicked.connect(self._suspend_selected)
        toolbar.addWidget(self.suspend_btn)

        self.resume_btn = make_button("▶ Retomar", tooltip="Retomar processo suspenso")
        self.resume_btn.clicked.connect(self._resume_selected)
        toolbar.addWidget(self.resume_btn)

        layout.addLayout(toolbar)

        # Tabela
        self._model = ProcessTableModel()
        class _ProcFilter(QSortFilterProxyModel):
            def filterAcceptsRow(self, source_row, source_parent):
                text = self.filterRegularExpression().pattern().lower()
                if not text:
                    return True
                model = self.sourceModel()
                for col in range(model.columnCount()):
                    idx = model.index(source_row, col, source_parent)
                    if text in str(model.data(idx) or "").lower():
                        return True
                return False

        self._proxy = _ProcFilter()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)

        self.table = QTableView()
        self.table.setModel(self._proxy)
        self.table.setStyleSheet(f"""
            QTableView {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                gridline-color: {Colors.BORDER};
                font-size: 12px;
                selection-background-color: {Colors.ACCENT};
                selection-color: white;
            }}
            QHeaderView::section {{
                background: {Colors.BG_BASE};
                color: {Colors.TEXT_SECONDARY};
                border: none;
                border-right: 1px solid {Colors.BORDER};
                border-bottom: 1px solid {Colors.BORDER};
                padding: 6px 8px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.table, 1)

        # Status bar
        self.status_lbl = make_label("", color=Colors.TEXT_MUTED, size=10)
        layout.addWidget(self.status_lbl)

        # Timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)

    def _connect_signals(self) -> None:
        self.manager.sig_proc_list.connect(self._on_proc_list)
        self.manager.sig_proc_result.connect(self._on_proc_result)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._refresh()

    @Slot()
    def _refresh(self) -> None:
        worker = self.get_worker()
        if worker:
            worker.request_proc_list()

    @Slot(bool)
    def _toggle_auto(self, checked: bool) -> None:
        if checked:
            self._timer.start(5000)
        else:
            self._timer.stop()

    @Slot(str)
    def _filter_changed(self, text: str) -> None:
        self._proxy.setFilterRegularExpression(text)

    @Slot(str, list)
    def _on_proc_list(self, client_id: str, processes: list) -> None:
        if client_id != self._active_client:
            return
        self._model.update_data(processes)
        self.status_lbl.setText(f"{len(processes)} processos | Atualizado: {datetime.datetime.now().strftime('%H:%M:%S')}")

    @Slot(str, str, bool, str)
    def _on_proc_result(self, client_id: str, action: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        level = "success" if ok else "error"
        actions = {"kill": "Processo encerrado", "suspend": "Processo suspenso", "resume": "Processo retomado"}
        txt = f"{actions.get(action, action)}: {msg}"
        self._show_notification(self.banner_layout, txt, level)
        if ok:
            self._refresh()

    def _get_selected_pid(self) -> Optional[int]:
        idx = self.table.selectionModel().currentIndex()
        if not idx.isValid():
            return None
        src_idx = self._proxy.mapToSource(idx)
        row_data = self._model.get_row_data(src_idx.row())
        if row_data:
            return int(row_data.get("pid", 0))
        return None

    def _kill_selected(self) -> None:
        if self._no_client_msg():
            return
        pid = self._get_selected_pid()
        if not pid:
            return
        ans = QMessageBox.question(self, "Confirmar", f"Encerrar processo PID {pid}?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            ans2 = QMessageBox.question(self, "Confirmar", f"Confirmar encerramento forçado do PID {pid}?",
                                        QMessageBox.Yes | QMessageBox.No)
            if ans2 == QMessageBox.Yes:
                self.get_worker().request_proc_kill(pid)

    def _suspend_selected(self) -> None:
        if self._no_client_msg():
            return
        pid = self._get_selected_pid()
        if pid:
            self.get_worker().request_proc_suspend(pid)

    def _resume_selected(self) -> None:
        if self._no_client_msg():
            return
        pid = self._get_selected_pid()
        if pid:
            self.get_worker().request_proc_resume(pid)

    def _on_double_click(self, index: QModelIndex) -> None:
        src_idx = self._proxy.mapToSource(index)
        row = self._model.get_row_data(src_idx.row())
        if row:
            info = "\n".join(f"{k}: {v}" for k, v in row.items())
            QMessageBox.information(self, f"PID {row.get('pid', '?')}", info)

    def _show_context_menu(self, pos: QPoint) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        src_idx = self._proxy.mapToSource(idx)
        row = self._model.get_row_data(src_idx.row())
        if not row:
            return
        pid = row.get("pid", 0)
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background: {Colors.BG_WHITE}; border: 1px solid {Colors.BORDER}; padding: 4px; font-size: 12px; }}
            QMenu::item {{ padding: 6px 16px; border-radius: 3px; }}
            QMenu::item:selected {{ background: {Colors.ACCENT}; color: white; }}
        """)
        kill_act = menu.addAction(f"✕ Encerrar PID {pid}")
        susp_act = menu.addAction(f"⏸ Suspender PID {pid}")
        resu_act = menu.addAction(f"▶ Retomar PID {pid}")
        menu.addSeparator()
        info_act = menu.addAction("ℹ Detalhes")
        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == kill_act:
            self._kill_selected()
        elif action == susp_act:
            self._suspend_selected()
        elif action == resu_act:
            self._resume_selected()
        elif action == info_act:
            self._on_double_click(idx)


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: ARQUIVOS
# ─────────────────────────────────────────────────────────────────────────────
class FilesPage(BasePage):
    """Página de navegação e gerenciamento de arquivos do client."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = make_label("Arquivos", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        # Banners
        self.banner_layout = QVBoxLayout()
        layout.addLayout(self.banner_layout)

        # Barra de navegação
        nav_bar = QHBoxLayout()
        nav_bar.setSpacing(4)

        self.back_btn = make_button("◀", tooltip="Voltar")
        self.back_btn.setFixedWidth(36)
        self.back_btn.clicked.connect(self._go_back)
        nav_bar.addWidget(self.back_btn)

        self.fwd_btn = make_button("▶", tooltip="Avançar")
        self.fwd_btn.setFixedWidth(36)
        self.fwd_btn.clicked.connect(self._go_forward)
        nav_bar.addWidget(self.fwd_btn)

        home_btn = make_button("⌂", tooltip="Home do usuário")
        home_btn.setFixedWidth(36)
        home_btn.clicked.connect(self._go_home)
        nav_bar.addWidget(home_btn)

        root_btn = make_button("/", tooltip="Raiz do sistema")
        root_btn.setFixedWidth(36)
        root_btn.clicked.connect(self._go_root)
        nav_bar.addWidget(root_btn)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Caminho...")
        self.path_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
                font-family: Consolas, monospace;
            }}
        """)
        self.path_input.returnPressed.connect(self._navigate_to_path)
        nav_bar.addWidget(self.path_input, 1)

        refresh_btn = make_button("⟳", tooltip="Atualizar listagem")
        refresh_btn.setFixedWidth(36)
        refresh_btn.setShortcut(QKeySequence("F5"))
        refresh_btn.clicked.connect(self._refresh)
        nav_bar.addWidget(refresh_btn)

        layout.addLayout(nav_bar)

        # Barra de ações
        action_bar = QHBoxLayout()
        action_bar.setSpacing(6)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Buscar...")
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
                max-width: 180px;
            }}
        """)
        action_bar.addWidget(self.search_input)
        search_btn = make_button("Buscar")
        search_btn.clicked.connect(self._search)
        action_bar.addWidget(search_btn)

        action_bar.addStretch()

        self.upload_btn = make_button("⬆ Upload", primary=True, tooltip="Enviar arquivo para o client")
        self.upload_btn.clicked.connect(self._upload_file)
        action_bar.addWidget(self.upload_btn)

        self.download_btn = make_button("⬇ Download", tooltip="Baixar arquivo do client")
        self.download_btn.clicked.connect(self._download_file)
        action_bar.addWidget(self.download_btn)

        self.read_btn = make_button("👁 Ler", tooltip="Ler conteúdo do arquivo texto")
        self.read_btn.clicked.connect(self._read_file)
        action_bar.addWidget(self.read_btn)

        self.mkdir_btn = make_button("📁 Nova Pasta")
        self.mkdir_btn.clicked.connect(self._mkdir)
        action_bar.addWidget(self.mkdir_btn)

        self.rename_btn = make_button("✏ Renomear")
        self.rename_btn.clicked.connect(self._rename)
        action_bar.addWidget(self.rename_btn)

        self.delete_btn = make_button("🗑 Deletar", danger=True)
        self.delete_btn.setShortcut(QKeySequence("Delete"))
        self.delete_btn.clicked.connect(self._delete)
        action_bar.addWidget(self.delete_btn)

        layout.addLayout(action_bar)

        # Splitter: lista de arquivos + painel de detalhes
        splitter = QSplitter(Qt.Horizontal)

        # Lista de arquivos
        self.file_list = QTreeWidget()
        self.file_list.setHeaderLabels(["Nome", "Tipo", "Tamanho", "Modificado"])
        self.file_list.setStyleSheet(f"""
            QTreeWidget {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                font-size: 12px;
                outline: none;
            }}
            QTreeWidget::item:selected {{
                background: {Colors.ACCENT};
                color: white;
                border-radius: 2px;
            }}
            QTreeWidget::item:hover:!selected {{
                background: #EBF3FC;
            }}
            QHeaderView::section {{
                background: {Colors.BG_BASE};
                border: none;
                border-right: 1px solid {Colors.BORDER};
                border-bottom: 1px solid {Colors.BORDER};
                padding: 5px 8px;
                font-size: 11px;
                font-weight: 600;
                color: {Colors.TEXT_SECONDARY};
            }}
        """)
        self.file_list.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.file_list.itemDoubleClicked.connect(self._on_item_double_click)
        self.file_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self._file_context_menu)
        self.file_list.itemSelectionChanged.connect(self._on_selection_changed)
        splitter.addWidget(self.file_list)

        # Painel de detalhes
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(8, 0, 0, 0)
        details_layout.setSpacing(8)
        details_widget.setMinimumWidth(200)
        details_widget.setMaximumWidth(280)

        details_card = make_card("Detalhes")
        details_inner = QVBoxLayout()
        details_inner.setSpacing(6)

        self.detail_icon = make_label("📄", size=28, align=Qt.AlignCenter)
        details_inner.addWidget(self.detail_icon)

        self.detail_name = make_label("—", bold=True, size=12, align=Qt.AlignCenter)
        self.detail_name.setWordWrap(True)
        details_inner.addWidget(self.detail_name)

        details_inner.addWidget(make_separator())

        self.detail_fields: Dict[str, QLabel] = {}
        for key in ["Tipo", "Tamanho", "Modificado", "Criado", "Permissões"]:
            row = QHBoxLayout()
            kl = make_label(key, color=Colors.TEXT_MUTED, size=10)
            kl.setFixedWidth(80)
            vl = make_label("—", size=10)
            vl.setWordWrap(True)
            row.addWidget(kl)
            row.addWidget(vl, 1)
            details_inner.addLayout(row)
            self.detail_fields[key] = vl

        details_inner.addStretch()

        # Barra de progresso para upload/download
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                background: {Colors.BG_BASE};
                height: 12px;
            }}
            QProgressBar::chunk {{
                background: {Colors.ACCENT};
                border-radius: 3px;
            }}
        """)
        details_inner.addWidget(self.progress_bar)

        details_card.setLayout(details_inner)
        details_layout.addWidget(details_card)
        details_layout.addStretch()
        splitter.addWidget(details_widget)
        splitter.setSizes([700, 250])

        layout.addWidget(splitter, 1)

        # Histórico de navegação
        self._history: List[str] = []
        self._history_idx: int = -1
        self._current_path: str = "/"
        self._current_entries: List[dict] = []

    def _connect_signals(self) -> None:
        self.manager.sig_file_list.connect(self._on_file_list)
        self.manager.sig_file_download.connect(self._on_file_download)
        self.manager.sig_file_upload_res.connect(self._on_upload_res)
        self.manager.sig_file_delete_res.connect(self._on_delete_res)
        self.manager.sig_file_rename_res.connect(self._on_rename_res)
        self.manager.sig_file_mkdir_res.connect(self._on_mkdir_res)
        self.manager.sig_file_read_res.connect(self._on_read_res)
        self.manager.sig_file_search_res.connect(self._on_search_res)
        self.manager.sig_file_move_res.connect(self._on_move_res)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._navigate("/")

    def _navigate(self, path: str, add_history: bool = True) -> None:
        worker = self.get_worker()
        if not worker:
            return
        self._current_path = path
        self.path_input.setText(path)
        worker.request_file_list(path)
        if add_history:
            if self._history_idx < len(self._history) - 1:
                self._history = self._history[:self._history_idx + 1]
            self._history.append(path)
            self._history_idx = len(self._history) - 1
        self._update_nav_buttons()

    def _update_nav_buttons(self) -> None:
        self.back_btn.setEnabled(self._history_idx > 0)
        self.fwd_btn.setEnabled(self._history_idx < len(self._history) - 1)

    def _go_back(self) -> None:
        if self._history_idx > 0:
            self._history_idx -= 1
            self._navigate(self._history[self._history_idx], add_history=False)

    def _go_forward(self) -> None:
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            self._navigate(self._history[self._history_idx], add_history=False)

    def _go_home(self) -> None:
        self._navigate("~")

    def _go_root(self) -> None:
        root = "C:\\" if platform.system() == "Windows" else "/"
        self._navigate(root)

    def _navigate_to_path(self) -> None:
        path = self.path_input.text().strip()
        if path:
            self._navigate(path)

    def _refresh(self) -> None:
        self._navigate(self._current_path, add_history=False)

    def _search(self) -> None:
        if self._no_client_msg():
            return
        query = self.search_input.text().strip()
        if not query:
            return
        self.get_worker().request_file_search(self._current_path, query)

    @Slot(str, str, list)
    def _on_file_list(self, client_id: str, path: str, entries: list) -> None:
        if client_id != self._active_client:
            return
        self._current_entries = entries
        self._current_path = path
        self.path_input.setText(path)
        self.file_list.clear()
        for entry in sorted(entries, key=lambda e: (0 if e.get("is_dir") else 1, e.get("name", "").lower())):
            item = QTreeWidgetItem()
            name = entry.get("name", "")
            is_dir = entry.get("is_dir", False)
            size = entry.get("size", 0)
            modified = entry.get("modified", "")
            entry_type = "Pasta" if is_dir else "Arquivo"
            item.setText(0, ("📁 " if is_dir else "📄 ") + name)
            item.setText(1, entry_type)
            item.setText(2, format_bytes(size) if not is_dir else "")
            item.setText(3, modified)
            item.setData(0, Qt.UserRole, entry)
            self.file_list.addTopLevelItem(item)

    @Slot(QTreeWidgetItem)
    def _on_item_double_click(self, item: QTreeWidgetItem) -> None:
        entry = item.data(0, Qt.UserRole)
        if not entry:
            return
        if entry.get("is_dir"):
            import posixpath
            new_path = entry.get("full_path") or posixpath.join(self._current_path, entry["name"])
            self._navigate(new_path)

    def _on_selection_changed(self) -> None:
        items = self.file_list.selectedItems()
        if not items:
            return
        entry = items[0].data(0, Qt.UserRole)
        if not entry:
            return
        self.detail_name.setText(entry.get("name", "—"))
        is_dir = entry.get("is_dir", False)
        self.detail_icon.setText("📁" if is_dir else "📄")
        self.detail_fields["Tipo"].setText("Pasta" if is_dir else "Arquivo")
        size = entry.get("size", 0)
        self.detail_fields["Tamanho"].setText(format_bytes(size) if not is_dir else "—")
        self.detail_fields["Modificado"].setText(str(entry.get("modified", "—")))
        self.detail_fields["Criado"].setText(str(entry.get("created", "—")))
        self.detail_fields["Permissões"].setText(str(entry.get("permissions", "—")))

    def _get_selected_entry(self) -> Optional[dict]:
        items = self.file_list.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.UserRole)

    def _upload_file(self) -> None:
        if self._no_client_msg():
            return
        fnames, _ = QFileDialog.getOpenFileNames(self, "Selecionar Arquivos para Upload")
        if not fnames:
            return
        worker = self.get_worker()
        for fname in fnames:
            try:
                with open(fname, "rb") as f:
                    data = f.read()
                filename = Path(fname).name
                worker.request_file_upload(self._current_path, filename, data)
                self._show_notification(self.banner_layout, f"Enviando: {filename}...", "info")
            except Exception as e:
                self._show_notification(self.banner_layout, f"Erro ao ler {fname}: {e}", "error")

    def _download_file(self) -> None:
        if self._no_client_msg():
            return
        entry = self._get_selected_entry()
        if not entry or entry.get("is_dir"):
            QMessageBox.warning(self, "Aviso", "Selecione um arquivo para download.")
            return
        full_path = entry.get("full_path") or f"{self._current_path}/{entry['name']}"
        self.get_worker().request_file_download(full_path)
        self._show_notification(self.banner_layout, f"Baixando: {entry['name']}...", "info")

    def _read_file(self) -> None:
        if self._no_client_msg():
            return
        entry = self._get_selected_entry()
        if not entry or entry.get("is_dir"):
            QMessageBox.warning(self, "Aviso", "Selecione um arquivo texto.")
            return
        full_path = entry.get("full_path") or f"{self._current_path}/{entry['name']}"
        self.get_worker().request_file_read(full_path)

    def _mkdir(self) -> None:
        if self._no_client_msg():
            return
        name, ok = QInputDialog.getText(self, "Nova Pasta", "Nome da pasta:")
        if ok and name.strip():
            self.get_worker().request_file_mkdir(self._current_path, name.strip())

    def _rename(self) -> None:
        if self._no_client_msg():
            return
        entry = self._get_selected_entry()
        if not entry:
            return
        old_path = entry.get("full_path") or f"{self._current_path}/{entry['name']}"
        new_name, ok = QInputDialog.getText(self, "Renomear", "Novo nome:", text=entry["name"])
        if ok and new_name.strip():
            self.get_worker().request_file_rename(old_path, new_name.strip())

    def _delete(self) -> None:
        if self._no_client_msg():
            return
        entry = self._get_selected_entry()
        if not entry:
            return
        name = entry.get("name", "?")
        ans = QMessageBox.question(self, "Deletar", f"Deletar '{name}'?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            ans2 = QMessageBox.question(self, "Confirmar", f"Confirmar deleção definitiva de '{name}'?",
                                        QMessageBox.Yes | QMessageBox.No)
            if ans2 == QMessageBox.Yes:
                full_path = entry.get("full_path") or f"{self._current_path}/{name}"
                self.get_worker().request_file_delete(full_path)

    @Slot(str, str, bytes)
    def _on_file_download(self, client_id: str, filename: str, data: bytes) -> None:
        if client_id != self._active_client:
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Arquivo", filename)
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(data)
                self._show_notification(self.banner_layout, f"Arquivo salvo: {save_path}", "success")
            except Exception as e:
                self._show_notification(self.banner_layout, f"Erro ao salvar: {e}", "error")

    @Slot(str, bool, str)
    def _on_upload_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        self._show_notification(self.banner_layout, msg, "success" if ok else "error")
        if ok:
            self._refresh()

    @Slot(str, bool, str)
    def _on_delete_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        self._show_notification(self.banner_layout, msg, "success" if ok else "error")
        if ok:
            self._refresh()

    @Slot(str, bool, str)
    def _on_rename_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        self._show_notification(self.banner_layout, msg, "success" if ok else "error")
        if ok:
            self._refresh()

    @Slot(str, bool, str)
    def _on_mkdir_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        self._show_notification(self.banner_layout, msg, "success" if ok else "error")
        if ok:
            self._refresh()

    @Slot(str, str, str)
    def _on_read_res(self, client_id: str, filename: str, content: str) -> None:
        if client_id != self._active_client:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Arquivo: {filename}")
        dlg.resize(700, 500)
        layout = QVBoxLayout(dlg)
        editor = QPlainTextEdit()
        editor.setPlainText(content)
        editor.setReadOnly(True)
        editor.setFont(QFont("Consolas", 10))
        editor.setStyleSheet(f"background: {Colors.BG_WHITE}; color: {Colors.TEXT_PRIMARY}; border: 1px solid {Colors.BORDER};")
        layout.addWidget(editor)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        dlg.exec()

    @Slot(str, list)
    def _on_search_res(self, client_id: str, results: list) -> None:
        if client_id != self._active_client:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Resultados da Busca")
        dlg.resize(600, 400)
        layout = QVBoxLayout(dlg)
        lbl = make_label(f"{len(results)} resultado(s):", bold=True)
        layout.addWidget(lbl)
        lst = QListWidget()
        lst.setStyleSheet(f"font-family: Consolas; font-size: 11px; background: {Colors.BG_WHITE}; border: 1px solid {Colors.BORDER};")
        for r in results:
            item = QListWidgetItem(str(r))
            lst.addItem(item)
        lst.itemDoubleClicked.connect(lambda i: self._navigate(str(i.text())))
        layout.addWidget(lst, 1)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)
        dlg.exec()

    @Slot(str, bool, str)
    def _on_move_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        self._show_notification(self.banner_layout, msg, "success" if ok else "error")
        if ok:
            self._refresh()

    def _file_context_menu(self, pos: QPoint) -> None:
        item = self.file_list.itemAt(pos)
        if not item:
            return
        entry = item.data(0, Qt.UserRole)
        if not entry:
            return
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background: {Colors.BG_WHITE}; border: 1px solid {Colors.BORDER}; padding: 4px; font-size: 12px; }}
            QMenu::item {{ padding: 6px 16px; border-radius: 3px; }}
            QMenu::item:selected {{ background: {Colors.ACCENT}; color: white; }}
        """)
        if not entry.get("is_dir"):
            dl = menu.addAction("⬇ Download")
            rd = menu.addAction("👁 Ler arquivo")
        else:
            dl = rd = None
        rn = menu.addAction("✏ Renomear")
        menu.addSeparator()
        rm = menu.addAction("🗑 Deletar")
        action = menu.exec(self.file_list.viewport().mapToGlobal(pos))
        if action == dl and dl:
            self._download_file()
        elif action == rd and rd:
            self._read_file()
        elif action == rn:
            self._rename()
        elif action == rm:
            self._delete()


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: TERMINAL
# ─────────────────────────────────────────────────────────────────────────────
class TerminalPage(BasePage):
    """Terminal remoto com modo shell persistente e histórico."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = make_label("Terminal Remoto", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()

        clear_btn = make_button("🗑 Limpar")
        clear_btn.clicked.connect(self._clear)
        header.addWidget(clear_btn)

        layout.addLayout(header)

        # Área de output
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 11))
        self.output.setStyleSheet(f"""
            QPlainTextEdit {{
                background: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        self.output.setMaximumBlockCount(5000)
        layout.addWidget(self.output, 1)

        # Linha de entrada
        input_row = QHBoxLayout()
        input_row.setSpacing(6)

        self.prompt_lbl = make_label("$", bold=True, color="#569CD6", size=14)
        self.prompt_lbl.setFixedWidth(16)
        input_row.addWidget(self.prompt_lbl)

        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Digite o comando...")
        self.cmd_input.setFont(QFont("Consolas", 11))
        self.cmd_input.setStyleSheet(f"""
            QLineEdit {{
                background: #252526;
                color: #D4D4D4;
                border: 1px solid #3C3C3C;
                border-radius: 4px;
                padding: 8px 12px;
                font-size: 12px;
            }}
            QLineEdit:focus {{ border-color: {Colors.ACCENT}; }}
        """)
        self.cmd_input.returnPressed.connect(self._send_command)
        self.cmd_input.installEventFilter(self)
        input_row.addWidget(self.cmd_input, 1)

        send_btn = make_button("▶ Executar", primary=True)
        send_btn.clicked.connect(self._send_command)
        input_row.addWidget(send_btn)

        layout.addLayout(input_row)

        self._history: List[str] = []
        self._history_idx: int = -1

        self._append_output("RemoteAdmin Terminal\n" + "─" * 40 + "\n", "#569CD6")

    def _connect_signals(self) -> None:
        self.manager.sig_term_output.connect(self._on_term_output)
        self.manager.sig_term_stream.connect(self._on_term_stream)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._append_output(f"\n[Conectado ao client: {client_id}]\n", "#569CD6")
        else:
            self._append_output("\n[Nenhum client selecionado]\n", Colors.WARNING)

    def eventFilter(self, obj, event) -> bool:
        from PySide6.QtCore import QEvent
        if obj == self.cmd_input and event.type() == QEvent.KeyPress:
            from PySide6.QtGui import QKeyEvent
            key = event.key()
            if key == Qt.Key_Up:
                if self._history and self._history_idx > 0:
                    self._history_idx -= 1
                    self.cmd_input.setText(self._history[self._history_idx])
                return True
            elif key == Qt.Key_Down:
                if self._history_idx < len(self._history) - 1:
                    self._history_idx += 1
                    self.cmd_input.setText(self._history[self._history_idx])
                elif self._history_idx == len(self._history) - 1:
                    self._history_idx = len(self._history)
                    self.cmd_input.clear()
                return True
        return super().eventFilter(obj, event)

    def _send_command(self) -> None:
        if self._no_client_msg():
            return
        cmd = self.cmd_input.text().strip()
        if not cmd:
            return
        self._history.append(cmd)
        self._history_idx = len(self._history)
        self.cmd_input.clear()
        self._append_output(f"\n$ {cmd}\n", "#9CDCFE")
        self.get_worker().request_term_cmd(cmd)

    @Slot(str, str, str)
    def _on_term_output(self, client_id: str, stdout: str, stderr: str) -> None:
        if client_id != self._active_client:
            return
        if stdout:
            self._append_output(stdout, "#D4D4D4")
        if stderr:
            self._append_output(stderr, "#F14C4C")

    @Slot(str, str)
    def _on_term_stream(self, client_id: str, chunk: str) -> None:
        if client_id != self._active_client:
            return
        self._append_output(chunk, "#D4D4D4")

    def _append_output(self, text: str, color: str = "#D4D4D4") -> None:
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def _clear(self) -> None:
        self.output.clear()
        self._append_output("RemoteAdmin Terminal\n" + "─" * 40 + "\n", "#569CD6")


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: TELA REMOTA
# ─────────────────────────────────────────────────────────────────────────────
class ScreenPage(BasePage):
    """Página de visualização de screenshot remoto."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = make_label("Tela Remota", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()

        self.fps_lbl = make_label("FPS: —", color=Colors.TEXT_MUTED, size=10)
        header.addWidget(self.fps_lbl)
        self.latency_lbl = make_label("Latência: —", color=Colors.TEXT_MUTED, size=10)
        header.addWidget(self.latency_lbl)
        layout.addLayout(header)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        # Screenshot único
        snap_btn = make_button("📷 Screenshot", primary=True)
        snap_btn.clicked.connect(self._take_screenshot)
        toolbar.addWidget(snap_btn)

        # Watch mode
        self.watch_cb = QCheckBox("Modo Watch")
        self.watch_cb.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        self.watch_cb.toggled.connect(self._toggle_watch)
        toolbar.addWidget(self.watch_cb)

        interval_lbl = make_label("Intervalo:", color=Colors.TEXT_MUTED, size=11)
        toolbar.addWidget(interval_lbl)

        self.interval_slider = QSlider(Qt.Horizontal)
        self.interval_slider.setRange(1, 10)
        self.interval_slider.setValue(2)
        self.interval_slider.setFixedWidth(100)
        self.interval_slider.setStyleSheet(f"""
            QSlider::groove:horizontal {{ background: {Colors.BORDER}; height: 4px; border-radius: 2px; }}
            QSlider::handle:horizontal {{ background: {Colors.ACCENT}; width: 14px; height: 14px; border-radius: 7px; margin: -5px 0; }}
            QSlider::sub-page:horizontal {{ background: {Colors.ACCENT}; border-radius: 2px; }}
        """)
        self.interval_slider.valueChanged.connect(self._update_interval_label)
        toolbar.addWidget(self.interval_slider)

        self.interval_lbl = make_label("2s", color=Colors.TEXT_SECONDARY, size=11)
        self.interval_lbl.setFixedWidth(24)
        toolbar.addWidget(self.interval_lbl)

        sep = make_separator(False)
        toolbar.addWidget(sep)

        quality_lbl = make_label("Qualidade:", color=Colors.TEXT_MUTED, size=11)
        toolbar.addWidget(quality_lbl)

        self.quality_combo = QComboBox()
        self.quality_combo.addItems(["Baixa (30)", "Média (60)", "Alta (90)"])
        self.quality_combo.setCurrentIndex(1)
        self.quality_combo.setStyleSheet(f"""
            QComboBox {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
                min-width: 110px;
            }}
        """)
        toolbar.addWidget(self.quality_combo)

        toolbar.addStretch()

        save_btn = make_button("💾 Salvar")
        save_btn.clicked.connect(self._save_screenshot)
        toolbar.addWidget(save_btn)

        fullscreen_btn = make_button("⛶ Tela Cheia (F)")
        fullscreen_btn.clicked.connect(self._fullscreen)
        fullscreen_btn.setShortcut(QKeySequence("F"))
        toolbar.addWidget(fullscreen_btn)

        layout.addLayout(toolbar)

        # Área de imagem com scroll e zoom
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background: #1A1A1A;
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
            }}
        """)

        self.image_label = QLabel("Clique em 'Screenshot' para capturar a tela remota")
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("color: #666666; background: #1A1A1A; font-size: 13px;")
        self.image_label.setMinimumSize(400, 300)
        self.scroll_area.setWidget(self.image_label)
        layout.addWidget(self.scroll_area, 1)

        # Barra de info
        info_bar = QHBoxLayout()
        self.res_lbl = make_label("", color=Colors.TEXT_MUTED, size=10)
        info_bar.addWidget(self.res_lbl)
        info_bar.addStretch()
        self.size_lbl = make_label("", color=Colors.TEXT_MUTED, size=10)
        info_bar.addWidget(self.size_lbl)
        layout.addLayout(info_bar)

        self._current_pixmap: Optional[QPixmap] = None
        self._zoom_factor = 1.0
        self._last_screen_time: float = 0
        self._frame_count: int = 0
        self._fps_timer = QTimer(self)
        self._fps_timer.timeout.connect(self._update_fps)
        self._fps_timer.start(1000)
        self._watch_timer = QTimer(self)
        self._watch_timer.timeout.connect(self._take_screenshot)

        # Scroll zoom
        self.scroll_area.wheelEvent = self._wheel_zoom

    def _connect_signals(self) -> None:
        self.manager.sig_screen_res.connect(self._on_screen_res)
        self.manager.sig_heartbeat.connect(self._on_heartbeat)

    def on_client_changed(self, client_id: str) -> None:
        if not client_id:
            self._watch_cb_stop()

    def _watch_cb_stop(self) -> None:
        self.watch_cb.setChecked(False)
        self._watch_timer.stop()

    def _take_screenshot(self) -> None:
        if self._no_client_msg():
            return
        qualities = [30, 60, 90]
        quality = qualities[self.quality_combo.currentIndex()]
        self._last_screen_time = time.time()
        self.get_worker().request_screenshot(quality)

    def _toggle_watch(self, checked: bool) -> None:
        if checked:
            interval_s = self.interval_slider.value()
            self._watch_timer.start(interval_s * 1000)
            self._take_screenshot()
        else:
            self._watch_timer.stop()

    def _update_interval_label(self, value: int) -> None:
        self.interval_lbl.setText(f"{value}s")
        if self._watch_timer.isActive():
            self._watch_timer.setInterval(value * 1000)

    @Slot(str, bytes)
    def _on_screen_res(self, client_id: str, jpeg_data: bytes) -> None:
        if client_id != self._active_client:
            return
        if not jpeg_data:
            return
        try:
            pixmap = QPixmap()
            pixmap.loadFromData(jpeg_data, "JPEG")
            if pixmap.isNull():
                return
            self._current_pixmap = pixmap
            self._frame_count += 1
            # Calcular latência
            latency = (time.time() - self._last_screen_time) * 1000
            self.latency_lbl.setText(f"Latência: {latency:.0f}ms")
            self.res_lbl.setText(f"Resolução: {pixmap.width()}x{pixmap.height()}")
            self.size_lbl.setText(f"Tamanho: {format_bytes(len(jpeg_data))}")
            self._update_display()
        except Exception as e:
            log.error(f"Erro ao processar screenshot: {e}")

    def _update_display(self) -> None:
        if not self._current_pixmap:
            return
        w = int(self._current_pixmap.width() * self._zoom_factor)
        h = int(self._current_pixmap.height() * self._zoom_factor)
        scaled = self._current_pixmap.scaled(w, h, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.image_label.setPixmap(scaled)
        self.image_label.resize(scaled.width(), scaled.height())

    def _wheel_zoom(self, event) -> None:
        delta = event.angleDelta().y()
        if delta > 0:
            self._zoom_factor = min(4.0, self._zoom_factor * 1.1)
        else:
            self._zoom_factor = max(0.1, self._zoom_factor / 1.1)
        self._update_display()

    def _save_screenshot(self) -> None:
        if not self._current_pixmap:
            QMessageBox.warning(self, "Aviso", "Nenhum screenshot disponível.")
            return
        fname, _ = QFileDialog.getSaveFileName(
            self, "Salvar Screenshot",
            f"screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg",
            "JPEG (*.jpg);;PNG (*.png)"
        )
        if fname:
            self._current_pixmap.save(fname)
            QMessageBox.information(self, "Sucesso", f"Screenshot salvo em:\n{fname}")

    def _fullscreen(self) -> None:
        if not self._current_pixmap:
            return
        dlg = QDialog(self)
        dlg.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        dlg.showFullScreen()
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel()
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("background: black;")
        screen = QApplication.primaryScreen()
        sw, sh = screen.size().width(), screen.size().height()
        scaled = self._current_pixmap.scaled(sw, sh, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        lbl.setPixmap(scaled)
        dlg_layout.addWidget(lbl)
        lbl.mousePressEvent = lambda e: dlg.close()
        dlg.keyPressEvent = lambda e: dlg.close()
        dlg.exec()

    def _update_fps(self) -> None:
        self.fps_lbl.setText(f"FPS: {self._frame_count}")
        self._frame_count = 0

    @Slot(str, float)
    def _on_heartbeat(self, client_id: str, ping_ms: float) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: LOCK DE TELA
# ─────────────────────────────────────────────────────────────────────────────
class LockPage(BasePage):
    """Página de controle do lock de tela do client."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        title = make_label("Lock de Tela", bold=True, size=16)
        layout.addWidget(title)

        self.banner_layout = QVBoxLayout()
        layout.addLayout(self.banner_layout)

        # Card principal
        card = make_card("Controle de Lock")
        card_layout = QVBoxLayout()
        card_layout.setSpacing(12)

        # Status
        status_row = QHBoxLayout()
        status_lbl = make_label("Status:", bold=True, size=13)
        status_row.addWidget(status_lbl)
        self.lock_status = StatusPill("Desbloqueado", "online")
        status_row.addWidget(self.lock_status)
        status_row.addStretch()
        card_layout.addLayout(status_row)

        card_layout.addWidget(make_separator())

        # Senha
        pwd_row = QHBoxLayout()
        pwd_lbl = make_label("Senha de desbloqueio:", size=13)
        pwd_lbl.setFixedWidth(180)
        pwd_row.addWidget(pwd_lbl)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Digite a senha que o usuário deverá usar...")
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 7px 12px;
                font-size: 13px;
                min-width: 250px;
            }}
            QLineEdit:focus {{ border-color: {Colors.ACCENT}; }}
        """)
        pwd_row.addWidget(self.password_input, 1)
        show_pwd_btn = QPushButton("👁")
        show_pwd_btn.setFixedWidth(32)
        show_pwd_btn.setStyleSheet(f"background: transparent; border: 1px solid {Colors.BORDER}; border-radius: 4px; font-size: 14px;")
        show_pwd_btn.setCheckable(True)
        show_pwd_btn.toggled.connect(lambda c: self.password_input.setEchoMode(
            QLineEdit.Normal if c else QLineEdit.Password))
        pwd_row.addWidget(show_pwd_btn)
        card_layout.addLayout(pwd_row)

        # Mensagem customizável
        msg_row = QHBoxLayout()
        msg_lbl = make_label("Mensagem na tela:", size=13)
        msg_lbl.setFixedWidth(180)
        msg_row.addWidget(msg_lbl)
        self.lock_msg_input = QLineEdit()
        self.lock_msg_input.setText("Esta máquina está bloqueada pelo administrador.")
        self.lock_msg_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 7px 12px;
                font-size: 13px;
            }}
            QLineEdit:focus {{ border-color: {Colors.ACCENT}; }}
        """)
        msg_row.addWidget(self.lock_msg_input, 1)
        card_layout.addLayout(msg_row)

        card_layout.addWidget(make_separator())

        # Botões de ação
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.lock_btn = make_button("🔒 Bloquear Tela", primary=True, tooltip="Ativar bloqueio de tela no client")
        self.lock_btn.clicked.connect(self._lock)
        btn_row.addWidget(self.lock_btn)

        self.unlock_btn = make_button("🔓 Desbloquear Remotamente", tooltip="Desbloquear a tela do client via admin")
        self.unlock_btn.clicked.connect(self._unlock)
        btn_row.addWidget(self.unlock_btn)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)

        card.setLayout(card_layout)
        layout.addWidget(card)

        # Info
        info_card = make_card("ℹ Como funciona")
        info_layout = QVBoxLayout()
        info_text = """
• Ao bloquear, o client exibe uma tela em fullscreen que não pode ser fechada normalmente
• O usuário pode digitar a senha configurada aqui para desbloquear
• O administrador pode desbloquear remotamente clicando em "Desbloquear Remotamente"
• A senha é transmitida de forma criptografada (XOR+base64)
• O overlay cobre todos os monitores e captura todas as entradas de teclado
        """.strip()
        info_lbl = QLabel(info_text)
        info_lbl.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px; background: transparent;")
        info_lbl.setWordWrap(True)
        info_layout.addWidget(info_lbl)
        info_card.setLayout(info_layout)
        layout.addWidget(info_card)

        layout.addStretch()

    def _connect_signals(self) -> None:
        self.manager.sig_lock_res.connect(self._on_lock_res)
        self.manager.sig_unlock_res.connect(self._on_unlock_res)

    def _lock(self) -> None:
        if self._no_client_msg():
            return
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Atenção", "Digite uma senha antes de bloquear.")
            return
        message = self.lock_msg_input.text()
        encrypted_pwd = encrypt_password(password)
        self.get_worker().request_lock(encrypted_pwd, message)
        self.lock_status.set_status("warning", "Bloqueando...")

    def _unlock(self) -> None:
        if self._no_client_msg():
            return
        self.get_worker().request_unlock()
        self.lock_status.set_status("warning", "Desbloqueando...")

    @Slot(str, bool, str)
    def _on_lock_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        if ok:
            self.lock_status.set_status("offline", "BLOQUEADO")
            self._show_notification(self.banner_layout, "Tela bloqueada com sucesso", "warning")
        else:
            self.lock_status.set_status("online", "Desbloqueado")
            self._show_notification(self.banner_layout, f"Erro ao bloquear: {msg}", "error")

    @Slot(str, bool, str)
    def _on_unlock_res(self, client_id: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        if ok:
            self.lock_status.set_status("online", "Desbloqueado")
            # Distingue se foi o próprio client que digitou a senha
            if msg.startswith("[CLIENTE]"):
                notif_msg = "🔓 Tela desbloqueada pelo próprio usuário na máquina remota"
                self._show_notification(self.banner_layout, notif_msg, "warning")
            else:
                notif_msg = "🔓 Tela desbloqueada remotamente pelo admin"
                self._show_notification(self.banner_layout, notif_msg, "success")
        else:
            self._show_notification(self.banner_layout, f"Erro ao desbloquear: {msg}", "error")


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: REDE
# ─────────────────────────────────────────────────────────────────────────────
class NetworkPage(BasePage):
    """Página de informações de rede do client."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        header = QHBoxLayout()
        title = make_label("Rede", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()
        refresh_btn = make_button("⟳ Atualizar")
        refresh_btn.setShortcut(QKeySequence("F5"))
        refresh_btn.clicked.connect(self._refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        self.banner_layout = QVBoxLayout()
        layout.addLayout(self.banner_layout)

        splitter = QSplitter(Qt.Vertical)

        # Interfaces de rede
        iface_card = make_card("Interfaces de Rede")
        iface_inner = QVBoxLayout()
        self.iface_table = QTreeWidget()
        self.iface_table.setHeaderLabels(["Interface", "IP", "Máscara", "MAC", "Status", "RX", "TX"])
        self.iface_table.setStyleSheet(f"""
            QTreeWidget {{
                background: {Colors.BG_WHITE};
                border: none;
                font-size: 12px;
            }}
            QHeaderView::section {{
                background: {Colors.BG_BASE};
                border: none;
                border-right: 1px solid {Colors.BORDER};
                border-bottom: 1px solid {Colors.BORDER};
                padding: 5px 8px;
                font-size: 11px;
                font-weight: 600;
                color: {Colors.TEXT_SECONDARY};
            }}
        """)
        self.iface_table.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.iface_table.header().setSectionResizeMode(1, QHeaderView.Stretch)
        iface_inner.addWidget(self.iface_table)
        iface_card.setLayout(iface_inner)
        splitter.addWidget(iface_card)

        # Ping e rotas
        bottom = QWidget()
        bottom_layout = QHBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(10)

        # Ping
        ping_card = make_card("Teste de Ping")
        ping_inner = QVBoxLayout()
        ping_row = QHBoxLayout()
        ping_row.setSpacing(6)
        self.ping_input = QLineEdit("8.8.8.8")
        self.ping_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        ping_row.addWidget(self.ping_input, 1)
        ping_btn = make_button("Pingar", primary=True)
        ping_btn.clicked.connect(self._ping)
        ping_row.addWidget(ping_btn)
        ping_inner.addLayout(ping_row)
        self.ping_result = make_label("—", size=18, bold=True, align=Qt.AlignCenter)
        self.ping_result.setMinimumHeight(60)
        ping_inner.addWidget(self.ping_result)
        self.ping_status = make_label("", color=Colors.TEXT_MUTED, size=11, align=Qt.AlignCenter)
        ping_inner.addWidget(self.ping_status)
        ping_inner.addStretch()
        ping_card.setLayout(ping_inner)
        bottom_layout.addWidget(ping_card)

        # DNS
        dns_card = make_card("DNS Configurado")
        dns_inner = QVBoxLayout()
        self.dns_list = QListWidget()
        self.dns_list.setStyleSheet(f"""
            QListWidget {{
                background: {Colors.BG_WHITE};
                border: none;
                font-size: 12px;
                font-family: Consolas;
            }}
        """)
        dns_inner.addWidget(self.dns_list)
        dns_card.setLayout(dns_inner)
        bottom_layout.addWidget(dns_card)

        # Rotas
        routes_card = make_card("Rotas de Rede")
        routes_inner = QVBoxLayout()
        self.routes_list = QListWidget()
        self.routes_list.setStyleSheet(f"""
            QListWidget {{
                background: {Colors.BG_WHITE};
                border: none;
                font-size: 11px;
                font-family: Consolas;
            }}
        """)
        routes_inner.addWidget(self.routes_list)
        routes_card.setLayout(routes_inner)
        bottom_layout.addWidget(routes_card)

        splitter.addWidget(bottom)
        splitter.setSizes([300, 200])
        layout.addWidget(splitter, 1)

    def _connect_signals(self) -> None:
        self.manager.sig_net_info.connect(self._on_net_info)
        self.manager.sig_net_ping_res.connect(self._on_ping_res)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._refresh()

    @Slot()
    def _refresh(self) -> None:
        worker = self.get_worker()
        if worker:
            worker.request_net_info()

    @Slot()
    def _ping(self) -> None:
        if self._no_client_msg():
            return
        host = self.ping_input.text().strip()
        if not host:
            return
        self.ping_result.setText("...")
        self.ping_status.setText(f"Pingando {host}...")
        self.get_worker().request_net_ping(host)

    @Slot(str, dict)
    def _on_net_info(self, client_id: str, data: dict) -> None:
        if client_id != self._active_client:
            return
        self.iface_table.clear()
        for iface in data.get("interfaces", []):
            item = QTreeWidgetItem()
            item.setText(0, iface.get("name", ""))
            item.setText(1, iface.get("ip", "—"))
            item.setText(2, iface.get("netmask", "—"))
            item.setText(3, iface.get("mac", "—"))
            status = "Up" if iface.get("up") else "Down"
            item.setText(4, status)
            if iface.get("up"):
                item.setForeground(4, QColor(Colors.SUCCESS))
            else:
                item.setForeground(4, QColor(Colors.ERROR))
            item.setText(5, format_bytes(iface.get("bytes_recv", 0)))
            item.setText(6, format_bytes(iface.get("bytes_sent", 0)))
            self.iface_table.addTopLevelItem(item)

        self.dns_list.clear()
        for dns in data.get("dns", []):
            self.dns_list.addItem(dns)

        self.routes_list.clear()
        for route in data.get("routes", []):
            self.routes_list.addItem(str(route))

    @Slot(str, float)
    def _on_ping_res(self, client_id: str, rtt_ms: float) -> None:
        if client_id != self._active_client:
            return
        host = self.ping_input.text().strip()
        if rtt_ms < 0:
            self.ping_result.setText("Falhou")
            self.ping_result.setStyleSheet(f"color: {Colors.ERROR}; font-size: 18px; font-weight: bold; background: transparent;")
            self.ping_status.setText(f"Host {host} inacessível")
        else:
            self.ping_result.setText(f"{rtt_ms:.1f} ms")
            color = Colors.SUCCESS if rtt_ms < 50 else Colors.WARNING if rtt_ms < 150 else Colors.ERROR
            self.ping_result.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold; background: transparent;")
            self.ping_status.setText(f"RTT para {host}")


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: LOGS
# ─────────────────────────────────────────────────────────────────────────────
class LogsPage(BasePage):
    """Página de visualização dos logs do agente client."""

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = make_label("Logs do Agente", bold=True, size=16)
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        self.banner_layout = QVBoxLayout()
        layout.addLayout(self.banner_layout)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Buscar nos logs...")
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
                min-width: 200px;
            }}
        """)
        self.search_input.textChanged.connect(self._filter_logs)
        toolbar.addWidget(self.search_input)

        level_lbl = make_label("Nível:", color=Colors.TEXT_MUTED, size=11)
        toolbar.addWidget(level_lbl)

        self.level_combo = QComboBox()
        self.level_combo.addItems(["ALL", "DEBUG", "INFO", "WARNING", "ERROR"])
        self.level_combo.setStyleSheet(f"""
            QComboBox {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
                min-width: 90px;
            }}
        """)
        self.level_combo.currentTextChanged.connect(self._filter_logs)
        toolbar.addWidget(self.level_combo)

        toolbar.addStretch()

        refresh_btn = make_button("⟳ Buscar Logs")
        refresh_btn.setShortcut(QKeySequence("F5"))
        refresh_btn.clicked.connect(self._refresh)
        toolbar.addWidget(refresh_btn)

        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 12px;")
        toolbar.addWidget(self.auto_scroll_cb)

        export_btn = make_button("⬇ Exportar .txt")
        export_btn.clicked.connect(self._export)
        toolbar.addWidget(export_btn)

        layout.addLayout(toolbar)

        # Área de log
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        self.log_view.setStyleSheet(f"""
            QPlainTextEdit {{
                background: {Colors.BG_WHITE};
                color: {Colors.TEXT_PRIMARY};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px;
            }}
        """)
        self.log_view.setMaximumBlockCount(10000)
        layout.addWidget(self.log_view, 1)

        self.status_lbl = make_label("", color=Colors.TEXT_MUTED, size=10)
        layout.addWidget(self.status_lbl)

        self._all_logs: List[dict] = []

    def _connect_signals(self) -> None:
        self.manager.sig_log_res.connect(self._on_log_res)
        self.manager.sig_log_stream.connect(self._on_log_stream)

    def on_client_changed(self, client_id: str) -> None:
        if client_id:
            self._refresh()

    @Slot()
    def _refresh(self) -> None:
        worker = self.get_worker()
        if worker:
            level = self.level_combo.currentText()
            if level == "ALL":
                level = "DEBUG"
            worker.request_logs(level, limit=1000)

    @Slot(str, list)
    def _on_log_res(self, client_id: str, entries: list) -> None:
        if client_id != self._active_client:
            return
        self._all_logs = entries
        self._filter_logs()
        self.status_lbl.setText(f"{len(entries)} entradas | {datetime.datetime.now().strftime('%H:%M:%S')}")

    @Slot(str, str, str)
    def _on_log_stream(self, client_id: str, level: str, msg: str) -> None:
        if client_id != self._active_client:
            return
        entry = {"level": level, "msg": msg, "ts": datetime.datetime.now().isoformat()}
        self._all_logs.append(entry)
        self._append_log_entry(entry)

    def _filter_logs(self) -> None:
        self.log_view.clear()
        query = self.search_input.text().lower()
        level_filter = self.level_combo.currentText()
        LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
        min_level = LEVEL_ORDER.get(level_filter, 0) if level_filter != "ALL" else -1
        for entry in self._all_logs:
            lv = entry.get("level", "INFO")
            if min_level >= 0 and LEVEL_ORDER.get(lv, 0) < min_level:
                continue
            text = entry.get("msg", "") + entry.get("ts", "")
            if query and query not in text.lower():
                continue
            self._append_log_entry(entry)

    def _append_log_entry(self, entry: dict) -> None:
        level = entry.get("level", "INFO")
        ts = entry.get("ts", "")
        msg = entry.get("msg", "")
        colors = {
            "DEBUG":   Colors.TEXT_MUTED,
            "INFO":    Colors.TEXT_PRIMARY,
            "WARNING": Colors.WARNING,
            "ERROR":   Colors.ERROR,
        }
        color = colors.get(level, Colors.TEXT_PRIMARY)
        line = f"[{ts}] [{level:8s}] {msg}"
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(line + "\n")
        if self.auto_scroll_cb.isChecked():
            self.log_view.setTextCursor(cursor)
            self.log_view.ensureCursorVisible()

    def _export(self) -> None:
        fname, _ = QFileDialog.getSaveFileName(
            self, "Exportar Logs",
            f"logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Texto (*.txt)"
        )
        if not fname:
            return
        try:
            content = self.log_view.toPlainText()
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            self._show_notification(self.banner_layout, f"Logs exportados: {fname}", "success")
        except Exception as e:
            self._show_notification(self.banner_layout, f"Erro ao exportar: {e}", "error")


# ─────────────────────────────────────────────────────────────────────────────
# PÁGINA: AÇÕES RÁPIDAS
# ─────────────────────────────────────────────────────────────────────────────
class ActionsPage(BasePage):
    """Página de ações rápidas no client."""

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        title = make_label("Ações Rápidas", bold=True, size=16)
        layout.addWidget(title)

        self.banner_layout = QVBoxLayout()
        self.banner_layout.setSpacing(4)
        layout.addLayout(self.banner_layout)

        # ── Clipboard ─────────────────────────────────────────────────────
        clip_card = make_card("📋 Clipboard")
        clip_layout = QVBoxLayout()

        get_row = QHBoxLayout()
        get_btn = make_button("📋 Obter Clipboard do Client", tooltip="Ler conteúdo da área de transferência do client")
        get_btn.clicked.connect(self._get_clipboard)
        get_row.addWidget(get_btn)
        get_row.addStretch()
        clip_layout.addLayout(get_row)

        self.clipboard_display = QTextEdit()
        self.clipboard_display.setReadOnly(True)
        self.clipboard_display.setFixedHeight(70)
        self.clipboard_display.setPlaceholderText("Conteúdo do clipboard do client aparecerá aqui...")
        self.clipboard_display.setStyleSheet(f"""
            QTextEdit {{
                background: {Colors.BG_BASE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px;
                font-family: Consolas;
                font-size: 11px;
            }}
        """)
        clip_layout.addWidget(self.clipboard_display)

        set_row = QHBoxLayout()
        set_row.setSpacing(6)
        self.clipboard_input = QLineEdit()
        self.clipboard_input.setPlaceholderText("Texto para enviar ao clipboard do client...")
        self.clipboard_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        set_row.addWidget(self.clipboard_input, 1)
        set_btn = make_button("Definir Clipboard", primary=True)
        set_btn.clicked.connect(self._set_clipboard)
        set_row.addWidget(set_btn)
        clip_layout.addLayout(set_row)

        clip_card.setLayout(clip_layout)
        layout.addWidget(clip_card)

        # ── Popup de Mensagem ─────────────────────────────────────────────
        popup_card = make_card("💬 Enviar Mensagem Popup")
        popup_layout = QVBoxLayout()
        popup_layout.setSpacing(8)

        title_row = QHBoxLayout()
        title_lbl = make_label("Título:", size=12)
        title_lbl.setFixedWidth(60)
        self.popup_title = QLineEdit("Mensagem do Administrador")
        self.popup_title.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        title_row.addWidget(title_lbl)
        title_row.addWidget(self.popup_title, 1)
        popup_layout.addLayout(title_row)

        body_row = QHBoxLayout()
        body_lbl = make_label("Corpo:", size=12)
        body_lbl.setFixedWidth(60)
        self.popup_body = QTextEdit()
        self.popup_body.setFixedHeight(70)
        self.popup_body.setPlaceholderText("Conteúdo da mensagem...")
        self.popup_body.setStyleSheet(f"""
            QTextEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }}
        """)
        body_row.addWidget(body_lbl)
        body_row.addWidget(self.popup_body, 1)
        popup_layout.addLayout(body_row)

        send_popup_btn = make_button("💬 Enviar Popup", primary=True)
        send_popup_btn.clicked.connect(self._send_popup)
        popup_layout.addWidget(send_popup_btn)
        popup_card.setLayout(popup_layout)
        layout.addWidget(popup_card)

        # ── Abrir URL ────────────────────────────────────────────────────
        url_card = make_card("🌐 Abrir URL no Navegador do Client")
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit("https://")
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 6px 10px;
                font-size: 12px;
            }}
        """)
        url_layout.addWidget(self.url_input, 1)
        open_url_btn = make_button("Abrir URL", primary=True)
        open_url_btn.clicked.connect(self._open_url)
        url_layout.addWidget(open_url_btn)
        url_card.setLayout(url_layout)
        layout.addWidget(url_card)

        # ── Agente ────────────────────────────────────────────────────────
        agent_card = make_card("⚙ Controle do Agente")
        agent_layout = QHBoxLayout()
        agent_layout.setSpacing(10)

        restart_btn = make_button("🔄 Reiniciar Agente", tooltip="Reinicia o processo do agente no client")
        restart_btn.clicked.connect(self._restart_agent)
        agent_layout.addWidget(restart_btn)

        stop_btn = make_button("⏹ Encerrar Agente", danger=True, tooltip="Encerra completamente o agente no client")
        stop_btn.clicked.connect(self._stop_agent)
        agent_layout.addWidget(stop_btn)

        agent_layout.addStretch()
        agent_card.setLayout(agent_layout)
        layout.addWidget(agent_card)

        # ── Desligar/Reiniciar PC ─────────────────────────────────────────
        power_card = make_card("⚡ Controle de Energia")
        power_layout = QHBoxLayout()
        power_layout.setSpacing(10)

        shutdown_btn = make_button("🔴 Desligar PC", danger=True, tooltip="Desligar a máquina do client")
        shutdown_btn.clicked.connect(self._shutdown)
        power_layout.addWidget(shutdown_btn)

        reboot_btn = make_button("🔃 Reiniciar PC", tooltip="Reiniciar a máquina do client")
        reboot_btn.clicked.connect(self._reboot)
        power_layout.addWidget(reboot_btn)

        power_layout.addStretch()

        warn_lbl = make_label("⚠ Use com extrema cautela!", color=Colors.WARNING, size=11)
        power_layout.addWidget(warn_lbl)

        power_card.setLayout(power_layout)
        layout.addWidget(power_card)

        layout.addStretch()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

        self.banner_layout = QVBoxLayout()

    def _connect_signals(self) -> None:
        self.manager.sig_clipboard_res.connect(self._on_clipboard_res)
        self.manager.sig_action_res.connect(self._on_action_res)

    def _get_clipboard(self) -> None:
        if self._no_client_msg():
            return
        self.get_worker().request_clipboard_get()

    def _set_clipboard(self) -> None:
        if self._no_client_msg():
            return
        text = self.clipboard_input.text()
        if text:
            self.get_worker().request_clipboard_set(text)

    def _send_popup(self) -> None:
        if self._no_client_msg():
            return
        title = self.popup_title.text()
        body = self.popup_body.toPlainText()
        if body:
            self.get_worker().request_popup_msg(title, body)

    def _open_url(self) -> None:
        if self._no_client_msg():
            return
        url = self.url_input.text().strip()
        if url:
            self.get_worker().request_open_url(url)

    def _restart_agent(self) -> None:
        if self._no_client_msg():
            return
        ans = QMessageBox.question(self, "Confirmar", "Reiniciar o agente no client?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            self.get_worker().request_restart_agent()

    def _stop_agent(self) -> None:
        if self._no_client_msg():
            return
        ans = QMessageBox.question(self, "Confirmar", "Encerrar o agente no client?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            ans2 = QMessageBox.question(self, "Confirmar", "Confirmar encerramento do agente?",
                                        QMessageBox.Yes | QMessageBox.No)
            if ans2 == QMessageBox.Yes:
                self.get_worker().request_stop_agent()

    def _shutdown(self) -> None:
        if self._no_client_msg():
            return
        for i in range(3):
            ans = QMessageBox.question(self, f"CONFIRMAR ({i+1}/3)",
                                       f"DESLIGAR o PC do client? ({i+1}/3)",
                                       QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        self.get_worker().request_shutdown()

    def _reboot(self) -> None:
        if self._no_client_msg():
            return
        for i in range(3):
            ans = QMessageBox.question(self, f"CONFIRMAR ({i+1}/3)",
                                       f"REINICIAR o PC do client? ({i+1}/3)",
                                       QMessageBox.Yes | QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        self.get_worker().request_reboot()

    @Slot(str, str)
    def _on_clipboard_res(self, client_id: str, content: str) -> None:
        if client_id != self._active_client:
            return
        self.clipboard_display.setPlainText(content)

    @Slot(str, str, bool, str)
    def _on_action_res(self, client_id: str, action: str, ok: bool, msg: str) -> None:
        if client_id != self._active_client:
            return
        level = "success" if ok else "error"
        # Como o banner_layout nesta página foi redefinido no __init__, precisamos
        # de um workaround para mostrar o banner no lugar certo.
        notif = NotificationBanner(f"{action}: {msg}", level)
        # Inserir no layout da página principal
        outer = self.layout()
        if outer:
            outer.insertWidget(0, notif)
            notif.show_timed(5000)


# ─────────────────────────────────────────────────────────────────────────────
# STATUS BAR
# ─────────────────────────────────────────────────────────────────────────────
class AppStatusBar(QStatusBar):
    """Barra de status no rodapé com informações em tempo real."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(24)
        self.setStyleSheet(f"""
            QStatusBar {{
                background: {Colors.BG_BASE};
                border-top: 1px solid {Colors.BORDER};
                color: {Colors.TEXT_MUTED};
                font-size: 10px;
            }}
        """)

        self._client_lbl = QLabel("Sem client ativo")
        self.addWidget(self._client_lbl)

        sep1 = make_separator(False)
        sep1.setFixedHeight(12)
        self.addWidget(sep1)

        self._ping_lbl = QLabel("Latência: —")
        self.addWidget(self._ping_lbl)

        sep2 = make_separator(False)
        sep2.setFixedHeight(12)
        self.addWidget(sep2)

        self._bytes_lbl = QLabel("TX: 0B / RX: 0B")
        self.addWidget(self._bytes_lbl)

        self.addPermanentWidget(QLabel(f" {APP_NAME} v{APP_VERSION} "))

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update)
        self._timer.start(2000)

        self._manager: Optional[ClientManager] = None
        self._active_client: str = ""

    def set_manager(self, manager: ClientManager) -> None:
        self._manager = manager

    def set_active_client(self, client_id: str) -> None:
        self._active_client = client_id

    def _update(self) -> None:
        if not self._manager or not self._active_client:
            self._client_lbl.setText("Sem client ativo")
            self._ping_lbl.setText("Latência: —")
            self._bytes_lbl.setText("TX: 0B / RX: 0B")
            return
        ci = self._manager.get_client_info(self._active_client)
        if not ci:
            return
        self._client_lbl.setText(f"Client: {ci.display_name}")
        self._ping_lbl.setText(f"Latência: {ci.ping_str}")
        self._bytes_lbl.setText(f"TX: {format_bytes(ci.bytes_sent)} / RX: {format_bytes(ci.bytes_recv)}")


# ─────────────────────────────────────────────────────────────────────────────
# JANELA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    """Janela principal do painel de administração remota."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(1280, 720)
        self.resize(1440, 900)

        # Manager de clients
        self.manager = ClientManager(self)
        self._active_client: str = ""
        self._client_history: List[dict] = []

        self._build_ui()
        self._connect_manager_signals()
        self._apply_global_style()
        self._start_server()

    def _apply_global_style(self) -> None:
        """Aplica estilo global à aplicação."""
        QApplication.instance().setStyle(QStyleFactory.create("Fusion"))
        self.setStyleSheet(f"""
            QMainWindow {{ background: {Colors.BG_BASE}; }}
            QDialog {{ background: {Colors.BG_WHITE}; }}
            QMessageBox {{ background: {Colors.BG_WHITE}; }}
            QToolTip {{
                background: #1A1A1A;
                color: white;
                border: 1px solid #333333;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
            }}
            QScrollBar:vertical {{
                background: {Colors.BG_BASE};
                width: 8px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background: #CCCCCC;
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{ background: #AAAAAA; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QScrollBar:horizontal {{
                background: {Colors.BG_BASE};
                height: 8px;
                border: none;
            }}
            QScrollBar::handle:horizontal {{
                background: #CCCCCC;
                border-radius: 4px;
                min-width: 20px;
            }}
            QScrollBar::handle:horizontal:hover {{ background: #AAAAAA; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
            QComboBox QAbstractItemView {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                selection-background-color: {Colors.ACCENT};
                selection-color: white;
                font-size: 12px;
                outline: none;
            }}
            QMenuBar {{
                background: {Colors.TOPBAR_BG};
                color: {Colors.TEXT_PRIMARY};
                border-bottom: 1px solid {Colors.BORDER};
                font-size: 12px;
            }}
            QMenuBar::item:selected {{ background: {Colors.BG_BASE}; border-radius: 3px; }}
            QMenu {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                padding: 4px;
                font-size: 12px;
            }}
            QMenu::item {{ padding: 6px 16px; border-radius: 3px; }}
            QMenu::item:selected {{ background: {Colors.ACCENT}; color: white; }}
            QSplitter::handle {{ background: {Colors.BORDER}; }}
            QCheckBox {{ font-size: 12px; }}
            QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {Colors.BORDER}; border-radius: 3px; background: white; }}
            QCheckBox::indicator:checked {{ background: {Colors.ACCENT}; border-color: {Colors.ACCENT}; }}
        """)

    def _build_ui(self) -> None:
        """Constrói a interface principal."""
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # TopBar
        self.topbar = TopBar()
        self.topbar.client_selected.connect(self._on_client_selected)
        self.topbar.client_close_req.connect(self._on_client_close_req)
        root_layout.addWidget(self.topbar)

        # Conteúdo principal: sidebar + páginas
        content = QWidget()
        content_layout = QHBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.page_changed.connect(self._on_page_changed)
        content_layout.addWidget(self.sidebar)

        # Separador
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color: {Colors.BORDER}; background: {Colors.BORDER}; max-width: 1px;")
        content_layout.addWidget(sep)

        # Stack de páginas
        self.pages = QStackedWidget()
        self.pages.setStyleSheet(f"background: {Colors.BG_BASE};")

        # Criar e registrar páginas
        self._pages: Dict[str, BasePage] = {}
        page_classes = {
            "dashboard": DashboardPage,
            "processes": ProcessesPage,
            "files":     FilesPage,
            "terminal":  TerminalPage,
            "screen":    ScreenPage,
            "lock":      LockPage,
            "network":   NetworkPage,
            "logs":      LogsPage,
            "actions":   ActionsPage,
        }
        for page_id, cls in page_classes.items():
            page = cls(self.manager)
            self._pages[page_id] = page
            self.pages.addWidget(page)

        content_layout.addWidget(self.pages, 1)
        root_layout.addWidget(content, 1)

        # Status bar
        self.status_bar = AppStatusBar()
        self.status_bar.set_manager(self.manager)
        self.setStatusBar(self.status_bar)

        # Menu
        self._build_menu()

        # Iniciar em dashboard
        self.sidebar.switch_to("dashboard")
        self._show_page("dashboard")

        # Tela de boas-vindas se sem client
        self._show_welcome_if_needed()

    def _build_menu(self) -> None:
        """Constrói a barra de menus."""
        menubar = self.menuBar()

        # Arquivo
        file_menu = menubar.addMenu("Arquivo")
        settings_act = QAction("⚙ Configurações", self)
        settings_act.triggered.connect(self._show_settings)
        file_menu.addAction(settings_act)
        file_menu.addSeparator()
        quit_act = QAction("✕ Sair", self)
        quit_act.setShortcut(QKeySequence("Ctrl+Q"))
        quit_act.triggered.connect(self.close)
        file_menu.addAction(quit_act)

        # Ver
        view_menu = menubar.addMenu("Ver")
        for page_id, icon, label in Sidebar.PAGES:
            act = QAction(f"{icon} {label}", self)
            act.triggered.connect(lambda checked, p=page_id: self._on_page_changed(p))
            view_menu.addAction(act)

        # Clients
        clients_menu = menubar.addMenu("Clients")
        disconnect_all = QAction("Desconectar Todos", self)
        disconnect_all.triggered.connect(self._disconnect_all)
        clients_menu.addAction(disconnect_all)
        clients_menu.addSeparator()
        self.clients_menu = clients_menu

        # Ajuda
        help_menu = menubar.addMenu("Ajuda")
        about_act = QAction(f"Sobre {APP_NAME}", self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    def _show_welcome_if_needed(self) -> None:
        """Mostra dica de boas-vindas se não há clients."""
        pass  # A topbar já exibe a mensagem

    @Slot(str)
    def _on_page_changed(self, page_id: str) -> None:
        self._show_page(page_id)
        self.sidebar.switch_to(page_id)

    def _show_page(self, page_id: str) -> None:
        page = self._pages.get(page_id)
        if page:
            self.pages.setCurrentWidget(page)

    @Slot(str)
    def _on_client_selected(self, client_id: str) -> None:
        self._active_client = client_id
        self.status_bar.set_active_client(client_id)
        for page in self._pages.values():
            page.set_active_client(client_id)

    @Slot(str)
    def _on_client_close_req(self, client_id: str) -> None:
        ans = QMessageBox.question(self, "Desconectar",
                                   f"Desconectar client {client_id}?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            self.manager.disconnect_client(client_id)
            self.topbar.remove_client(client_id)

    def _connect_manager_signals(self) -> None:
        """Conecta os signals do ClientManager à UI principal."""
        self.manager.sig_client_connected.connect(self._on_client_connected)
        self.manager.sig_client_disconnected.connect(self._on_client_disconnected)
        self.manager.sig_client_authenticated.connect(self._on_client_authenticated)
        self.manager.sig_server_error.connect(self._on_server_error)
        self.manager.sig_server_started.connect(self._on_server_started)
        self.manager.sig_heartbeat.connect(self._on_heartbeat)
        self.manager.sig_worker_error.connect(self._on_worker_error)

    @Slot(str)
    def _on_client_connected(self, client_id: str) -> None:
        log.info(f"UI: client conectado: {client_id}")
        self.topbar.add_client(client_id, client_id, "")
        self._client_history.append({
            "client_id": client_id,
            "connected_at": datetime.datetime.now().isoformat(),
            "event": "connected"
        })

    @Slot(str, dict)
    def _on_client_authenticated(self, client_id: str, sys_info: dict) -> None:
        hostname = sys_info.get("hostname", client_id)
        ip = sys_info.get("ip", "")
        # Atualizar aba
        for cid, tab in self.topbar._tabs.items():
            if cid == client_id:
                tab.set_hostname(hostname)
                break
        log.info(f"UI: client autenticado: {client_id} — {hostname}")
        # Mostrar notificação global
        self._flash_status(f"Client conectado: {hostname} ({ip})")

    @Slot(str)
    def _on_client_disconnected(self, client_id: str) -> None:
        log.info(f"UI: client desconectado: {client_id}")
        self.topbar.remove_client(client_id)
        self._client_history.append({
            "client_id": client_id,
            "disconnected_at": datetime.datetime.now().isoformat(),
            "event": "disconnected"
        })
        self._flash_status(f"Client desconectado: {client_id}")

    @Slot(str)
    def _on_server_error(self, error: str) -> None:
        log.error(f"Erro no servidor: {error}")
        self.topbar.set_server_offline()
        QMessageBox.critical(self, "Erro no Servidor", f"Falha no servidor TCP:\n{error}")

    @Slot()
    def _on_server_started(self) -> None:
        log.info(f"Servidor iniciado em {LISTEN_HOST}:{LISTEN_PORT}")
        self.status_bar.showMessage(f"Servidor escutando em {LISTEN_HOST}:{LISTEN_PORT}", 5000)

    @Slot(str, float)
    def _on_heartbeat(self, client_id: str, ping_ms: float) -> None:
        ci = self.manager.get_client_info(client_id)
        hostname = ci.hostname if ci else client_id
        self.topbar.update_client(client_id, hostname, ping_ms)

    @Slot(str, str)
    def _on_worker_error(self, client_id: str, error: str) -> None:
        log.warning(f"Erro no worker {client_id}: {error}")

    def _flash_status(self, msg: str) -> None:
        self.status_bar.showMessage(msg, 4000)

    def _start_server(self) -> None:
        """Inicia o servidor TCP."""
        try:
            self.manager.start_server()
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível iniciar o servidor:\n{e}")

    def _disconnect_all(self) -> None:
        """Desconecta todos os clients."""
        ans = QMessageBox.question(self, "Confirmar", "Desconectar todos os clients?",
                                   QMessageBox.Yes | QMessageBox.No)
        if ans == QMessageBox.Yes:
            for ci in self.manager.get_all_clients():
                self.manager.disconnect_client(ci.client_id)
                self.topbar.remove_client(ci.client_id)

    def _show_settings(self) -> None:
        """Dialog de configurações."""
        dlg = SettingsDialog(self)
        dlg.exec()

    def _show_about(self) -> None:
        QMessageBox.about(self, f"Sobre {APP_NAME}",
                          f"""<h3>{APP_NAME} v{APP_VERSION}</h3>
<p>Sistema de administração remota para fins educacionais e de pesquisa.</p>
<p>Uso exclusivo em ambiente de laboratório controlado com consentimento explícito.</p>
<p>Projeto acadêmico — CEH / OSCP / CompTIA Security+</p>
<hr>
<p>Porta: {LISTEN_PORT} | Protocolo: TCP binário | Heartbeat: {HEARTBEAT_INTERVAL}s</p>
""")

    def closeEvent(self, event) -> None:
        """Limpa recursos ao fechar a janela."""
        reply = QMessageBox.question(self, "Sair",
                                     "Deseja encerrar o servidor e desconectar todos os clients?",
                                     QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        if reply == QMessageBox.Cancel:
            event.ignore()
            return
        if reply == QMessageBox.Yes:
            self.manager.stop_server()
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
# DIALOG DE CONFIGURAÇÕES
# ─────────────────────────────────────────────────────────────────────────────
class SettingsDialog(QDialog):
    """Dialog de configurações do admin."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurações")
        self.setFixedSize(500, 380)
        self.setStyleSheet(f"background: {Colors.BG_WHITE};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        title = make_label("Configurações", bold=True, size=16)
        layout.addWidget(title)
        layout.addWidget(make_separator())

        # Rede
        net_card = make_card("Rede")
        net_layout = QVBoxLayout()

        port_row = QHBoxLayout()
        port_lbl = make_label("Porta do Servidor:", size=12)
        port_lbl.setFixedWidth(160)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(LISTEN_PORT)
        self.port_spin.setStyleSheet(f"""
            QSpinBox {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 5px 8px;
                font-size: 12px;
            }}
        """)
        port_row.addWidget(port_lbl)
        port_row.addWidget(self.port_spin)
        port_row.addStretch()
        net_layout.addLayout(port_row)

        token_row = QHBoxLayout()
        token_lbl = make_label("Token de Autenticação:", size=12)
        token_lbl.setFixedWidth(160)
        self.token_input = QLineEdit(AUTH_TOKEN)
        self.token_input.setEchoMode(QLineEdit.Password)
        self.token_input.setStyleSheet(f"""
            QLineEdit {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 5px 8px;
                font-size: 12px;
            }}
        """)
        token_row.addWidget(token_lbl)
        token_row.addWidget(self.token_input, 1)
        net_layout.addLayout(token_row)

        net_card.setLayout(net_layout)
        layout.addWidget(net_card)

        # Heartbeat
        hb_card = make_card("Heartbeat")
        hb_layout = QHBoxLayout()
        hb_lbl = make_label("Intervalo (segundos):", size=12)
        hb_lbl.setFixedWidth(180)
        self.hb_spin = QDoubleSpinBox()
        self.hb_spin.setRange(1.0, 60.0)
        self.hb_spin.setValue(HEARTBEAT_INTERVAL)
        self.hb_spin.setSingleStep(0.5)
        self.hb_spin.setStyleSheet(f"""
            QDoubleSpinBox {{
                background: {Colors.BG_WHITE};
                border: 1px solid {Colors.BORDER};
                border-radius: 4px;
                padding: 5px 8px;
                font-size: 12px;
                min-width: 80px;
            }}
        """)
        hb_layout.addWidget(hb_lbl)
        hb_layout.addWidget(self.hb_spin)
        hb_layout.addStretch()
        hb_card.setLayout(hb_layout)
        layout.addWidget(hb_card)

        layout.addStretch()

        note = make_label("⚠ Alterações de porta e token requerem reinicialização do servidor.",
                          color=Colors.WARNING, size=10)
        note.setWordWrap(True)
        layout.addWidget(note)

        # Botões
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setStyleSheet(f"""
            QPushButton {{
                background: {Colors.ACCENT};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 13px;
            }}
        """)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)


# ─────────────────────────────────────────────────────────────────────────────
# SPLASH SCREEN
# ─────────────────────────────────────────────────────────────────────────────
class SplashScreen(QWidget):
    """Tela de inicialização enquanto o servidor sobe."""

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(400, 240)
        self._center()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(12)

        # Frame com fundo
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {Colors.BG_WHITE};
                border-radius: 12px;
                border: 1px solid {Colors.BORDER};
            }}
        """)
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(24, 24, 24, 24)
        frame_layout.setSpacing(12)

        logo_lbl = make_label(f"● {APP_NAME}", bold=True, size=20, color=Colors.ACCENT, align=Qt.AlignCenter)
        frame_layout.addWidget(logo_lbl)

        version_lbl = make_label(f"v{APP_VERSION}", color=Colors.TEXT_MUTED, size=11, align=Qt.AlignCenter)
        frame_layout.addWidget(version_lbl)

        frame_layout.addSpacing(8)

        self.status_lbl = make_label("Inicializando...", color=Colors.TEXT_SECONDARY, size=12, align=Qt.AlignCenter)
        frame_layout.addWidget(self.status_lbl)

        prog = QProgressBar()
        prog.setRange(0, 0)  # Indeterminado
        prog.setFixedHeight(4)
        prog.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                background: {Colors.BORDER};
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: {Colors.ACCENT};
                border-radius: 2px;
            }}
        """)
        frame_layout.addWidget(prog)

        layout.addWidget(frame)

    def _center(self) -> None:
        screen = QApplication.primaryScreen()
        sg = screen.availableGeometry()
        x = (sg.width() - self.width()) // 2
        y = (sg.height() - self.height()) // 2
        self.move(x, y)

    def set_status(self, msg: str) -> None:
        self.status_lbl.setText(msg)
        QApplication.processEvents()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRADA PRINCIPAL
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    """Ponto de entrada da aplicação."""
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("EduLab")

    # Splash
    splash = SplashScreen()
    splash.show()
    splash.set_status("Carregando interface...")
    QApplication.processEvents()
    time.sleep(0.3)

    splash.set_status("Iniciando servidor TCP...")
    QApplication.processEvents()
    time.sleep(0.2)

    # Janela principal
    window = MainWindow()
    splash.set_status("Pronto!")
    QApplication.processEvents()
    time.sleep(0.3)

    splash.close()
    window.show()

    # Centralizar janela
    screen = QApplication.primaryScreen()
    sg = screen.availableGeometry()
    x = (sg.width() - window.width()) // 2
    y = (sg.height() - window.height()) // 2
    window.move(x, y)

    log.info(f"{APP_NAME} iniciado — PID {os.getpid()}")

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
