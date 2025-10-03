import os
import sys
import json
import time
import base64
import ctypes
import subprocess
import winreg
import win32api
import win32con
import win32security
import win32file
import win32process
import wmi
import pythoncom
from collections import deque, defaultdict
from datetime import datetime, timedelta
from threading import Thread, Event, Lock
from pathlib import Path
from ctypes import wintypes

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from PySide6.QtCore import Qt, QTimer, QSize, Signal, QObject, QPoint
from PySide6.QtGui import QIcon, QFont, QPixmap, QAction, QColor, QPainter, QLinearGradient, QBrush, QPen, QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget,
    QFileDialog, QStackedWidget, QGridLayout, QFrame, QCheckBox, QSpinBox, QMessageBox, QSystemTrayIcon,
    QMenu, QProgressBar, QListWidgetItem, QLineEdit, QGraphicsDropShadowEffect, QScrollArea, QSizePolicy
)

APP_NAME = "FAWKES Antivirus"
CONFIG_PATH = str(Path.home() / ".fawkes_av.json")
LOG_DIR = str(Path.home() / "FAWKES_AV_Logs")
QUAR_DIR = str(Path.home() / "FAWKES_AV_Quarantine")
HONEYPOT_DIR = str(Path.home() / "FAWKES_AV_Honeypots")
DEFAULT_WATCH = [str(Path.home() / "Desktop"), str(Path.home() / "Documents"), 
                str(Path.home() / "Downloads"), str(Path.home() / "Pictures"), 
                str(Path.home() / "Videos")]
WHITELIST_PROCS = {"System","Registry","MemCompression","MsMpEng.exe","SearchIndexer.exe",
                  "svchost.exe","explorer.exe","OneDrive.exe","dllhost.exe",
                  "ShellExperienceHost.exe","TextInputHost.exe","ctfmon.exe",
                  "RuntimeBroker.exe","wininit.exe","winlogon.exe","services.exe",
                  "lsass.exe","csrss.exe","smss.exe"}

PRIMARY_COLOR = "#3ad29f"
BG_DARK = "#15292a"
BG_MEDIUM = "#1f3c3e"
BG_LIGHT = "#f8f8f8"
TEXT_LIGHT = "#ffffff"
TEXT_DARK = "#2c5254"
ACCENT_LIGHT = "#e5f7f3"

b64_logo = "iVBORw0KGgoAAAANSUhEUgAAAZAAAAGQCAYAAADgq2rNAAABf0lEQVR4nO3RMQEAAAwCoNm/9E1gAUEgq4fB1yAAAO4fAAAKAAAACgAAAAgAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAAKAAAACgAAAAIAAAB4CAAATw4WJwABW2H0EwAAAABJRU5ErkJggg=="

def ensure_dirs():
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path(QUAR_DIR).mkdir(parents=True, exist_ok=True)
        Path(HONEYPOT_DIR).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Erro ao criar diretórios: {e}")

def log(msg):
    try:
        ensure_dirs()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(LOG_DIR, "events.log"), "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception as e:
        print(f"Erro ao registrar log: {e}")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def relaunch_as_admin():
    try:
        params = " ".join([f'"{x}"' for x in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)
    except Exception as e:
        log(f"Erro ao tentar reiniciar como administrador: {e}")
        QMessageBox.critical(None, "Erro", "Falha ao reiniciar como administrador. Por favor, execute manualmente como administrador.")
        sys.exit(1)

def run(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log(f"Timeout ao executar comando: {cmd}")
        return None
    except Exception as e:
        log(f"cmd_error {cmd} {e}")
        return None

def format_path_name(path):
    p = Path(path)
    if len(p.name) > 30:
        return p.name[:27] + "..."
    return p.name

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log(f"Erro ao carregar configuração: {e}")
            return {}
    return {}

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        log(f"cfg_error {e}")

def is_system_file(file_path):
    if not file_path:
        return False
    system_paths = [
        os.environ.get('WINDIR', 'C:\\Windows').lower(),
        os.environ.get('SystemRoot', 'C:\\Windows').lower(),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'WindowsPowerShell').lower(),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'WindowsPowerShell').lower(),
        os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32').lower(),
        os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'SysWOW64').lower(),
    ]
    file_path_lower = file_path.lower()
    for system_path in system_paths:
        if system_path and file_path_lower.startswith(system_path):
            return True
    return False

class GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', wintypes.BYTE * 8)
    ]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pcwszFilePath', wintypes.LPCWSTR),
        ('hFile', wintypes.HANDLE),
        ('pgKnownSubject', ctypes.POINTER(GUID))
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', wintypes.LPVOID),
        ('pSIPClientData', wintypes.LPVOID),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('pFile', ctypes.c_void_p),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD),
        ('pSignatureSettings', ctypes.c_void_p)
    ]

class SignatureChecker:
    WINTRUST_ACTION_GENERIC_VERIFY_V2_GUID_TUPLE = (0xAAC56B, 0xCD44, 0x11d0, (0x8C, 0xC2, 0x0, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    @staticmethod
    def is_signed(file_path):
        try:
            if not os.path.exists(file_path):
                return False, "Arquivo não existe"
            
            if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.ocx')):
                return True, "Não é um arquivo executável"
            
            wintrust = ctypes.WinDLL('wintrust.dll')
            
            WTD_UI_NONE = 2
            WTD_REVOKE_NONE = 0
            WTD_CHOICE_FILE = 1
            WTD_STATEACTION_VERIFY = 1
            WTD_STATEACTION_CLOSE = 2
            WTD_SAFER_FLAG = 0x100
            
            guid_tuple = SignatureChecker.WINTRUST_ACTION_GENERIC_VERIFY_V2_GUID_TUPLE
            action_guid = GUID(
                guid_tuple[0],
                guid_tuple[1],
                guid_tuple[2],
                (wintypes.BYTE * 8)(*guid_tuple[3])
            )
            
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(file_info)
            file_info.pcwszFilePath = file_path
            file_info.hFile = None
            file_info.pgKnownSubject = None
            
            trust_data = WINTRUST_DATA()
            trust_data.cbStruct = ctypes.sizeof(trust_data)
            trust_data.pPolicyCallbackData = None
            trust_data.pSIPClientData = None
            trust_data.dwUIChoice = WTD_UI_NONE
            trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
            trust_data.dwUnionChoice = WTD_CHOICE_FILE
            trust_data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
            trust_data.dwStateAction = WTD_STATEACTION_VERIFY
            trust_data.hWVTStateData = None
            trust_data.pwszURLReference = None
            trust_data.dwProvFlags = WTD_SAFER_FLAG
            trust_data.dwUIContext = 0
            trust_data.pSignatureSettings = None
            
            result = wintrust.WinVerifyTrust(
                None,
                ctypes.byref(action_guid),
                ctypes.byref(trust_data)
            )
            
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(
                None,
                ctypes.byref(action_guid),
                ctypes.byref(trust_data)
            )
            
            if result == 0:
                log(f"Assinatura válida: {file_path}")
                return True, "Assinatura válida"
            else:
                log(f"Assinatura inválida ({hex(result)}): {file_path}")
                return False, f"Assinatura inválida (código: {hex(result)})"
                
        except Exception as e:
            log(f"verify_signature_error {file_path} {e}")
            return False, f"Erro na verificação: {str(e)}"

class ProcCounter:
    def __init__(self, window_seconds=10, threshold=40):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.data = defaultdict(deque)
        self.lock = Lock()
    
    def add(self, pid):
        with self.lock:
            now = datetime.now()
            dq = self.data[pid]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            return len(dq)
    
    def set_threshold(self, v):
        with self.lock:
            self.threshold = v
    
    def set_window(self, s):
        with self.lock:
            self.window = timedelta(seconds=s)
    
    def get_counts(self):
        with self.lock:
            out = {}
            now = datetime.now()
            for k, dq in list(self.data.items()):
                while dq and now - dq[0] > self.window:
                    dq.popleft()
                if dq:
                    out[k] = len(dq)
            return out

class HoneypotManager:
    def __init__(self):
        ensure_dirs()
        self.paths = set()
    
    def create_in(self, base):
        try:
            Path(base).mkdir(parents=True, exist_ok=True)
            names = ["FAWKES_HONEYPOT_REPORT.docx", "FAWKES_HONEYPOT_INVOICE.xlsx", 
                    "FAWKES_HONEYPOT_BACKUP.pdf", "FAWKES_HONEYPOT_MEDIA.jpg", 
                    "FAWKES_HONEYPOT_KEYS.txt"]
            created = []
            
            if not os.access(base, os.W_OK):
                log(f"Sem permissão de escrita para criar honeypots em: {base}")
                return []
                
            for n in names:
                p = os.path.join(base, n)
                if os.path.exists(p):
                    created.append(p)
                    continue
                    
                try:
                    with open(p, "wb") as f:
                        f.write(os.urandom(2048))
                    try:
                        os.chmod(p, 0o444)
                    except:
                        pass
                    created.append(p)
                except PermissionError:
                    log(f"Sem permissão para criar honeypot: {p}")
                except Exception as e:
                    log(f"Erro ao criar honeypot {p}: {e}")
                    
            self.paths.update(created)
            return created
        except Exception as e:
            log(f"honeypot_error {e}")
            return []
    
    def is_honeypot(self, path):
        return "FAWKES_HONEYPOT_" in os.path.basename(path)

class BlockUnsigned:
    def __init__(self, engine):
        self.engine = engine
        self.blocked_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.msi', '.scr']
        self.whitelist_extensions = ['.py']
        self.whitelist_files = ['Fawkes', 'python', 'pythonw']
        self.whitelist_paths = [os.path.abspath(__file__), sys.executable]
        self.downloads_folders = self._get_download_folders()
        self.stop_event = Event()
        self.observer = None
        self.initialized = False
        self.wmi_connection = None
        self.process_watcher = None
        log("Módulo de bloqueio de executáveis não assinados inicializado")
        
    def _get_download_folders(self):
        folders = []
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
            download_path = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")[0]
            folders.append(download_path)
            winreg.CloseKey(key)
        except Exception as e:
            log(f"Erro ao obter pasta de downloads do registro: {e}")
            
        try:
            for drive in self._get_drives():
                users_dir = os.path.join(drive, "Users")
                if os.path.exists(users_dir):
                    for user in os.listdir(users_dir):
                        download_dir = os.path.join(users_dir, user, "Downloads")
                        if os.path.exists(download_dir):
                            folders.append(download_dir)
        except Exception as e:
            log(f"Erro ao listar pastas de downloads: {e}")
        
        return list(set(folders))
    
    def _get_drives(self):
        drives = []
        try:
            bitmask = win32api.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drives.append(f"{letter}:")
                bitmask >>= 1
        except Exception as e:
            log(f"Erro ao obter unidades de disco: {e}")
            drives = ["C:"]
        return drives

    def _is_whitelisted_file(self, file_path):
        if not file_path:
            return False
            
        if file_path in self.whitelist_paths:
            return True
            
        file_name = os.path.basename(file_path).lower()
        name_without_ext = os.path.splitext(file_name)[0]
        
        for whitelist_name in self.whitelist_files:
            if whitelist_name.lower() in name_without_ext:
                return True
            
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.whitelist_extensions:
            return True
            
        return False
    
    def _delete_file(self, file_path):
        log(f"Tentando excluir arquivo: {file_path}")
        for attempt in range(10):
            try:
                if os.path.exists(file_path):
                    try:
                        os.chmod(file_path, 0o777)
                    except:
                        pass
                    os.unlink(file_path)
                if not os.path.exists(file_path):
                    log(f"Arquivo excluído com sucesso: {file_path}")
                    return True
            except OSError as e:
                log(f"Erro ao excluir arquivo {file_path} (tentativa {attempt + 1}): {e}")
                time.sleep(0.1)
        return False
    
    def _terminate_process(self, pid, name="Processo"):
        try:
            log(f"Tentando encerrar processo: {name} (PID {pid})")
            
            try:
                handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
                if handle:
                    result = win32api.TerminateProcess(handle, 0)
                    win32api.CloseHandle(handle)
                    if result:
                        log(f"Processo {pid} terminado com win32api")
                        return True
            except Exception as e:
                log(f"Erro ao encerrar via win32api: {e}")
                
            return self.engine.block_process(pid)
        except Exception as e:
            log(f"Falha ao encerrar processo {pid}: {e}")
            return False
    
    def _extract_script_path(self, cmd_line):
        if not cmd_line:
            return None
        
        cmd_lower = cmd_line.lower()
        
        for ext in ['.ps1', '.bat', '.cmd', '.vbs', '.js']:
            if ext in cmd_lower:
                parts = cmd_line.split('"')
                for part in parts:
                    if part.lower().endswith(ext) and os.path.exists(part):
                        return part
                
                parts = cmd_line.split(' ')
                for part in parts:
                    if part.lower().endswith(ext) and os.path.exists(part):
                        return part
        
        return None
    
    class DownloadWatcher(FileSystemEventHandler):
        def __init__(self, blocker, engine):
            self.blocker = blocker
            self.engine = engine
            
        def _handle_event(self, file_path):
            try:
                log(f"Evento de arquivo detectado em pasta de downloads: {file_path}")
                
                if self.blocker._is_whitelisted_file(file_path) or is_system_file(file_path):
                    log(f"Arquivo na lista de permissões: {file_path}")
                    return
                    
                _, ext = os.path.splitext(file_path)
                if ext.lower() in self.blocker.blocked_extensions:
                    log(f"Extensão bloqueada detectada: {ext}")
                    
                    if ext.lower() in ['.exe', '.dll', '.sys']:
                        signed, reason = SignatureChecker.is_signed(file_path)
                        if signed:
                            log(f"Executável com assinatura válida: {file_path}")
                            return
                        else:
                            log(f"Executável sem assinatura detectado: {file_path} - {reason}")
                    
                    pid, proc_name = self.engine.resolve_pid_from_path(file_path)
                    if pid:
                        log(f"Processo responsável: {proc_name} (PID {pid})")
                        
                        if self.blocker._terminate_process(pid, proc_name):
                            log(f"Processo {proc_name} (PID {pid}) encerrado")
                            self.engine.threats_blocked += 1
                            self.engine.signal_threat.emit(proc_name, pid, f"Arquivo malicioso bloqueado: {os.path.basename(file_path)}")
                    else:
                        log(f"Não foi possível identificar o processo responsável pelo arquivo: {file_path}")
                    
                    if self.blocker._delete_file(file_path):
                        log(f"Arquivo excluído: {file_path}")
                    else:
                        log(f"Não foi possível excluir o arquivo: {file_path}")
            except Exception as e:
                log(f"Erro ao processar evento de arquivo: {e}")

        def on_created(self, event):
            if not event.is_directory:
                self._handle_event(event.src_path)
                
        def on_modified(self, event):
            if not event.is_directory:
                self._handle_event(event.src_path)

    def start(self):
        try:
            log("Iniciando proteção de bloqueio de executáveis não assinados")
            self.stop_event.clear()
            
            self.observer = Observer()
            for folder in self.downloads_folders:
                if os.path.exists(folder):
                    try:
                        self.observer.schedule(self.DownloadWatcher(self, self.engine), folder, recursive=True)
                        log(f"Monitorando pasta de downloads: {folder}")
                    except Exception as e:
                        log(f"Erro ao monitorar pasta {folder}: {e}")
            
            try:
                self.observer.start()
                log("Observador de downloads iniciado")
            except Exception as e:
                log(f"Erro ao iniciar observador de downloads: {e}")
            
            Thread(target=self._monitor_processes, daemon=True).start()
            log("Thread de monitoramento de processos iniciada")
            
            self.initialized = True
            return True
        except Exception as e:
            log(f"Erro ao iniciar proteção de bloqueio: {e}")
            return False
    
    def stop(self):
        log("Parando proteção de bloqueio de executáveis não assinados")
        self.stop_event.set()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
                log("Observador de downloads parado")
            except Exception as e:
                log(f"Erro ao parar observador: {e}")
        self.initialized = False
    
    def _monitor_processes(self):
        log("Iniciando monitoramento de processos")
        try:
            pythoncom.CoInitialize()
            self.wmi_connection = wmi.WMI()
            self.process_watcher = self.wmi_connection.Win32_Process.watch_for("creation")
            log("Monitor WMI inicializado com sucesso")
            
            while not self.stop_event.is_set():
                try:
                    new_process = self.process_watcher(timeout_ms=1000)
                    if not new_process or self.stop_event.is_set():
                        continue
                        
                    process_path = new_process.ExecutablePath or ""
                    process_name = os.path.basename(process_path).lower() if process_path else ""
                    cmd_line = new_process.CommandLine or ""
                    pid = new_process.ProcessId
                    
                    log(f"Novo processo detectado: {process_name} (PID {pid})")
                    
                    if not process_path:
                        continue
                        
                    if (self._is_whitelisted_file(process_path) or 
                        is_system_file(process_path) or 
                        process_name in self.engine.allowlist):
                        log(f"Processo na lista de permissões: {process_path}")
                        continue

                    if process_path.lower().endswith((".exe", ".dll", ".sys")):
                        log(f"Verificando assinatura do executável: {process_path}")
                        signed, reason = SignatureChecker.is_signed(process_path)
                        if not signed:
                            log(f"Executável sem assinatura detectado: {process_path} - Razão: {reason}")
                            
                            if self._terminate_process(pid, process_name):
                                log(f"Processo {process_name} (PID {pid}) bloqueado - Sem assinatura")
                                self.engine.threats_blocked += 1
                                self.engine.signal_threat.emit(
                                    process_name, pid, "Executável sem assinatura digital bloqueado"
                                )
                                
                                if self._delete_file(process_path):
                                    log(f"Arquivo executável excluído: {process_path}")
                            continue
                    
                    if process_name in ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"]:
                        log(f"Analisando linha de comando para processo de script: {cmd_line}")
                        script_path = self._extract_script_path(cmd_line)
                        
                        if script_path and os.path.exists(script_path):
                            log(f"Script detectado: {script_path}")
                            
                            if not is_system_file(script_path) and not self._is_whitelisted_file(script_path):
                                log(f"Script potencialmente malicioso detectado: {script_path}")
                                
                                if self._terminate_process(pid, process_name):
                                    log(f"Processo de script {process_name} (PID {pid}) bloqueado")
                                    self.engine.threats_blocked += 1
                                    self.engine.signal_threat.emit(
                                        process_name, pid, 
                                        f"Script potencialmente malicioso bloqueado: {os.path.basename(script_path)}"
                                    )
                                    
                                    if self._delete_file(script_path):
                                        log(f"Arquivo de script excluído: {script_path}")
                                continue
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    if not self.stop_event.is_set():
                        log(f"Erro no loop de monitoramento de processos: {e}")
                        time.sleep(1)
                    
        except Exception as e:
            log(f"Exceção fatal no monitor de processos: {e}")
        finally:
            log("Finalizando monitoramento de processos")
            try:
                pythoncom.CoUninitialize()
            except:
                pass

class FileEventRouter(FileSystemEventHandler):
    def __init__(self, engine):
        self.engine = engine
    
    def on_created(self, event):
        if not event.is_directory:
            self.engine.handle_event(event.src_path, "created")
    
    def on_modified(self, event):
        if not event.is_directory:
            self.engine.handle_event(event.src_path, "modified")
    
    def on_moved(self, event):
        if not event.is_directory:
            self.engine.handle_event(event.dest_path, "moved")

class RealtimeEngine(QObject):
    signal_threat = Signal(str, int, str)
    signal_stats = Signal(dict)
    signal_scan_progress = Signal(int, int)
    signal_scan_complete = Signal(int)
    
    def __init__(self, watch_paths, window=10, threshold=40):
        super().__init__()
        self.watch_paths = set(p for p in watch_paths if os.path.exists(p))
        self.counter = ProcCounter(window, threshold)
        self.stop_event = Event()
        self.observer = None
        self.honeypots = HoneypotManager()
        self.enabled = False
        self.lock = Lock()
        self.threats_blocked = 0
        self.allowlist = {p.lower() for p in WHITELIST_PROCS}
        self.scanning = False
        self.block_unsigned = None
    
    def update_params(self, window, threshold):
        self.counter.set_window(window)
        self.counter.set_threshold(threshold)
    
    def start(self):
        if self.enabled:
            return
        
        log("Iniciando proteção em tempo real")
        self.stop_event.clear()
        
        if not self.block_unsigned:
            try:
                self.block_unsigned = BlockUnsigned(self)
                log("Módulo de bloqueio de assinaturas criado com sucesso")
            except Exception as e:
                log(f"Erro ao criar módulo de bloqueio de assinaturas: {e}")
        
        try:
            self.observer = Observer()
            handler = FileEventRouter(self)
            
            for p in list(self.watch_paths):
                if os.path.exists(p):
                    try:
                        self.observer.schedule(handler, p, recursive=True)
                        log(f"Monitorando pasta: {p}")
                    except Exception as e:
                        log(f"watch_error {p} {e}")
            
            self.observer.start()
            log("Observador de arquivos iniciado")
            
            for p in list(self.watch_paths):
                try:
                    created = self.honeypots.create_in(p)
                    if created:
                        log(f"Honeypots criados em {p}: {len(created)}")
                except Exception as e:
                    log(f"Erro ao criar honeypots em {p}: {e}")
                
        except Exception as e:
            log(f"observer_start_error {e}")
        
        if self.block_unsigned:
            try:
                if self.block_unsigned.start():
                    log("Bloqueio de executáveis não assinados iniciado com sucesso")
                else:
                    log("Falha ao iniciar bloqueio de executáveis não assinados")
            except Exception as e:
                log(f"Erro ao iniciar bloqueio de executáveis não assinados: {e}")
            
        self.enabled = True
        Thread(target=self._stats_loop, daemon=True).start()
        log("Proteção em tempo real iniciada com sucesso")
    
    def stop(self):
        log("Parando proteção em tempo real")
        self.stop_event.set()
        
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
                log("Observador de arquivos parado")
            except Exception as e:
                log(f"observer_stop_error {e}")
        
        if self.block_unsigned:
            try:
                self.block_unsigned.stop()
                log("Bloqueio de executáveis não assinados parado")
            except Exception as e:
                log(f"Erro ao parar bloqueio de executáveis não assinados: {e}")
            
        self.enabled = False
    
    def _stats_loop(self):
        while not self.stop_event.is_set():
            time.sleep(1)
            try:
                self.signal_stats.emit(self.counter.get_counts())
            except Exception as e:
                log(f"Erro no loop de estatísticas: {e}")
    
    def add_watch(self, path):
        if os.path.exists(path):
            self.watch_paths.add(path)
            if self.enabled and self.observer:
                try:
                    self.observer.schedule(FileEventRouter(self), path, recursive=True)
                    log(f"Pasta adicionada ao monitoramento: {path}")
                except Exception as e:
                    log(f"add_watch_error {path} {e}")
    
    def remove_watch(self, path):
        self.watch_paths.discard(path)
        log(f"Pasta removida do monitoramento: {path}")
    
    def resolve_pid_from_path(self, path):
        try:
            if not path or not os.path.exists(path):
                return None, None
                
            for p in psutil.process_iter(["pid", "name", "open_files"]):
                try:
                    if p.info.get("open_files"):
                        for f in p.info["open_files"]:
                            if f.path and os.path.abspath(f.path) == os.path.abspath(path):
                                return p.info.get("pid"), p.info.get("name", "")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            log(f"resolve_pid_error {e}")
        return None, None
    
    def block_process(self, pid):
        try:
            if pid in (0, 4):
                return False
                
            p = psutil.Process(pid)
            n = p.name()
            
            if n.lower() in self.allowlist:
                log(f"Processo {n} ({pid}) está na lista de permitidos, não será bloqueado")
                return False
                
            log(f"Tentando bloquear processo: {n} (PID {pid})")
            
            try:
                exe_path = p.exe()
                create_time = datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S')
                log(f"Informações do processo: {n} ({pid}) - Caminho: {exe_path}, Criado: {create_time}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            try:
                for ch in p.children(recursive=True):
                    try:
                        log(f"Terminando processo filho: {ch.name()} (PID {ch.pid})")
                        ch.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        log(f"Erro ao terminar processo filho {ch.pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                log(f"Erro ao listar processos filhos de {pid}")
            
            try:
                p.terminate()
                log(f"Sinal de término enviado para {n} ({pid})")
                
                gone, alive = psutil.wait_procs([p], timeout=3)
                if p in alive:
                    log(f"Processo {n} ({pid}) não terminou após terminate(), tentando kill()")
                    p.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                log(f"Erro ao terminar/matar processo {pid}: {e}")
                return False
                    
            if not psutil.pid_exists(pid):
                log(f"Processo {pid} encerrado com sucesso")
                return True
            else:
                log(f"AVISO: Processo {pid} ainda existe após tentativa de encerramento")
                return False

        except psutil.NoSuchProcess:
             log(f"block_error: Processo com PID {pid} não encontrado.")
             return True
        except Exception as e:
            log(f"block_error {pid} {e}")
            return False
    
    def handle_event(self, path, kind):
        try:
            log(f"Evento detectado: {kind} - {path}")
            
            pid, name = self.resolve_pid_from_path(path)
            if pid is None:
                return
                
            if name.lower() in self.allowlist:
                log(f"Processo {name} está na lista de permitidos, ignorando evento")
                return
            
            if self.honeypots.is_honeypot(path):
                log(f"Atividade em honeypot detectada: {path}")
                if self.block_process(pid):
                    self.threats_blocked += 1
                    self.signal_threat.emit(name, pid, f"Atividade em honeypot {os.path.basename(path)}")
                    log(f"BLOQUEADO (honeypot): {name} (PID {pid}) - {path}")
                return
            
            c = self.counter.add(pid)
            log(f"Atividade do processo {name} (PID {pid}): {c}/{self.counter.threshold}")
            
            if c >= self.counter.threshold:
                log(f"Excesso de atividade detectado: {name} (PID {pid}) - {c} eventos na janela")
                if self.block_process(pid):
                    self.threats_blocked += 1
                    self.signal_threat.emit(name, pid, f"Excesso de alterações ({c}) em janela")
                    log(f"BLOQUEADO (excesso): {name} (PID {pid}) - {c} eventos")
        except Exception as e:
            log(f"Erro ao processar evento: {e}")
    
    def perform_full_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        Thread(target=self._scan_thread, daemon=True).start()
    
    def _scan_thread(self):
        try:
            scan_dirs = []
            
            drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
            for drive in drives:
                scan_dirs.append(drive)
            
            log("Iniciando verificação completa")
            
            total_files = 0
            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    try:
                        for entry in os.scandir(scan_dir):
                            if entry.is_dir(follow_symlinks=False):
                                try:
                                    for root, _, files in os.walk(entry.path):
                                        total_files += len(files)
                                except OSError:
                                    continue
                            else:
                                total_files += 1
                    except Exception as e:
                        log(f"Erro ao contar arquivos em {scan_dir}: {e}")

            processed = 0
            found_threats = 0
            
            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    for root, _, files in os.walk(scan_dir, topdown=True):
                        for file in files:
                            if self.scanning is False:
                                log("Verificação cancelada pelo usuário")
                                return

                            filepath = os.path.join(root, file)
                            
                            try:
                                filename = file.lower()
                                
                                is_threat = False
                                
                                if filename.endswith(('.exe', '.dll', '.sys')):
                                    signed, _ = SignatureChecker.is_signed(filepath)
                                    is_threat = not signed
                                elif any(filename.endswith(ext) for ext in ['.bat', '.cmd', '.vbs', '.js', '.ps1']):
                                    is_threat = not is_system_file(filepath)
                                else:
                                    is_threat = (
                                        "malware" in filename or
                                        "virus" in filename or
                                        "hack" in filename or
                                        "trojan" in filename or
                                        "exploit" in filename
                                    )
                                
                                if is_threat:
                                    found_threats += 1
                                    log(f"Ameaça detectada: {filepath}")
                                
                                processed += 1
                                
                                if processed % 100 == 0:
                                    self.signal_scan_progress.emit(processed, total_files)
                                
                                time.sleep(0.001)
                                
                            except Exception as e:
                                log(f"scan_error {filepath} {e}")
                                processed += 1
            
            self.signal_scan_progress.emit(total_files, total_files)
            self.signal_scan_complete.emit(found_threats)
            log(f"Verificação concluída: {found_threats} ameaças encontradas")
            
        except Exception as e:
            log(f"scan_thread_error {e}")
        finally:
            self.scanning = False

class FolderProtector:
    def __init__(self):
        self.state = {}
    
    def lock(self, path):
        if not os.path.exists(path):
            return False, "Pasta inexistente"
        try:
            run(f'takeown /F "{path}" /R /D Y')
            run(f'icacls "{path}" /inheritance:r /grant:r SYSTEM:(F) Administrators:(F)')
            run(f'attrib +s +h "{path}"')
            log(f"Pasta protegida: {path}")
            return True, "Protegida"
        except Exception as e:
            log(f"folder_lock_error {e}")
            return False, str(e)
    
    def unlock(self, path):
        if not os.path.exists(path):
            return False, "Pasta inexistente"
        try:
            run(f'icacls "{path}" /reset /T')
            run(f'attrib -s -h "{path}"')
            log(f"Pasta desprotegida: {path}")
            return True, "Desprotegida"
        except Exception as e:
            log(f"folder_unlock_error {e}")
            return False, str(e)

class SimpleLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setText("FAWKES")
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"color: {TEXT_LIGHT}; font-size: 28px; font-weight: 800; letter-spacing: 2px;")

class ToggleSwitch(QCheckBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(48, 24)
        
        self.setStyleSheet(f"""
            QCheckBox::indicator {{
                width: 48px;
                height: 24px;
            }}
            QCheckBox::indicator:unchecked {{
                background: #ccc;
                border-radius: 12px;
            }}
            QCheckBox::indicator:checked {{
                background: {PRIMARY_COLOR};
                border-radius: 12px;
            }}
        """)

class MetricCard(QFrame):
    def __init__(self, title, value="0", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setStyleSheet(f"""
            #card {{
                background: {BG_LIGHT};
                border-radius: 12px;
                padding: 20px;
            }}
        """)
        
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 3)
        self.setGraphicsEffect(shadow)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.value_label = QLabel(value)
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {TEXT_DARK}")
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"color: #666; font-size: 14px;")
        
        layout.addWidget(self.value_label)
        layout.addWidget(title_label)

class FeatureCard(QFrame):
    def __init__(self, icon_name, title, description, active=True, parent=None):
        super().__init__(parent)
        self.setObjectName("feature_card")
        
        self.setStyleSheet(f"""
            #feature_card {{
                background: {BG_LIGHT};
                border-radius: 12px;
                padding: 15px;
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        icon_frame = QFrame()
        icon_frame.setFixedSize(60, 60)
        icon_frame.setStyleSheet(f"""
            background: {BG_DARK};
            border-radius: 10px;
            color: {PRIMARY_COLOR};
        """)
        
        icon_layout = QHBoxLayout(icon_frame)
        icon_label = QLabel(icon_name[0].upper())
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet(f"color: {PRIMARY_COLOR}; font-size: 25px; font-weight: bold;")
        icon_layout.addWidget(icon_label)
        
        content_layout = QVBoxLayout()
        
        title_layout = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {TEXT_DARK}; font-size: 16px; font-weight: bold;")
        
        self.toggle = ToggleSwitch()
        self.toggle.setChecked(active)
        
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.toggle)
        
        desc_label = QLabel(description)
        desc_label.setStyleSheet("color: #666; font-size: 14px;")
        desc_label.setWordWrap(True)
        
        content_layout.addLayout(title_layout)
        content_layout.addWidget(desc_label)
        
        layout.addWidget(icon_frame)
        layout.addSpacing(15)
        layout.addLayout(content_layout, 1)

class ScanButton(QPushButton):
    def __init__(self, text, icon_text, is_primary=False, parent=None):
        super().__init__(text, parent)
        self.setFixedHeight(45)
        
        self.icon_text = icon_text
        self.is_primary = is_primary
        
        self._update_style()
        
        self.setCursor(Qt.PointingHandCursor)
    
    def _update_style(self):
        if self.is_primary:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {PRIMARY_COLOR};
                    color: white;
                    border-radius: 10px;
                    font-weight: bold;
                    padding: 10px 15px;
                    text-align: center;
                }}
                QPushButton:hover {{
                    background-color: #2dbf8e;
                }}
                QPushButton:pressed {{
                    background-color: #25a87c;
                }}
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #f2f2f2;
                    color: #333;
                    border: 1px solid #ddd;
                    border-radius: 10px;
                    font-weight: bold;
                    padding: 10px 15px;
                    text-align: center;
                }
                QPushButton:hover {
                    background-color: #e5e5e5;
                }
                QPushButton:pressed {
                    background-color: #d9d9d9;
                }
            """)

class SidebarButton(QPushButton):
    def __init__(self, text, icon_char=None, parent=None):
        super().__init__(text, parent)
        self.icon_char = icon_char
        
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(44)
        
        self.setStyleSheet(f"""
            QPushButton {{
                color: #b7c0ff;
                background: transparent;
                border: 0;
                text-align: left;
                padding-left: 16px;
                font-weight: 600;
            }} 
            QPushButton:hover {{
                background: {BG_MEDIUM};
                border-radius: 10px;
            }} 
            QPushButton:checked {{
                background: {BG_MEDIUM};
                border-radius: 10px;
                color: white;
            }}
        """)

class ProtectionInfoWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            background-color: #f5fbf8;
            border-radius: 8px;
            border-left: 4px solid {PRIMARY_COLOR};
            padding: 10px;
            margin-top: 5px;
        """)
        
        layout = QHBoxLayout(self)
        
        icon_label = QLabel("🔒")
        icon_label.setFixedWidth(20)
        
        text_label = QLabel("Proteção total contra execução de arquivos sem assinatura digital")
        text_label.setStyleSheet("color: #555; font-size: 13px;")
        
        layout.addWidget(icon_label)
        layout.addWidget(text_label, 1)

class DashboardPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)
        
        title = QLabel("Você está protegido")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"font-size: 32px; font-weight: 700; color: {TEXT_DARK};")
        
        subtitle = QLabel("Relaxe, tudo está sob controle")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #666; font-size: 18px;")
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        
        self.create_feature_cards(layout)
        
        self.create_scan_buttons(layout)
        
        self.create_stat_cards(layout)
        
        self.engine.signal_scan_progress.connect(self.update_scan_progress)
        self.engine.signal_scan_complete.connect(self.scan_complete)
    
    def create_feature_cards(self, parent_layout):
        rt_card = FeatureCard(
            "R", 
            "Proteção em tempo real está ATIVA",
            "Seus arquivos estão sendo monitorados para deter ameaças", 
            True
        )
        
        rt_content_layout = rt_card.layout().itemAt(2).layout()
        protection_info = ProtectionInfoWidget()
        rt_content_layout.addWidget(protection_info)
        
        rt_card.toggle.stateChanged.connect(self.toggle_realtime)
        
        def_card = FeatureCard(
            "V", 
            "Verificação de assinatura digital",
            f"Última atualização: hoje às {datetime.now().strftime('%H:%M')}", 
            True
        )
        def_card.toggle.setVisible(False)
        
        def_content_layout = def_card.layout().itemAt(2).layout()
        def_title_layout = def_content_layout.itemAt(0).layout()
        
        update_status = QLabel("Ativo")
        update_status.setStyleSheet(f"color: {PRIMARY_COLOR}; font-weight: 500;")
        def_title_layout.insertWidget(1, update_status)
        
        cards_layout = QVBoxLayout()
        cards_layout.setSpacing(15)
        cards_layout.addWidget(rt_card)
        cards_layout.addWidget(def_card)
        
        parent_layout.addLayout(cards_layout)
    
    def create_scan_buttons(self, parent_layout):
        scan_layout = QHBoxLayout()
        scan_layout.setSpacing(15)
        
        self.full_scan_btn = ScanButton("Verificação Completa", "🔍", True)
        self.folder_scan_btn = ScanButton("Verificar Pasta", "📁", False)
        
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setTextVisible(True)
        self.scan_progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #ddd;
                border-radius: 5px;
                background: white;
                text-align: center;
                height: 20px;
            }}
            QProgressBar::chunk {{
                background-color: {PRIMARY_COLOR};
                border-radius: 5px;
            }}
        """)
        
        scan_layout.addWidget(self.full_scan_btn)
        scan_layout.addWidget(self.folder_scan_btn)
        
        self.full_scan_btn.clicked.connect(self.start_full_scan)
        self.folder_scan_btn.clicked.connect(self.start_folder_scan)
        
        buttons_container = QVBoxLayout()
        buttons_container.addLayout(scan_layout)
        buttons_container.addWidget(self.scan_progress)
        
        parent_layout.addLayout(buttons_container)
    
    def create_stat_cards(self, parent_layout):
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        self.days_card = MetricCard("Dias de Proteção", "0")
        self.threats_card = MetricCard("Ameaças Bloqueadas", "0")
        
        stats_layout.addWidget(self.days_card)
        stats_layout.addWidget(self.threats_card)
        
        parent_layout.addLayout(stats_layout)
    
    def update_stats(self, days, threats):
        self.days_card.value_label.setText(str(days))
        self.threats_card.value_label.setText(str(threats))
    
    def toggle_realtime(self, state):
        if state == Qt.Checked:
            self.engine.start()
        else:
            self.engine.stop()
    
    def start_full_scan(self):
        if not self.engine.scanning:
            self.full_scan_btn.setText("Verificando...")
            self.full_scan_btn.setEnabled(False)
            self.folder_scan_btn.setEnabled(False)
            self.scan_progress.setVisible(True)
            self.scan_progress.setValue(0)
            self.engine.perform_full_scan()
    
    def start_folder_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Selecionar pasta para verificar")
        if folder and not self.engine.scanning:
            QMessageBox.information(self, "Info", "A verificação de pastas específicas ainda não foi implementada no motor.")

    
    def update_scan_progress(self, current, total):
        if total > 0:
            percent = int((current / total) * 100)
            self.scan_progress.setValue(percent)
            self.scan_progress.setFormat(f"{percent}% ({current}/{total} arquivos)")
    
    def scan_complete(self, threats):
        self.full_scan_btn.setText("Verificação Completa")
        self.folder_scan_btn.setText("Verificar Pasta")
        
        self.full_scan_btn.setEnabled(True)
        self.folder_scan_btn.setEnabled(True)
        
        self.scan_progress.setValue(100)
        self.scan_progress.setFormat(f"Concluído! {threats} ameaças encontradas")
        
        QTimer.singleShot(5000, lambda: self.scan_progress.setVisible(False))

class SettingsPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Configurações de Proteção")
        title.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {TEXT_DARK};")
        layout.addWidget(title)
        
        rt_layout = QHBoxLayout()
        
        rt_label = QLabel("Proteção em tempo real")
        rt_label.setStyleSheet(f"color: {TEXT_DARK}; font-weight: 600")
        
        self.rt_toggle = ToggleSwitch()
        self.rt_toggle.setChecked(True)
        self.rt_toggle.stateChanged.connect(self.on_toggle)
        
        rt_layout.addWidget(rt_label)
        rt_layout.addStretch()
        rt_layout.addWidget(self.rt_toggle)
        
        layout.addLayout(rt_layout)
        
        param_layout = QHBoxLayout()
        
        win_label = QLabel("Janela (segundos)")
        win_label.setStyleSheet("color: #666")
        
        self.win_spin = QSpinBox()
        self.win_spin.setRange(2, 120)
        self.win_spin.setValue(10)
        self.win_spin.setFixedWidth(80)
        
        thr_label = QLabel("Limite de alterações")
        thr_label.setStyleSheet("color: #666")
        
        self.thr_spin = QSpinBox()
        self.thr_spin.setRange(10, 1000)
        self.thr_spin.setValue(40)
        self.thr_spin.setFixedWidth(80)
        
        apply_btn = QPushButton("Aplicar")
        apply_btn.setCursor(Qt.PointingHandCursor)
        apply_btn.clicked.connect(self.apply_params)
        apply_btn.setStyleSheet(f"""
            background: {PRIMARY_COLOR};
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        param_layout.addWidget(win_label)
        param_layout.addWidget(self.win_spin)
        param_layout.addSpacing(20)
        param_layout.addWidget(thr_label)
        param_layout.addWidget(self.thr_spin)
        param_layout.addStretch()
        param_layout.addWidget(apply_btn)
        
        layout.addLayout(param_layout)
        
        layout.addWidget(QLabel("Pastas monitoradas"))
        
        self.folder_list = QListWidget()
        self.folder_list.setStyleSheet("""
            color: #333;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 5px;
        """)
        
        layout.addWidget(self.folder_list)
        
        folder_btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Adicionar pasta")
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.clicked.connect(self.add_folder)
        add_btn.setStyleSheet("""
            background: #22c55e;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        rm_btn = QPushButton("Remover pasta")
        rm_btn.setCursor(Qt.PointingHandCursor)
        rm_btn.clicked.connect(self.remove_folder)
        rm_btn.setStyleSheet("""
            background: #ef4444;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        folder_btn_layout.addWidget(add_btn)
        folder_btn_layout.addWidget(rm_btn)
        folder_btn_layout.addStretch()
        
        layout.addLayout(folder_btn_layout)
        
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: #666")
        
        layout.addWidget(self.stats_label)
        layout.addStretch()
        
        self.load_folders()
        
        engine.signal_stats.connect(self.update_stats)
    
    def load_folders(self):
        for folder in self.engine.watch_paths:
            self.folder_list.addItem(folder)
    
    def on_toggle(self, state):
        if state == Qt.Checked:
            self.engine.start()
        else:
            self.engine.stop()
    
    def apply_params(self):
        self.engine.update_params(self.win_spin.value(), self.thr_spin.value())
        
        cfg = load_config()
        cfg["window"] = self.win_spin.value()
        cfg["threshold"] = self.thr_spin.value()
        save_config(cfg)
        
        QMessageBox.information(self, "Configuração", "Parâmetros aplicados com sucesso!")
    
    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Adicionar pasta monitorada")
        if folder:
            self.engine.add_watch(folder)
            self.folder_list.addItem(folder)
            
            self.save_folder_config()
    
    def remove_folder(self):
        row = self.folder_list.currentRow()
        if row >= 0:
            folder = self.folder_list.item(row).text()
            self.engine.remove_watch(folder)
            self.folder_list.takeItem(row)
            
            self.save_folder_config()
    
    def save_folder_config(self):
        folders = [self.folder_list.item(i).text() for i in range(self.folder_list.count())]
        cfg = load_config()
        cfg["watch_paths"] = folders
        save_config(cfg)
    
    def update_stats(self, counts):
        active_procs = [f"{k}:{v}" for k, v in counts.items() if v > 0]
        if active_procs:
            self.stats_label.setText("Atividade recente: " + ", ".join(active_procs))
        else:
            self.stats_label.setText("Atividade recente: Nenhuma")

class ProtectedFoldersPage(QWidget):
    def __init__(self):
        super().__init__()
        self.prot = FolderProtector()
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Pastas Protegidas")
        title.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {TEXT_DARK};")
        layout.addWidget(title)
        
        desc = QLabel("Proteja pastas contra modificações não autorizadas")
        desc.setStyleSheet("color: #666")
        layout.addWidget(desc)
        
        self.folder_list = QListWidget()
        self.folder_list.setStyleSheet("""
            color: #333;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 5px;
        """)
        
        layout.addWidget(self.folder_list)
        
        btn_layout = QHBoxLayout()
        
        self.add_btn = QPushButton("Adicionar")
        self.add_btn.setCursor(Qt.PointingHandCursor)
        self.add_btn.clicked.connect(self.add_folder)
        self.add_btn.setStyleSheet("""
            background: #22c55e;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        self.lock_btn = QPushButton("Trancar")
        self.lock_btn.setCursor(Qt.PointingHandCursor)
        self.lock_btn.clicked.connect(self.lock_folder)
        self.lock_btn.setStyleSheet("""
            background: #f59e0b;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        self.unlock_btn = QPushButton("Destrancar")
        self.unlock_btn.setCursor(Qt.PointingHandCursor)
        self.unlock_btn.clicked.connect(self.unlock_folder)
        self.unlock_btn.setStyleSheet("""
            background: #3b82f6;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        self.remove_btn = QPushButton("Remover")
        self.remove_btn.setCursor(Qt.PointingHandCursor)
        self.remove_btn.clicked.connect(self.remove_folder)
        self.remove_btn.setStyleSheet("""
            background: #ef4444;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.lock_btn)
        btn_layout.addWidget(self.unlock_btn)
        btn_layout.addWidget(self.remove_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666")
        
        layout.addWidget(self.status_label)
        layout.addStretch()
        
        self.load_state()
    
    def load_state(self):
        cfg = load_config()
        for folder in cfg.get("protected_folders", []):
            self.folder_list.addItem(folder)
    
    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Adicionar pasta protegida")
        if folder:
            self.folder_list.addItem(folder)
            self.save_state()
            self.status_label.setText(f"Pasta adicionada: {Path(folder).name}")
    
    def lock_folder(self):
        row = self.folder_list.currentRow()
        if row >= 0:
            folder = self.folder_list.item(row).text()
            ok, msg = self.prot.lock(folder)
            self.status_label.setText(f"{Path(folder).name}: {msg}")
    
    def unlock_folder(self):
        row = self.folder_list.currentRow()
        if row >= 0:
            folder = self.folder_list.item(row).text()
            ok, msg = self.prot.unlock(folder)
            self.status_label.setText(f"{Path(folder).name}: {msg}")
    
    def remove_folder(self):
        row = self.folder_list.currentRow()
        if row >= 0:
            folder = self.folder_list.item(row).text()
            self.folder_list.takeItem(row)
            self.save_state()
            self.status_label.setText(f"Pasta removida: {Path(folder).name}")
    
    def save_state(self):
        items = [self.folder_list.item(i).text() for i in range(self.folder_list.count())]
        cfg = load_config()
        cfg["protected_folders"] = items
        save_config(cfg)

class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Quarentena")
        title.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {TEXT_DARK};")
        layout.addWidget(title)
        
        desc = QLabel("Ameaças bloqueadas pelo sistema")
        desc.setStyleSheet("color: #666")
        layout.addWidget(desc)
        
        self.threat_list = QListWidget()
        self.threat_list.setStyleSheet("""
            color: #333;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 5px;
        """)
        
        layout.addWidget(self.threat_list)
        
        btn_layout = QHBoxLayout()
        
        remove_btn = QPushButton("Remover selecionado")
        remove_btn.setCursor(Qt.PointingHandCursor)
        remove_btn.clicked.connect(self.remove_selected)
        remove_btn.setStyleSheet("""
            background: #ef4444;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        clear_btn = QPushButton("Limpar lista")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_list)
        clear_btn.setStyleSheet("""
            background: #f59e0b;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        layout.addStretch()
    
    def add_entry(self, name, pid, reason):
        entry = f"{datetime.now().strftime('%H:%M:%S')} • {name} (PID {pid}) • {reason}"
        self.threat_list.addItem(entry)
    
    def remove_selected(self):
        row = self.threat_list.currentRow()
        if row >= 0:
            self.threat_list.takeItem(row)
    
    def clear_list(self):
        self.threat_list.clear()

class LogsPage(QWidget):
    def __init__(self):
        super().__init__()
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Relatórios")
        title.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {TEXT_DARK};")
        layout.addWidget(title)
        
        self.log_text = QLabel("")
        self.log_text.setStyleSheet("""
            color: #333;
            background: white;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 15px;
            font-family: Consolas, monospace;
        """)
        self.log_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.log_text.setWordWrap(True)
        self.log_text.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.log_text)
        scroll_area.setStyleSheet("border: none;")
        
        layout.addWidget(scroll_area)
        
        btn_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Atualizar")
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_logs)
        refresh_btn.setFixedWidth(120)
        refresh_btn.setStyleSheet(f"""
            background: {PRIMARY_COLOR};
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        clear_btn = QPushButton("Limpar Logs")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.clicked.connect(self.clear_logs)
        clear_btn.setFixedWidth(120)
        clear_btn.setStyleSheet("""
            background: #ef4444;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        
        layout.addLayout(btn_layout)
        
        self.refresh_logs()
    
    def refresh_logs(self):
        log_path = os.path.join(LOG_DIR, "events.log")
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    content = "".join(lines[-1000:])
                    self.log_text.setText(content)
            except Exception as e:
                self.log_text.setText(f"Erro ao ler logs: {e}")
        else:
            self.log_text.setText("Sem registros ainda.")
    
    def clear_logs(self):
        reply = QMessageBox.question(
            self, 
            'Limpar Logs', 
            "Tem certeza que deseja limpar todos os logs?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            log_path = os.path.join(LOG_DIR, "events.log")
            try:
                if os.path.exists(log_path):
                    with open(log_path, "w", encoding="utf-8") as f:
                        f.write("")
                    self.log_text.setText("Logs limpos com sucesso.")
                    log("Logs foram limpos pelo usuário")
                else:
                    self.log_text.setText("Sem registros para limpar.")
            except Exception as e:
                QMessageBox.warning(self, "Erro", f"Erro ao limpar logs: {e}")
                self.log_text.setText(f"Erro ao limpar logs: {e}")

class ConfigPage(QWidget):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("Configurações")
        title.setStyleSheet(f"font-size: 24px; font-weight: 600; color: {TEXT_DARK};")
        layout.addWidget(title)
        
        auto_layout = QHBoxLayout()
        
        self.auto_start = QCheckBox("Iniciar com o Windows (Admin)")
        self.auto_start.setStyleSheet("color: #333")
        
        save_btn = QPushButton("Salvar")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.clicked.connect(self.save_autostart)
        save_btn.setStyleSheet(f"""
            background: {PRIMARY_COLOR};
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        auto_layout.addWidget(self.auto_start)
        auto_layout.addStretch()
        auto_layout.addWidget(save_btn)
        
        layout.addLayout(auto_layout)
        
        allow_label = QLabel("Lista de confiança (processos separados por ;)")
        allow_label.setStyleSheet("color: #333")
        
        self.allow_edit = QLineEdit()
        self.allow_edit.setPlaceholderText("ex: onedrive.exe; dropbox.exe")
        self.allow_edit.setStyleSheet("""
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
        """)
        
        apply_btn = QPushButton("Aplicar")
        apply_btn.setCursor(Qt.PointingHandCursor)
        apply_btn.clicked.connect(self.apply_allowlist)
        apply_btn.setStyleSheet(f"""
            background: {PRIMARY_COLOR};
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        """)
        
        layout.addWidget(allow_label)
        layout.addWidget(self.allow_edit)
        layout.addWidget(apply_btn, 0, Qt.AlignLeft)
        layout.addStretch()
        
        self.load_config()
    
    def load_config(self):
        cfg = load_config()
        
        if cfg.get("autostart"):
            self.auto_start.setChecked(True)
        
        self.allow_edit.setText("; ".join(sorted(self.engine.allowlist)))
    
    def save_autostart(self):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key_name = "FAWKES_AV"
            
            if self.auto_start.isChecked():
                exe_path = sys.executable.replace("python.exe", "pythonw.exe")
                script_path = os.path.abspath(sys.argv[0])
                value = f'"{exe_path}" "{script_path}"'
                
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, value)
                winreg.CloseKey(key)
                
                msg = "Inicialização automática ativada."
            else:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, key_name)
                winreg.CloseKey(key)
                msg = "Inicialização automática desativada."

            cfg = load_config()
            cfg["autostart"] = self.auto_start.isChecked()
            save_config(cfg)
            
            QMessageBox.information(self, "Sucesso", msg)
        except FileNotFoundError:
             QMessageBox.information(self, "Info", "Inicialização automática já estava desativada.")
        except Exception as e:
            QMessageBox.warning(self, "Erro", f"Ocorreu um erro ao configurar a inicialização automática:\n{e}")

    def apply_allowlist(self):
        txt = self.allow_edit.text().strip()
        user_list = set([x.strip().lower() for x in txt.replace(",", ";").split(";") if x.strip()])
        final_list = {p.lower() for p in WHITELIST_PROCS}.union(user_list)

        self.engine.allowlist = final_list
        
        cfg = load_config()
        cfg["allowlist"] = list(final_list)
        save_config(cfg)
        
        QMessageBox.information(self, "Sucesso", "Lista de confiança aplicada")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        ensure_dirs()
        
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1100, 700)
        
        try:
            self.setWindowIcon(QIcon(self._pix_from_b64(b64_logo)))
        except Exception as e:
            log(f"Erro ao carregar ícone: {e}")
        
        self.engine = RealtimeEngine(DEFAULT_WATCH)
        self.engine.signal_threat.connect(self.on_threat)
        
        self._build_ui()
        self._apply_style()
        self._setup_tray()
        self._load_state()
        
        self.days_start = datetime.now().date()
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)
        
        QTimer.singleShot(800, lambda: self.statusBar().showMessage("FAWKES ativado"))
        QTimer.singleShot(1000, self.engine.start)
    
    def _pix_from_b64(self, b):
        ba = base64.b64decode(b)
        pix = QPixmap()
        pix.loadFromData(ba)
        return pix
    
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        
        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet(f"background: {BG_DARK}; border-right: 1px solid #2a3e40")
        
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 20, 15, 20)
        sidebar_layout.setSpacing(10)
        
        logo_container = QWidget()
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 15)
        
        self.logo = SimpleLabel()
        
        premium_badge = QLabel(" ")
        premium_badge.setAlignment(Qt.AlignCenter)
        premium_badge.setStyleSheet(f"color: {PRIMARY_COLOR}; font-size: 14px; font-weight: 500; letter-spacing: 1px;")
        
        logo_layout.addWidget(self.logo)
        logo_layout.addWidget(premium_badge)
        
        sidebar_layout.addWidget(logo_container)
        
        self.btn_dash = SidebarButton("Meu Painel", "D")
        self.btn_prot = SidebarButton("Proteção", "P")
        self.btn_folders = SidebarButton("Pastas Protegidas", "F")
        self.btn_quar = SidebarButton("Quarentena", "Q")
        self.btn_logs = SidebarButton("Relatórios", "R")
        self.btn_settings = SidebarButton("Configurações", "C")
        
        for btn in [self.btn_dash, self.btn_prot, self.btn_folders, 
                   self.btn_quar, self.btn_logs, self.btn_settings]:
            sidebar_layout.addWidget(btn)
        
        sidebar_layout.addStretch()
        
        premium_info = QFrame()
        premium_info.setStyleSheet(f"""
            background-color: {BG_MEDIUM};
            border-radius: 10px;
            padding: 15px;
        """)
        
        premium_layout = QVBoxLayout(premium_info)
        premium_layout.setSpacing(5)
        
        expire_label = QLabel(" ")
        expire_label.setStyleSheet("color: #ccc; font-size: 13px;")
        
        expiry_date = (datetime.now() + timedelta(days=365)).strftime("%d/%m/%Y")
        expire_value = QLabel(expiry_date)
        expire_value.setStyleSheet(f"color: {PRIMARY_COLOR}; font-weight: 600; font-size: 14px;")
        
        signature = QLabel("© Leonardo Garroti")
        signature.setStyleSheet("color: #7f8ac9; font-size: 11px;")
        
        premium_layout.addWidget(expire_label)
        premium_layout.addWidget(expire_value)
        premium_layout.addWidget(signature)
        
        sidebar_layout.addWidget(premium_info)
        
        self.stack = QStackedWidget()
        
        self.page_dash = DashboardPage(self.engine)
        self.page_rt = SettingsPage(self.engine)
        self.page_pf = ProtectedFoldersPage()
        self.page_quar = QuarantinePage()
        self.page_logs = LogsPage()
        self.page_cfg = ConfigPage(self.engine)
        
        for page in [self.page_dash, self.page_rt, self.page_pf, 
                    self.page_quar, self.page_logs, self.page_cfg]:
            self.stack.addWidget(page)
        
        self.btn_dash.clicked.connect(lambda: self._select_page(0))
        self.btn_prot.clicked.connect(lambda: self._select_page(1))
        self.btn_folders.clicked.connect(lambda: self._select_page(2))
        self.btn_quar.clicked.connect(lambda: self._select_page(3))
        self.btn_logs.clicked.connect(lambda: self._select_page(4))
        self.btn_settings.clicked.connect(lambda: self._select_page(5))
        
        self.btn_dash.setChecked(True)
        
        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.stack, 1)
        
        self.statusBar().setStyleSheet(f"background: {BG_DARK}; color: {PRIMARY_COLOR}; padding: 5px;")
    
    def _select_page(self, index):
        self.stack.setCurrentIndex(index)
        
        buttons = [self.btn_dash, self.btn_prot, self.btn_folders, 
                  self.btn_quar, self.btn_logs, self.btn_settings]
        
        for i, btn in enumerate(buttons):
            btn.setChecked(i == index)
    
    def _apply_style(self):
        self.setStyleSheet(f"""
            QMainWindow {{
                background: white;
            }}
            QLabel {{
                color: #333;
            }}
            QStatusBar {{
                background: {BG_DARK};
                color: {PRIMARY_COLOR};
            }}
        """)
    
    def _setup_tray(self):
        try:
            self.tray = QSystemTrayIcon(QIcon(self._pix_from_b64(b64_logo)), self)
            self.tray.setToolTip(APP_NAME)
            
            menu = QMenu()
            show_action = QAction("Mostrar", self)
            show_action.triggered.connect(self.showNormal)
            
            quit_action = QAction("Sair", self)
            quit_action.triggered.connect(self.close)
            
            menu.addAction(show_action)
            menu.addSeparator()
            menu.addAction(quit_action)
            
            self.tray.setContextMenu(menu)
            self.tray.show()
        except Exception as e:
            log(f"tray_error {e}")

    def _load_state(self):
        cfg = load_config()
        self.engine.update_params(cfg.get("window", 10), cfg.get("threshold", 40))
        self.engine.watch_paths.update(cfg.get("watch_paths", []))
        
        allowlist_from_cfg = {p.lower() for p in cfg.get("allowlist", [])}
        self.engine.allowlist.update(allowlist_from_cfg)
            
        start_date = cfg.get("start_date")
        if start_date:
            try:
                self.days_start = datetime.strptime(start_date, "%Y-%m-%d").date()
            except:
                self.days_start = datetime.now().date()
        else:
            cfg["start_date"] = datetime.now().strftime("%Y-%m-%d")
            save_config(cfg)

    def on_threat(self, name, pid, reason):
        self.page_quar.add_entry(name, pid, reason)
        self.tray.showMessage(
            "Ameaça Bloqueada",
            f"O processo {name} (PID {pid}) foi bloqueado.\nMotivo: {reason}",
            QSystemTrayIcon.Warning,
            3000
        )
        self.statusBar().showMessage(f"Ameaça bloqueada: {name}", 5000)

    def _tick(self):
        days = (datetime.now().date() - self.days_start).days
        self.page_dash.update_stats(days, self.engine.threats_blocked)


    def closeEvent(self, event):

        reply = QMessageBox.question(self, 'Sair', 
                                     "Deseja fechar o FAWKES ou minimizá-lo para a bandeja?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
                                     QMessageBox.StandardButton.Cancel)

        if reply == QMessageBox.StandardButton.Yes:
            self.engine.stop()
            self.tray.hide()
            event.accept()
        elif reply == QMessageBox.StandardButton.No:
            self.hide()
            self.tray.showMessage("FAWKES", "O antivírus continua ativo em segundo plano.")
            event.ignore()
        else:
            event.ignore()


if __name__ == "__main__":
    if not is_admin():
        relaunch_as_admin()

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())