#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import os
import sys
import json
import subprocess
import threading
import time
import re
import io
import contextlib
import shutil
import inspect
import textwrap
import platform
from typing import Optional, Dict, Any, List, Tuple, Iterable

# ---------- Intento de importar g4f (silencio prints) ----------
try:
    _buf_out = io.StringIO()
    with contextlib.redirect_stdout(_buf_out), contextlib.redirect_stderr(_buf_out):
        import g4f
        try:
            from g4f.client import Client  # type: ignore
            from g4f.Provider import RetryProvider  # type: ignore
            _HAS_CLIENT = True
        except Exception:
            Client = None  # type: ignore
            RetryProvider = None  # type: ignore
            _HAS_CLIENT = False
except Exception as e:
    print("❗ Error importando g4f:", e)
    print("Asegúrate de instalar la librería: pip install -U g4f")
    raise

# ---------- colorama (opcional) ----------
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    class _Dummy:
        def __getattr__(self, name):
            return ""
    Fore = _Dummy()
    Style = _Dummy()

# ---------------- CONFIG / CONSTANTES ----------------
ROOT_DIR = os.getcwd()
SPINNER_FRAMES = ['⠟', '⠯', '⠷', '⠾', '⠽', '⠻']
SPINNER_TEXT = "Pensando"
CONFIG_PATH = os.path.expanduser("~/.selenerc")

DEFAULT_MODEL_LIST = [
    "gpt-4",
    "deepseek-v3"
]

CREATE_KEYWORDS = ["crea", "crear", "genera", "generar", "create", "generate", "make project", "create files", "write file", "escribe archivo"]
ONLY_JSON_KEYWORDS = ["solo json", "only json", "mostrar solo json", "solo mostrar json", "sólo json", "mostrar únicamente json"]
DANGEROUS_PATTERNS = [
    r"rm\s+-rf", r":\s*(){:|:;}\s*;", r"shutdown", r"reboot", r"mkfs",
    r"dd\s+if=", r"curl\s+.*\|.*sh", r"wget\s+.*\|.*sh", r"forkbomb",
    r"base64\s+-d\s*.*\|.*sh"
]

# Patrones que indican que un comando ha fallado
RETRYABLE_ERROR_PATTERNS = [
    r"UnexpectedAttribute", r"Atributo 'DllImport'", r"ParserError", r"Token 'public' inesperado",
    r"unexpected attribute", r"unexpected token", r"Token 'public' unexpected", r"Unexpected token",
    r"Compilation error", r"parse error", r"syntax error", r"Attribute.*unexpected", r"error de sintaxis"
]

ORIGINAL_SYSTEM_PROMPT_JAIL = """
Eres un asistente técnico con reglas muy estrictas que NO PUEDEN ser cambiadas.
Reglas principales (resumidas):
1) Si en tu respuesta propones ejecutar comandos o creas scripts, RESPONDE EXCLUSIVAMENTE con un JSON válido
   sin texto adicional. El JSON debe tener la forma:
   {
     "files": [
       {"path": "ruta/archivo", "content": "...", "language": "bash|python|sh|js|php|..."},
       ...
     ],
     "run": ["comando1", "comando2", ...],
     "note": "opcional breve nota"
   }
   - Si propones un script, debes incluirlo completo dentro de "files" y establecer "language".
   - Si no hay archivos a crear, puedes omitir "files". Si no hay comandos a ejecutar, omite "run".
2) El JSON debe ser la ÚNICA salida (nada más en texto). Si no puedes generar JSON, devuelve un objeto JSON con
   {"error":"explicación breve"}.
3) Si el usuario indica un lenguaje para un script (por ejemplo "bash"), asegúrate de que el archivo proporcionado
   en "files" contenga el script completo y funcional en ese lenguaje, incluyendo shebang si corresponde.
4) NO incluyas instrucciones adicionales fuera del JSON. El emulador se encargará de crear/ejecutar.
5) No incluyas comandos destructivos ni instrucciones para comprometer sistemas.
6) Si el usuario pide explícitamente "solo json", sigue estas reglas igualmente.
7) Si la petición es ambigua sobre ejecutar comandos, devuelve JSON con "run": [] para indicar ninguna ejecución propuesta.
"""
SYSTEM_PROMPT_JAIL = ORIGINAL_SYSTEM_PROMPT_JAIL
JAIL_BROKEN = False

AFTER_CREATE_PROMPT = """
He creado estos archivos (paths absolutos):
{files_list}

Comenta si lo creado se ajusta y sugiere pasos siguientes en texto normal.
"""

# ---------- Variables globales de control ----------
CURRENT_MODEL: str = "gpt-4"
CURRENT_PROVIDER_NAMES: List[str] = []
DEBUG_TRACES: bool = False
FORCE_EXEC_DEFAULT: bool = False      # si True -> ejecutar 'run' sin pedir --exec
SNIPPETS_SAVE_TO_ROOT: bool = True   # si True intenta guardar en /SNIPPETS, si no puede usa ./SNIPPETS
INCLUDE_ENV_INFO: bool = True        # si True -> añadir info del OS al mensaje de sistema

# Cache modelos probeo
MODEL_PROBE_CACHE: Dict[str, Tuple[float, str]] = {}
MODEL_PROBE_TTL = 300

# ---------------- Helpers ----------------
def debug_print(*args, **kwargs):
    if DEBUG_TRACES:
        print("[DEBUG]", *args, **kwargs, flush=True)

def safe_print(*args, **kwargs):
    print(*args, **kwargs, flush=True)

def normalize_cd(cmd: str) -> Optional[str]:
    stripped = cmd.strip()
    low = stripped.lower()
    if low == "cd":
        return os.path.expanduser("~")
    if low.startswith("cd "):
        target = stripped[3:].strip()
        if (target.startswith('"') and target.endswith('"')) or (target.startswith("'") and target.endswith("'")):
            target = target[1:-1]
        return target
    return None

def run_command(cmd: str, cwd: str, input_text: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """
    Ejecuta un comando con subprocess.run, opcionalmente enviando 'input_text' a stdin.
    Devuelve dict con stdout, stderr, code, cwd.
    """
    cd_target = normalize_cd(cmd)
    if cd_target is not None:
        try:
            new_dir = os.path.abspath(os.path.join(cwd, cd_target)) if not os.path.isabs(cd_target) else os.path.abspath(cd_target)
            if not os.path.isdir(new_dir):
                return {"stdout":"", "stderr":f"No such directory: {cd_target}\n", "code":1, "cwd":cwd}
            os.chdir(new_dir)
            return {"stdout":"", "stderr":"", "code":0, "cwd": new_dir}
        except Exception as e:
            return {"stdout":"", "stderr": str(e) + "\n", "code":1, "cwd":cwd}
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, input=input_text, timeout=timeout)
        return {"stdout": p.stdout, "stderr": p.stderr, "code": p.returncode, "cwd": cwd}
    except subprocess.TimeoutExpired:
        return {"stdout":"", "stderr":"Command timed out.\n", "code":124, "cwd":cwd}
    except Exception as e:
        return {"stdout":"", "stderr": str(e) + "\n", "code":1, "cwd":cwd}

def build_dir_tree(base: str, max_depth: int = 4) -> str:
    base = os.path.abspath(base)
    lines = [os.path.basename(base) + "/"]
    def walk(path, prefix, depth):
        if depth > max_depth:
            return
        try:
            entries = sorted(os.listdir(path))
        except Exception:
            lines.append(prefix + "[PermissionError]")
            return
        for i, name in enumerate(entries):
            p = os.path.join(path, name)
            connector = "└── " if i == len(entries)-1 else "├── "
            lines.append(prefix + connector + name)
            if os.path.isdir(p):
                new_pref = prefix + ("    " if i == len(entries)-1 else "│   ")
                walk(p, new_pref, depth+1)
    walk(base, "", 1)
    return "\n".join(lines)

def extract_json_from_text(text: str) -> Optional[Dict[str,Any]]:
    start = text.find('{')
    if start == -1:
        return None
    for end in range(len(text), start-1, -1):
        candidate = text[start:end]
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None

def user_requested_creation(prompt: str) -> bool:
    low = prompt.lower()
    return any(k in low for k in CREATE_KEYWORDS)

def user_requested_only_json(prompt: str) -> bool:
    low = prompt.lower()
    return any(k in low for k in ONLY_JSON_KEYWORDS)

def check_file_content_safety(content: str) -> Optional[str]:
    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, content, flags=re.IGNORECASE):
            return f"Pattern matched: {pat}"
    return None

def _ensure_snippets_dir() -> str:
    root_snip = os.path.join(os.path.abspath(os.sep), "SNIPPETS")
    cwd_snip = os.path.join(os.getcwd(), "SNIPPETS")
    if SNIPPETS_SAVE_TO_ROOT:
        try:
            os.makedirs(root_snip, exist_ok=True)
            return root_snip
        except Exception:
            pass
    os.makedirs(cwd_snip, exist_ok=True)
    return cwd_snip

def _lang_to_ext(lang: str) -> str:
    mapping = {
        "bash": ".sh",
        "sh": ".sh",
        "python": ".py",
        "py": ".py",
        "javascript": ".js",
        "js": ".js",
        "php": ".php",
        "html": ".html",
        "css": ".css",
        "ruby": ".rb",
        "perl": ".pl",
        "go": ".go",
        "c": ".c",
        "cpp": ".cpp",
        "cmd": ".bat",
        "powershell": ".ps1"
    }
    return mapping.get((lang or "").lower(), "")

def sanitize_and_prepare_files(files_spec: List[Dict[str,Any]], base_dir: str) -> List[str]:
    created = []
    base_abs = os.path.abspath(base_dir)
    snippets_dir = _ensure_snippets_dir()
    for it in files_spec:
        content = it.get("content", "")
        language = it.get("language", "")
        snippet_flag = bool(it.get("snippet", False))
        path = it.get("path", "")

        if not path:
            ext = _lang_to_ext(language) or ""
            name = f"snippet_{int(time.time())}{ext}"
            target_abs = os.path.join(snippets_dir, name)
        else:
            if path.startswith("/SNIPPETS") or path.startswith("\\SNIPPETS") or snippet_flag:
                name = os.path.basename(path)
                if not name:
                    name = f"snippet_{int(time.time())}{_lang_to_ext(language)}"
                target_abs = os.path.join(snippets_dir, name)
            else:
                target_abs = os.path.abspath(os.path.join(base_abs, path))

        if not target_abs.startswith(base_abs) and not target_abs.startswith(os.path.abspath(snippets_dir)):
            raise ValueError(f"Path outside allowed directories: {path}")

        danger = check_file_content_safety(content)
        if danger:
            raise ValueError(f"Dangerous content in {path or target_abs}: {danger}")

        folder = os.path.dirname(target_abs)
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        if language and language.lower() in ("bash", "sh") and not content.startswith("#!"):
            content = "#!/usr/bin/env bash\n" + content
        with open(target_abs, "w", encoding="utf-8") as fh:
            fh.write(content)
        try:
            if language and language.lower() in ("bash", "sh", "python"):
                os.chmod(target_abs, 0o755)
        except Exception:
            pass
        created.append(target_abs)
    return created

# ---------------- g4f PROVIDERS DETECTION / HELPERS ----------------

def _is_valid_provider_obj(obj: Any) -> bool:
    if obj is None:
        return False
    if isinstance(obj, type):
        return True
    for attr in ("get_dict", "create", "chat", "__call__"):
        try:
            if hasattr(obj, attr):
                return True
        except Exception:
            continue
    return False

def _g4f_provider_list_with_names() -> List[Tuple[str, Any]]:
    providers: List[Tuple[str, Any]] = []
    try:
        provider_module = getattr(g4f, "Provider", None)
        if not provider_module:
            return providers
        for name in dir(provider_module):
            if name.startswith("_"):
                continue
            try:
                candidate = getattr(provider_module, name)
            except Exception:
                continue
            try:
                if _is_valid_provider_obj(candidate):
                    providers.append((name, candidate))
            except Exception:
                continue
        try:
            maybe_all = getattr(provider_module, "ALL", None)
            if isinstance(maybe_all, (list, tuple, dict)):
                if isinstance(maybe_all, dict):
                    for k, v in maybe_all.items():
                        if _is_valid_provider_obj(v):
                            providers.append((str(k), v))
                else:
                    for item in maybe_all:
                        nm = getattr(item, "__name__", repr(item))
                        if _is_valid_provider_obj(item):
                            providers.append((nm, item))
        except Exception:
            pass
    except Exception:
        pass
    seen = set()
    unique = []
    for name, obj in providers:
        if name in seen:
            continue
        seen.add(name)
        unique.append((name, obj))
    unique.sort(key=lambda x: x[0].lower())
    return unique

def _get_provider_objs_by_names(names: List[str]) -> List[Any]:
    objs: List[Any] = []
    provider_module = getattr(g4f, "Provider", None)
    if not provider_module:
        return objs
    for nm in names:
        try:
            candidate = getattr(provider_module, nm)
            if _is_valid_provider_obj(candidate):
                objs.append(candidate)
                continue
        except Exception:
            pass
        for attr in dir(provider_module):
            if attr.lower() == nm.lower():
                try:
                    cand = getattr(provider_module, attr)
                    if _is_valid_provider_obj(cand):
                        objs.append(cand)
                except Exception:
                    continue
    return objs

def _describe_provider(candidate: Any, max_methods: int = 6) -> str:
    parts = []
    try:
        tname = type(candidate).__name__ if not inspect.isclass(candidate) else candidate.__name__
        parts.append(f"Tipo: {tname}")
        doc = getattr(candidate, "__doc__", "") or ""
        doc = textwrap.shorten(doc.strip().splitlines()[0] if doc else "", width=140, placeholder="...")
        if doc:
            parts.append(f"Doc: {doc}")
        methods = []
        for m in dir(candidate):
            if m.startswith("_"):
                continue
            try:
                attr = getattr(candidate, m)
                if inspect.isroutine(attr) or inspect.isfunction(attr) or inspect.ismethod(attr):
                    methods.append(m)
                elif inspect.isclass(attr):
                    methods.append(m + " (class)")
                else:
                    if m in ("name", "provider_name", "id"):
                        methods.append(m)
            except Exception:
                continue
            if len(methods) >= max_methods:
                break
        if methods:
            parts.append("Métodos: " + ", ".join(methods))
    except Exception as e:
        parts.append(f"Error describiendo provider: {e}")
    return " | ".join(parts)

# ---------------- System / Environment info ----------------

def get_client_env_info() -> Dict[str, Any]:
    try:
        info = {
            "os_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cwd": os.getcwd(),
            "python_executable": sys.executable,
            "sys_platform": sys.platform
        }
    except Exception as e:
        info = {"error_detecting_env": str(e)}
    return info

# ---------------- Persistent system prompt builder ----------------

def get_persistent_system_prompt() -> str:
    """
    Construye un bloque que contiene:
     - SYSTEM_PROMPT_JAIL (si existe)
     - RESUMEN DE CONFIG (modelo, providers, flags)
     - NOTA: esto se inyecta siempre antes del user message en cada llamada.
    """
    cfg = {
        "model": CURRENT_MODEL,
        "providers": CURRENT_PROVIDER_NAMES,
        "force_exec_default": FORCE_EXEC_DEFAULT,
        "snippets_save_to_root": SNIPPETS_SAVE_TO_ROOT,
        "include_env_info": INCLUDE_ENV_INFO
    }
    cfg_str = json.dumps(cfg, ensure_ascii=False)
    parts = []
    if SYSTEM_PROMPT_JAIL and SYSTEM_PROMPT_JAIL.strip():
        parts.append(SYSTEM_PROMPT_JAIL.strip())
    parts.append("----- CURRENT CONFIGURATION (auto-injected) -----")
    parts.append(cfg_str)
    return "\n\n".join(parts)

# ---------------- Utility: extraer texto de RESPUESTAS g4f ----------------

def _extract_text_from_resp(resp: Any, buf: io.StringIO) -> str:
    try:
        if isinstance(resp, str):
            return resp
        if isinstance(resp, dict):
            choices = resp.get("choices")
            if choices and isinstance(choices, list):
                parts = []
                for ch in choices:
                    if isinstance(ch, dict):
                        msg = ch.get("message") or ch.get("delta") or ch
                        if isinstance(msg, dict):
                            content = msg.get("content") or msg.get("text")
                            if content:
                                parts.append(content)
                                continue
                        text = ch.get("text")
                        if text:
                            parts.append(text)
                            continue
                if parts:
                    return "".join(parts)
            for key in ("text", "content", "response"):
                if key in resp and isinstance(resp[key], str):
                    return resp[key]
            return str(resp)
        try:
            if hasattr(resp, "choices"):
                try:
                    choices = getattr(resp, "choices")
                    if isinstance(choices, (list, tuple)) and choices:
                        out = []
                        for ch in choices:
                            if isinstance(ch, dict):
                                out.append(ch.get("text") or ch.get("message", {}).get("content", "") or "")
                            else:
                                txt = getattr(ch, "text", None) or getattr(ch, "content", None)
                                if txt:
                                    out.append(txt)
                        if out:
                            return "".join(out)
                except Exception:
                    pass
            txt = getattr(resp, "content", None) or getattr(resp, "text", None)
            if isinstance(txt, str):
                return txt
        except Exception:
            pass
        if isinstance(resp, Iterable) and not isinstance(resp, (str, bytes)):
            collected = []
            try:
                for chunk in resp:
                    if isinstance(chunk, str):
                        collected.append(chunk)
                    elif isinstance(chunk, dict):
                        if "delta" in chunk and isinstance(chunk["delta"], dict):
                            c = chunk["delta"].get("content") or chunk["delta"].get("text")
                            if c:
                                collected.append(c)
                        else:
                            c = chunk.get("content") or chunk.get("text")
                            if c:
                                collected.append(c)
                    else:
                        collected.append(str(chunk))
                if collected:
                    return "".join(collected)
            except Exception:
                pass
        s = str(resp)
        if s and s.strip():
            return s
    except Exception as e:
        debug_print("Error extracting text from resp:", e)
    try:
        buf_val = buf.getvalue()
        if buf_val and buf_val.strip():
            return buf_val
    except Exception:
        pass
    return ""

# ---------------- g4f CALL + SPINNER (inserta persistent system prompt siempre) ----------------

def ask_g4f_with_spinner(messages: List[Dict[str,str]], model: Optional[str]=None, provider_names: Optional[List[str]]=None, timeout: int = 300) -> str:
    """
    Envía la petición a g4f y devuelve texto. Inserta SIEMPRE al principio:
      - get_persistent_system_prompt() como mensaje system
      - si INCLUDE_ENV_INFO True -> CLIENT_ENV system message adicional

    Corrección del spinner: ahora escribe en stderr y fuerza flush;
    además deja una línea limpia al terminar con la etiqueta SPINNER_TEXT.
    """
    model = model or CURRENT_MODEL
    provider_names = provider_names if provider_names is not None else CURRENT_PROVIDER_NAMES

    # construir messages_to_send: persistent system prompt siempre al inicio
    messages_to_send: List[Dict[str,str]] = []
    pers = get_persistent_system_prompt()
    if pers:
        messages_to_send.append({"role": "system", "content": pers})
    # añadir env info si procede
    if INCLUDE_ENV_INFO:
        env = get_client_env_info()
        env_str = "CLIENT_ENV: " + json.dumps(env, ensure_ascii=False)
        messages_to_send.append({"role": "system", "content": env_str})
    # añadir los mensajes que nos pasaron (user, etc.)
    messages_to_send.extend(messages)

    result = {"text": None, "error": None}
    finished = threading.Event()

    def call_api():
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                resp = None
                if _HAS_CLIENT and RetryProvider is not None and Client is not None and provider_names:
                    objs = _get_provider_objs_by_names(provider_names)
                    debug_print("Using provider names:", provider_names, "resolved objs:", [type(o) for o in objs])
                    if objs:
                        retry = None
                        try:
                            retry = RetryProvider(objs)
                        except TypeError:
                            try:
                                retry = RetryProvider(providers=objs)
                            except Exception:
                                retry = None
                        except Exception:
                            retry = None

                        if retry is not None:
                            try:
                                client = Client(provider=retry)
                                resp = client.chat.completions.create(model=model or "gpt-4", messages=messages_to_send, temperature=0.2)
                                text = _extract_text_from_resp(resp, buf)
                                result["text"] = text
                                return
                            except Exception as e:
                                debug_print("Client+RetryProvider failed:", e)
                try:
                    resp = g4f.ChatCompletion.create(model=model or "gpt-4", messages=messages_to_send, temperature=0.2)
                except Exception as e:
                    debug_print("g4f.ChatCompletion.create raised:", e)
                    try:
                        creator = getattr(g4f.ChatCompletion, "create_async", None)
                        if callable(creator):
                            resp = creator(model=model or "gpt-4", messages=messages_to_send, temperature=0.2)
                        else:
                            resp = None
                    except Exception as e2:
                        debug_print("create_async fallback failed:", e2)
                        resp = None
                text = _extract_text_from_resp(resp, buf)
                if not text or not text.strip():
                    try:
                        buf_val = buf.getvalue()
                        if buf_val and buf_val.strip():
                            text = buf_val
                    except Exception:
                        pass
                result["text"] = text
        except Exception as e_out:
            try:
                inner = buf.getvalue()
                result["error"] = f"{e_out}\n\n(g4f stdout/stderr):\n{inner}"
            except Exception:
                result["error"] = str(e_out)
        finally:
            finished.set()

    thread = threading.Thread(target=call_api, daemon=True)
    thread.start()

    i = 0
    # Spinner: ahora escribimos en stderr para que sea más visible en entornos con stdout redir.
    try:
        while not finished.is_set():
            frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)] if SPINNER_FRAMES else "."
            try:
                # Escribimos con \r para sobreescribir la línea y sin newline; usamos stderr.
                sys.stderr.write(f"\r{frame} {SPINNER_TEXT} ")
                sys.stderr.flush()
            except Exception:
                pass
            time.sleep(0.12)
            i += 1
    except KeyboardInterrupt:
        # si el usuario quiere cancelar la espera con Ctrl-C, marcamos finish y seguimos
        finished.set()

    # Cuando termine, limpiamos la línea del spinner y pintamos una línea final clara
    try:
        sys.stderr.write("\r" + " " * (len(SPINNER_TEXT) + 8) + "\r")
        sys.stderr.flush()
        # también dejamos una pequeña notita con 'Pensando' para que se vea que terminó
        sys.stderr.write(f"{SPINNER_TEXT} ✅\n")
        sys.stderr.flush()
    except Exception:
        pass

    if result["error"]:
        raise RuntimeError(result["error"])
    return result["text"] or ""

# ---------------- Model probe helpers ----------------

def _probe_model_once(model_name: str, provider_names: Optional[List[str]] = None, timeout: int = 8) -> Tuple[str, str]:
    res = {"status": "error", "msg": "No probe result", "done": False}
    def _call():
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                messages = [{"role":"user","content":"ping"}]
                if _HAS_CLIENT and RetryProvider is not None and Client is not None and provider_names:
                    objs = _get_provider_objs_by_names(provider_names)
                    if objs:
                        retry = None
                        try:
                            retry = RetryProvider(objs)
                        except Exception:
                            retry = None
                        if retry is not None:
                            try:
                                client = Client(provider=retry)
                                resp = client.chat.completions.create(model=model_name, messages=messages, temperature=0)
                                res["status"] = "ok"
                                res["msg"] = "OK via Client"
                                res["done"] = True
                                return
                            except Exception as e:
                                debug_print("Client probe failed:", e)
                try:
                    resp = g4f.ChatCompletion.create(model=model_name, messages=messages, temperature=0)
                    text = _extract_text_from_resp(resp, buf)
                    if re.search(r"model not found|Model not found|Unknown model|model.*not.*found", text, flags=re.IGNORECASE):
                        res["status"] = "unsupported"
                        res["msg"] = text.strip()
                    else:
                        res["status"] = "ok"
                        res["msg"] = text.strip()[:500]
                except Exception as e:
                    emsg = str(e)
                    if re.search(r"model not found|Model not found|Unknown model|model.*not.*found", emsg, flags=re.IGNORECASE):
                        res["status"] = "unsupported"
                        res["msg"] = emsg
                    else:
                        res["status"] = "error"
                        try:
                            extra = buf.getvalue()
                            if extra:
                                emsg = emsg + "\n(g4f stdout/stderr):\n" + extra
                        except Exception:
                            pass
                        res["msg"] = emsg
        except Exception as e_outer:
            res["status"] = "error"
            res["msg"] = str(e_outer)
        finally:
            res["done"] = True

    th = threading.Thread(target=_call, daemon=True)
    th.start()
    th.join(timeout)
    if not res["done"]:
        return ("timeout", f"No response in {timeout}s")
    return (res["status"], res["msg"])

def probe_models(models: List[str], provider_names: Optional[List[str]] = None, timeout_per: int = 6, refresh: bool = False) -> Dict[str, Tuple[str, str]]:
    out: Dict[str, Tuple[str, str]] = {}
    now = time.time()
    for m in models:
        cached = MODEL_PROBE_CACHE.get(m)
        if cached and not refresh:
            ts, status_str = cached
            if now - ts < MODEL_PROBE_TTL:
                out[m] = (status_str, "cached")
                continue
        try:
            status, msg = _probe_model_once(m, provider_names=provider_names, timeout=timeout_per)
        except Exception as e:
            status, msg = "error", str(e)
        MODEL_PROBE_CACHE[m] = (now, status)
        out[m] = (status, msg)
    return out

# ---------------- CONFIG: load / save / interactive setup ----------------

def save_config(path: str = CONFIG_PATH) -> None:
    cfg = {
        "model": CURRENT_MODEL,
        "providers": CURRENT_PROVIDER_NAMES,
        "jail_broken": JAIL_BROKEN,
        "custom_system_prompt": SYSTEM_PROMPT_JAIL if SYSTEM_PROMPT_JAIL != ORIGINAL_SYSTEM_PROMPT_JAIL else "",
        "debug_traces": DEBUG_TRACES,
        "force_exec_default": FORCE_EXEC_DEFAULT,
        "snippets_save_to_root": SNIPPETS_SAVE_TO_ROOT,
        "include_env_info": INCLUDE_ENV_INFO
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, ensure_ascii=False)
        debug_print("Saved config to", path, "->", cfg)
    except Exception as e:
        safe_print(Fore.RED + f"Error guardando config en {path}: {e}")

def load_config(path: str = CONFIG_PATH) -> None:
    global CURRENT_MODEL, CURRENT_PROVIDER_NAMES, JAIL_BROKEN, SYSTEM_PROMPT_JAIL, DEBUG_TRACES, FORCE_EXEC_DEFAULT, SNIPPETS_SAVE_TO_ROOT, INCLUDE_ENV_INFO
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        if isinstance(cfg, dict):
            CURRENT_MODEL = cfg.get("model", CURRENT_MODEL)
            CURRENT_PROVIDER_NAMES = cfg.get("providers", CURRENT_PROVIDER_NAMES) or []
            JAIL_BROKEN = bool(cfg.get("jail_broken", False))
            custom_prompt = cfg.get("custom_system_prompt", "")
            DEBUG_TRACES = bool(cfg.get("debug_traces", False))
            FORCE_EXEC_DEFAULT = bool(cfg.get("force_exec_default", False))
            SNIPPETS_SAVE_TO_ROOT = bool(cfg.get("snippets_save_to_root", True))
            INCLUDE_ENV_INFO = bool(cfg.get("include_env_info", True))
            if custom_prompt:
                SYSTEM_PROMPT_JAIL = custom_prompt
            else:
                SYSTEM_PROMPT_JAIL = "" if JAIL_BROKEN else ORIGINAL_SYSTEM_PROMPT_JAIL
        debug_print("Loaded config:", cfg)
    except Exception as e:
        safe_print(Fore.YELLOW + f"No pude leer {path}: {e}")

def _print_models_list():
    safe_print("Modelos disponibles (elige número o escribe nombre):")
    for i, m in enumerate(DEFAULT_MODEL_LIST, start=1):
        safe_print(f"  {i}) {m}")
    safe_print("  (también puedes escribir otro nombre de modelo personalizado)")

def interactive_setup(quiet: bool = False) -> None:
    global CURRENT_MODEL, CURRENT_PROVIDER_NAMES, JAIL_BROKEN, SYSTEM_PROMPT_JAIL, DEBUG_TRACES, FORCE_EXEC_DEFAULT, SNIPPETS_SAVE_TO_ROOT, INCLUDE_ENV_INFO

    if not quiet:
        safe_print(Fore.CYAN + "=== Setup de Selene 🌙 (modelo, providers y opciones) ===")
    else:
        safe_print(Fore.CYAN + "(Setup inicial)")

    display_default = CURRENT_MODEL
    if isinstance(CURRENT_MODEL, str) and CURRENT_MODEL.isdigit():
        try:
            idx = int(CURRENT_MODEL) - 1
            if 0 <= idx < len(DEFAULT_MODEL_LIST):
                display_default = DEFAULT_MODEL_LIST[idx]
        except Exception:
            pass

    _print_models_list()

    while True:
        try:
            model_inp = input(f"Modelo a usar [{display_default}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            safe_print("\nSetup cancelado.")
            return
        if not model_inp:
            CURRENT_MODEL = display_default
            break
        if model_inp.isdigit():
            idx = int(model_inp) - 1
            if 0 <= idx < len(DEFAULT_MODEL_LIST):
                CURRENT_MODEL = DEFAULT_MODEL_LIST[idx]
                break
            else:
                safe_print(Fore.YELLOW + "Número fuera de rango, vuelve a intentarlo.")
                continue
        else:
            CURRENT_MODEL = model_inp
            break

    detected = _g4f_provider_list_with_names()
    if detected:
        safe_print("Proveedores detectados (elige números separados por comas, 'all' para todos, o deja vacío):")
        for i, (name, _) in enumerate(detected, start=1):
            safe_print(f"  {i}) {name}")
    else:
        safe_print(Fore.YELLOW + "No he detectado providers automáticos en g4f.Provider.")

    chosen_names: List[str] = []
    try:
        sel = input("Tu selección de providers: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return

    if detected:
        if sel == "all":
            chosen_names = [name for name, _ in detected]
        elif sel:
            parts = [s.strip() for s in sel.split(",") if s.strip()]
            for p in parts:
                if p.isdigit():
                    idx = int(p) - 1
                    if 0 <= idx < len(detected):
                        chosen_names.append(detected[idx][0])
                else:
                    for name, _ in detected:
                        if name.lower() == p.lower():
                            chosen_names.append(name)
    else:
        if sel:
            chosen_names = [s.strip() for s in sel.split(",") if s.strip()]

    CURRENT_PROVIDER_NAMES = chosen_names

    try:
        jb = input("¿Quitar restricciones del sistema prompt (JAIL)? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return
    if jb in ("y","yes"):
        JAIL_BROKEN = True
        SYSTEM_PROMPT_JAIL = ""
    else:
        JAIL_BROKEN = False
        SYSTEM_PROMPT_JAIL = ORIGINAL_SYSTEM_PROMPT_JAIL

    try:
        dt = input("¿Activar trazas debug? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return
    DEBUG_TRACES = dt in ("y","yes")

    try:
        fe = input("¿Forzar ejecución automática de 'run' sin necesidad de --exec? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return
    FORCE_EXEC_DEFAULT = fe in ("y","yes")

    try:
        ss = input("¿Guardar snippets en /SNIPPETS cuando se indique? (intenta /SNIPPETS y si no funciona usa ./SNIPPETS) (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return
    SNIPPETS_SAVE_TO_ROOT = ss in ("y","yes")

    try:
        inc = input("¿Incluir info del sistema (OS) en cada llamada para personalizar respuestas? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return
    INCLUDE_ENV_INFO = inc in ("y","yes")

    try:
        test = input("¿Probar ahora la configuración con una llamada de test? (y/N): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\nSetup cancelado.")
        return

    if test in ("y","yes"):
        safe_print(Fore.CYAN + "Realizando test call... (timeout rápido)")
        test_messages = []
        # NOTA: no añadimos manualmente SYSTEM_PROMPT_JAIL aquí: ask_g4f_with_spinner lo inyecta lo
        test_messages.append({"role":"user", "content":"Responde con exactamente 'selene-test-ok' (sin comillas) en una sola línea."})
        try:
            resp = ask_g4f_with_spinner(test_messages, model=CURRENT_MODEL, provider_names=CURRENT_PROVIDER_NAMES, timeout=30)
            safe_print(Fore.GREEN + "Respuesta de test:")
            safe_print(Fore.GREEN + resp)
            ok = input("¿Guardar configuración actual? (y/N): ").strip().lower()
            if ok in ("y","yes"):
                save_config()
                safe_print(Fore.GREEN + f"Configuración guardada en {CONFIG_PATH}")
                return
            else:
                safe_print(Fore.YELLOW + "No se guardó la configuración. Puedes volver a intentarlo con .selenesetup")
                return
        except Exception as e:
            safe_print(Fore.RED + f"Test call falló: {e}")
            try:
                choice = input("¿Guardar igual la configuración (S), reintentar test (R) o cancelar (C)? [C]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                safe_print("\nSetup inicial falló o fue cancelado.")
                return
            if choice == "s":
                save_config()
                safe_print(Fore.GREEN + f"Configuración guardada en {CONFIG_PATH}")
                return
            elif choice == "r":
                safe_print(Fore.CYAN + "Reintentando test...")
                interactive_setup(quiet=quiet)
                return
            else:
                safe_print(Fore.YELLOW + "Setup cancelado / no guardado.")
                return
    else:
        try:
            ok = input("¿Guardar configuración sin test? (y/N): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            safe_print("\nSetup cancelado.")
            return
        if ok in ("y","yes"):
            save_config()
            safe_print(Fore.GREEN + f"Configuración guardada en {CONFIG_PATH}")
        else:
            safe_print(Fore.YELLOW + "No se guardó la configuración. Ejecuta .selenesetup para configurarla manualmente.")

# ------------------ HELP / DEBUG / JAIL / BADGE / LOOP ------------------

HELP_TEXT = """
Comandos disponibles:
  .ask <mensaje> [--exec] [--force]   -> enviar prompt a la IA. --exec permite que la IA proponga ejecutar
                                        comandos/files; --force omite confirmaciones antes de ejecutar.
  .selenesetup                       -> ejecutar el setup interactivo (modelo + providers) y guardar en ~/.selenerc
  .providers                          -> listar providers detectados en g4f.Provider
  .models [--fast|--refresh] [<model1,model2,...>] -> listar modelos y probear disponibilidad.
  .help                               -> mostrar esta ayuda
  .jail break                         -> quitar las restricciones del system prompt (avisa de riesgos y activa badge)
  .jail off                           -> restaurar el jail original (desactiva badge)
  .debug                              -> abrir menú de debug (ver/reemplazar/restore prompt, activar trazas, guardar)
  exit / quit                         -> salir del terminal
Si pides "solo json" en tu prompt, el emulador no creará ni ejecutará nada aunque la IA devuelva JSON.
"""

def draw_jailbreak_badge():
    if not JAIL_BROKEN:
        return
    try:
        rows, cols = shutil.get_terminal_size((80, 24))
        badge = " JAILBREAK "
        badge_len = len(badge)
        col = max(1, cols - badge_len + 1)
        sys.stdout.write("\033[s")
        sys.stdout.write(f"\033[{rows};{col}H")
        sys.stdout.write("\033[41m\033[97m" + badge + "\033[0m")
        sys.stdout.write("\033[u")
        sys.stdout.flush()
    except Exception:
        pass

def debug_menu():
    global SYSTEM_PROMPT_JAIL, JAIL_BROKEN, DEBUG_TRACES, FORCE_EXEC_DEFAULT, SNIPPETS_SAVE_TO_ROOT, INCLUDE_ENV_INFO

    safe_print(Fore.CYAN + "=== DEBUG MENU ===")
    safe_print("1) Ver prompt JAIL original")
    safe_print("2) Reemplazar prompt JAIL")
    safe_print("3) Restaurar prompt original")
    safe_print("4) Activar/desactivar trazas debug (current: {})".format("ON" if DEBUG_TRACES else "OFF"))
    safe_print("5) Toggle FORCE_EXEC_DEFAULT (current: {})".format("ON" if FORCE_EXEC_DEFAULT else "OFF"))
    safe_print("6) Toggle SNIPPETS_SAVE_TO_ROOT (current: {})".format("ON" if SNIPPETS_SAVE_TO_ROOT else "OFF"))
    safe_print("7) Toggle INCLUDE_ENV_INFO (current: {})".format("ON" if INCLUDE_ENV_INFO else "OFF"))
    safe_print("8) Guardar cambios")
    safe_print("9) Salir sin guardar")

    while True:
        try:
            choice = input("Elige una opción (1-9): ").strip()
        except (KeyboardInterrupt, EOFError):
            safe_print("\nSaliendo del menú debug sin guardar.")
            break

        if choice == "1":
            safe_print(Fore.YELLOW + "=== PROMPT JAIL ORIGINAL ===")
            safe_print(ORIGINAL_SYSTEM_PROMPT_JAIL)
            safe_print(Fore.YELLOW + "=== FIN ===")
        elif choice == "2":
            safe_print(Fore.YELLOW + "Introduce el nuevo prompt JAIL. Termina con una línea que contenga solo EOF")
            lines: List[str] = []
            while True:
                try:
                    ln = input()
                except (KeyboardInterrupt, EOFError):
                    safe_print("\nEntrada cancelada. Volviendo al menú.")
                    lines = []
                    break
                if ln.strip() == "EOF":
                    break
                lines.append(ln)
            if not lines:
                continue
            new_prompt = "\n".join(lines)
            safe_print(Fore.YELLOW + "Nuevo prompt JAIL (preview):")
            safe_print(new_prompt)
            try:
                conf = input("¿Aplicar este prompt? (y/N): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                safe_print("\nOperación cancelada.")
                continue
            if conf in ("y","yes"):
                SYSTEM_PROMPT_JAIL = new_prompt
                JAIL_BROKEN = (new_prompt.strip() == "")
                safe_print(Fore.GREEN + "Prompt JAIL actualizado en memoria.")
            else:
                safe_print("No se realizaron cambios.")
        elif choice == "3":
            SYSTEM_PROMPT_JAIL = ORIGINAL_SYSTEM_PROMPT_JAIL
            JAIL_BROKEN = False
            safe_print(Fore.GREEN + "Prompt restaurado al original.")
        elif choice == "4":
            DEBUG_TRACES = not DEBUG_TRACES
            safe_print(Fore.CYAN + f"Trazas debug {'activadas' if DEBUG_TRACES else 'desactivadas'}.")
        elif choice == "5":
            FORCE_EXEC_DEFAULT = not FORCE_EXEC_DEFAULT
            safe_print(Fore.CYAN + f"FORCE_EXEC_DEFAULT {'ON' if FORCE_EXEC_DEFAULT else 'OFF'}.")
        elif choice == "6":
            SNIPPETS_SAVE_TO_ROOT = not SNIPPETS_SAVE_TO_ROOT
            safe_print(Fore.CYAN + f"SNIPPETS_SAVE_TO_ROOT {'ON' if SNIPPETS_SAVE_TO_ROOT else 'OFF'}.")
        elif choice == "7":
            INCLUDE_ENV_INFO = not INCLUDE_ENV_INFO
            safe_print(Fore.CYAN + f"INCLUDE_ENV_INFO {'ON' if INCLUDE_ENV_INFO else 'OFF'}.")
        elif choice == "8":
            save_config()
            safe_print(Fore.GREEN + f"Cambios guardados en {CONFIG_PATH}.")
        elif choice == "9":
            safe_print("Saliendo del menú debug sin guardar (si no guardaste antes).")
            break
        else:
            safe_print("Opción no válida. Elige 1-9.")

def _format_probe_result(status: str, msg: str) -> str:
    if status == "ok":
        return Fore.GREEN + "OK" + Style.RESET_ALL
    if status == "unsupported":
        return Fore.YELLOW + "UNSUPPORTED" + Style.RESET_ALL
    if status == "timeout":
        return Fore.MAGENTA + "TIMEOUT" + Style.RESET_ALL
    return Fore.RED + "ERROR" + Style.RESET_ALL

# ---------------- Smart helpers: auto-answer & retries ----------------

def _matches_any_pattern(text: str, patterns: List[str]) -> bool:
    for pat in patterns:
        try:
            if re.search(pat, text, flags=re.IGNORECASE):
                return True
        except Exception:
            continue
    return False

def _deduce_default_choice_from_text(text: str) -> Optional[str]:
    """
    Intenta deducir una respuesta por defecto de un texto que contiene prompts.
    - Busca [Y/n], [y/N], [C], [Default: X], (y/n), etc.
    - Para menús numéricos, si aparece algo como 'elige 1' o '1)' retorna '1'.
    """
    if not text:
        return None
    # Busca [Y/n], [y/N], [Y/N], [S/n], [C]
    m = re.search(r"\[([A-Za-z0-9])(?:/[A-Za-z0-9])?\]", text)
    if m:
        return m.group(1).lower()
    # Default: X
    m = re.search(r"Default[:\s]*([A-Za-z0-9])", text, flags=re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # Busca '(y/n)' o 'y/n' -> no deducción clara, devolver 'y' por si acaso
    if re.search(r"\by\/n\b|\(y\/n\)|\[y\/n\]", text, flags=re.IGNORECASE):
        return "y"
    # Menú numérico: buscar 'elige 1' o 'Elige 1-9' o '1)' etc.
    m = re.search(r"elige\s+([0-9]+)", text, flags=re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"\b([0-9]+)\)", text)
    if m:
        return m.group(1)
    # No pudo deducir
    return None

def _auto_answer_prompt(prompt_text: str, exec_force: bool, force_flag: bool) -> Optional[str]:
    """
    Decide una respuesta automática basada en el texto de prompt y flags.
    Devuelve la cadena que debe enviarse (por ejemplo 'y', 'n', '1', etc.) o None para
    indicar que hay que preguntar al usuario.
    """
    # Si estamos forzando ejecución, devolvemos 'y' o '1' si hay menú
    if exec_force or force_flag or FORCE_EXEC_DEFAULT:
        # intenta deducir si es menu; si no, responde 'y'
        ded = _deduce_default_choice_from_text(prompt_text)
        if ded:
            return ded
        return "y"

    # intentar deducción por defecto
    ded = _deduce_default_choice_from_text(prompt_text)
    if ded:
        return ded

    # No se pudo deducir: devolver None -> preguntar al usuario
    return None

def _run_with_retries(cmd: str, cwd: str, max_attempts: int = 5, exec_force: bool = False, force_flag: bool = False) -> Dict[str, Any]:
    """
    Ejecuta 'cmd' con reintentos. Si detecta errores que coinciden con RETRYABLE_ERROR_PATTERNS
    hará varios intentos, incluidas variantes heurísticas si parece ser un powershell -File.
    Devuelve el resultado final como run_command() devuelve.
    """
    attempt = 0
    last_res = {"stdout":"", "stderr":"", "code":1, "cwd":cwd}
    backoff = 0.8
    while attempt < max_attempts:
        attempt += 1
        if attempt == 1:
            trial_cmd = cmd
        elif attempt == 2:
            # primer reintento simple idéntico
            trial_cmd = cmd
        elif attempt == 3:
            # si es powershell -File, intentar con -Command & 'script'
            if re.search(r"powershell.*-file", cmd, flags=re.IGNORECASE):
                # extraer el path del script
                m = re.search(r"-file\s+['\"]?([^'\"]+)['\"]?", cmd, flags=re.IGNORECASE)
                if m:
                    script = m.group(1)
                    trial_cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& '{script}'\""
                else:
                    trial_cmd = cmd
            else:
                trial_cmd = cmd
        elif attempt == 4:
            # intentar forzar codepage UTF-8 en Windows (puede ayudar con mensajes raros)
            trial_cmd = f"chcp 65001 > nul & {cmd}"
        else:
            trial_cmd = cmd

        safe_print(Fore.CYAN + (f"▶ Intento {attempt}/{max_attempts}: {trial_cmd}"))
        # Preparar posible respuesta automática si el comando puede pedir y/n
        # Ejecutar y capturar salida
        res = run_command(trial_cmd, cwd)
        last_res = res
        stdout = res.get("stdout") or ""
        stderr = res.get("stderr") or ""
        code = res.get("code", 1)
        debug_print(f"_run_with_retries attempt {attempt} code={code} stdout={len(stdout)} stderr={len(stderr)}")

        # Mostrar salidas parciales
        if stdout:
            safe_print(stdout, end="")
        if stderr:
            safe_print(Fore.RED + stderr, end="")

        # Si el proceso salió bien -> OK
        if code == 0:
            safe_print(Style.DIM + f"[exit code {code}]")
            return res

        # Si hay indicios de prompt que necesita respuesta (y/n o numerico), intentar auto-responder
        combined = (stdout + "\n" + stderr).strip()
        if combined and re.search(r"\b(y\/n|\(y\/n\)|\[y\/n\]|\[[Yy]\/[Nn]\]|\bSeleccione\b|\bElige\b|\belige\b|\d\))", combined, flags=re.IGNORECASE):
            auto = _auto_answer_prompt(combined, exec_force, force_flag)
            if auto is not None:
                safe_print(Fore.YELLOW + f"(Detectado prompt en salida, respondiendo automáticamente: {auto})")
                # re-ejecutar enviando respuesta por stdin
                # asegurarnos de añadir newline
                res2 = run_command(trial_cmd, cwd, input_text=(str(auto) + "\n"))
                last_res = res2
                stdout2 = res2.get("stdout") or ""
                stderr2 = res2.get("stderr") or ""
                if stdout2:
                    safe_print(stdout2, end="")
                if stderr2:
                    safe_print(Fore.RED + stderr2, end="")
                if res2.get("code", 1) == 0:
                    safe_print(Style.DIM + f"[exit code {res2.get('code')}]")
                    return res2
                # si sigue fallando, continuar con reintentos
                code = res2.get("code", 1)

        # Si stderr sugiere que es recuperable, reintentar tras backoff
        if _matches_any_pattern(stderr + " " + stdout, RETRYABLE_ERROR_PATTERNS) and attempt < max_attempts:
            safe_print(Fore.YELLOW + f"⚠️ Detectado error retryable (intentando de nuevo en {backoff:.1f}s)...")
            time.sleep(backoff)
            backoff *= 1.6
            continue
        else:
            # No parece recuperable o ya no quedan intentos; si quedan intentos, esperar y reintentar
            if attempt < max_attempts:
                safe_print(Fore.YELLOW + f"Intento {attempt} fallido (exit {code}). Reintentando en {backoff:.1f}s...")
                time.sleep(backoff)
                backoff *= 1.6
                continue
            else:
                break

    safe_print(Fore.RED + Style.BRIGHT + f"❌ Todas las reintentos ({max_attempts}) han fallado. Último exit code {last_res.get('code')}.")
    return last_res

# ---------------- Core: manejo de .ask y ejecución automática ----------------

def _request_json_followup(original_text: str, user_prompt: str) -> Optional[Dict[str,Any]]:
    # Pedimos al modelo que reenvíe exclusivamente JSON. ask_g4f_with_spinner ya inyecta persistent system prompt.
    follow_messages = []
    follow_messages.append({"role":"user", "content": (
        "Has respondido con texto. Necesito que vuelvas a responder EXCLUSIVAMENTE con JSON "
        "como se especifica en el system prompt inyectado al inicio de cada request. Si propones ejecutar comandos o entregar scripts, "
        "inclúyelos en 'run' y/o 'files'. Si no propones ejecutar nada, devuelve {\"run\":[],\"files\":[]}."
        "\n\nTexto anterior de la IA:\n\n" + original_text
    )})
    try:
        resp = ask_g4f_with_spinner(follow_messages, model=CURRENT_MODEL, provider_names=CURRENT_PROVIDER_NAMES)
        parsed = extract_json_from_text(resp if isinstance(resp, str) else str(resp))
        return parsed
    except Exception as e:
        debug_print("Follow-up JSON request failed:", e)
        return None

def _handle_parsed_json_and_execute(parsed: Dict[str,Any], cwd: str, exec_force: bool, force_flag: bool) -> Tuple[List[str], str]:
    created_paths = []
    response_text = ""
    if not isinstance(parsed, dict):
        return created_paths, "JSON inválido"
    files = parsed.get("files", [])
    if files and isinstance(files, list):
        try:
            created_paths = sanitize_and_prepare_files(files, cwd)
        except Exception as e:
            response_text += f"\nError creando archivos: {e}\n"
            return created_paths, response_text
        response_text += Fore.GREEN + "📁 Archivos creados:\n"
        for p in created_paths:
            response_text += " - " + p + "\n"
    run_list = parsed.get("run", [])
    if run_list and isinstance(run_list, list):
        for cmd in run_list:
            # Ejecutar con reintentos y con heurística de respuesta a prompts
            safe_print(Fore.CYAN + f"▶ Ejecutando (aut.) con reintentos: {cmd}")
            # si no forzamos, preguntar antes de iniciar los reintentos
            if not (exec_force or force_flag or FORCE_EXEC_DEFAULT):
                safe_print(Fore.YELLOW + f"¿Ejecutar este comando ahora? -> {cmd}")
                ans = input("Confirmar (y/n): ").strip().lower()
                if ans not in ("y","yes"):
                    safe_print(Fore.YELLOW + "Comando omitido por el usuario.")
                    continue
            # ejecutar con reintentos (usa heurística para prompts y errores)
            res = _run_with_retries(cmd, cwd, max_attempts=5, exec_force=exec_force, force_flag=force_flag)
            if res.get("stdout"):
                safe_print(res["stdout"], end="")
            if res.get("stderr"):
                safe_print(Fore.RED + res["stderr"], end="")
            safe_print(Style.DIM + f"[exit code {res.get('code')}]")
            cwd = res.get("cwd", cwd)
            if res.get("code", 1) != 0:
                response_text += Fore.RED + f"\nFallo ejecutando: {cmd}  (exit {res.get('code')}). Ver stderr arriba.\n"
    return created_paths, response_text

# ---------------- MAIN LOOP ----------------

def main_loop():
    global JAIL_BROKEN, SYSTEM_PROMPT_JAIL, CURRENT_PROVIDER_NAMES, CURRENT_MODEL, DEBUG_TRACES, FORCE_EXEC_DEFAULT, INCLUDE_ENV_INFO

    cwd = ROOT_DIR
    safe_print("🖥️ Te damos la bienvenida a Selene, el emulador de terminal que trabaja para ti.")
    safe_print("Usa .ask <mensaje> [--exec] [--force]  | .help  | .selenesetup  | .providers  | .models  | .jail break/off  | .debug  | exit\n")

    while True:
        draw_jailbreak_badge()
        try:
            raw_inp = input(f"{os.path.basename(cwd)}> ").rstrip()
        except (KeyboardInterrupt, EOFError):
            safe_print("\n👋 Adiós")
            break

        if not raw_inp:
            continue
        if raw_inp in ("exit","quit"):
            break

        cmd_strip = raw_inp.strip()
        if cmd_strip == ".help":
            safe_print(HELP_TEXT)
            continue

        if cmd_strip == ".selenesetup":
            interactive_setup()
            continue

        if cmd_strip == ".debug":
            debug_menu()
            continue

        if cmd_strip.startswith(".jail"):
            parts = cmd_strip.split()
            if len(parts) >= 2:
                arg = parts[1].lower()
                if arg == "break":
                    safe_print(Fore.RED + "⚠️ Has pedido 'jail break'. Esto quitará las restricciones del system prompt.")
                    safe_print(Fore.RED + "Riesgos: la IA podría sugerir operaciones peligrosas o destructivas.")
                    try:
                        c = input("¿Continuar y quitar las restricciones? (y/N): ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        safe_print("\nOperación cancelada.")
                        continue
                    if c in ("y","yes"):
                        JAIL_BROKEN = True
                        SYSTEM_PROMPT_JAIL = ""
                        save_config()
                        safe_print(Fore.GREEN + "Jail desactivado. Badge 'JAILBREAK' activado.")
                    else:
                        safe_print("Operación abortada. No se realizaron cambios.")
                    continue
                elif arg in ("off","restore"):
                    JAIL_BROKEN = False
                    SYSTEM_PROMPT_JAIL = ORIGINAL_SYSTEM_PROMPT_JAIL
                    save_config()
                    safe_print(Fore.GREEN + "Jail restaurado al prompt original. Badge desactivado.")
                    continue
            safe_print(Fore.YELLOW + "Uso: .jail break   (para quitar restricciones)\n       .jail off     (para restaurar el jail original)")
            continue

        if cmd_strip == ".providers":
            detected = _g4f_provider_list_with_names()
            if not detected:
                safe_print(Fore.YELLOW + "No se encontraron providers en g4f.Provider.")
                continue
            safe_print(Fore.CYAN + f"🔎 Providers detectados ({len(detected)}):")
            for i, (name, obj) in enumerate(detected, start=1):
                safe_print(Fore.GREEN + f" {i}) {name}")
                try:
                    desc = _describe_provider(obj)
                    for line in textwrap.wrap(desc, width=100):
                        safe_print("     " + line)
                except Exception as e:
                    safe_print("     " + Fore.YELLOW + f"(No se pudo describir: {e})")
            continue

        if cmd_strip.startswith(".models"):
            parts = cmd_strip.split()
            fast = "--fast" in parts
            refresh = "--refresh" in parts
            explicit = []
            for tok in parts[1:]:
                if tok.startswith("--"):
                    continue
                explicit.extend([m.strip() for m in tok.split(",") if m.strip()])
            if explicit:
                to_check = explicit
            else:
                to_check = DEFAULT_MODEL_LIST.copy()

            safe_print(Fore.CYAN + f"Modelos a mostrar: {', '.join(to_check)}")
            if fast:
                safe_print(Fore.YELLOW + "Modo --fast: mostrando lista sin probeo (rápido).")
                for m in to_check:
                    safe_print(" - " + m)
                continue

            safe_print(Fore.CYAN + f"Probeando modelos (timeout por modelo: 6s). Esto puede tardar unos segundos...")
            try:
                results = probe_models(to_check, provider_names=CURRENT_PROVIDER_NAMES or None, timeout_per=6, refresh=refresh)
            except Exception as e:
                safe_print(Fore.RED + f"Error en probeo de modelos: {e}")
                continue
            for m, (status, msg) in results.items():
                label = _format_probe_result(status, msg)
                safe_print(f" {m:25} -> {label}  ({msg[:80].replace(chr(10),' ')}{'...' if len(msg)>80 else ''})")
            safe_print(Fore.CYAN + "Probeo de modelos completado. Usa .models --refresh para forzar nueva comprobación.")
            continue

        # .ask handling
        if raw_inp.startswith(".ask "):
            tokens = raw_inp.split()
            exec_flag = "--exec" in tokens
            force_flag = "--force" in tokens
            prompt_parts = [t for t in tokens[1:] if t not in ("--exec","--force")]
            user_prompt = " ".join(prompt_parts).strip()

            safe_print("🤖 Enviando a la IA...")
            messages = []
            messages.append({"role":"user", "content": user_prompt})

            try:
                raw_resp = ask_g4f_with_spinner(messages, model=CURRENT_MODEL, provider_names=CURRENT_PROVIDER_NAMES)
            except Exception as e:
                safe_print(Fore.RED + f"Error llamando a g4f: {e}")
                continue

            text = raw_resp if isinstance(raw_resp, str) else str(raw_resp)

            if not text or not text.strip():
                safe_print(Fore.YELLOW + "(sin respuesta de texto de la IA — activa .debug para ver stdout/stderr)")
                continue

            if "<<REQ_DIR_TREE>>" in text:
                tree = build_dir_tree(cwd, max_depth=4)
                follow_messages = []
                follow_messages.append({"role":"user", "content": f"Árbol de directorios (base {cwd}):\n\n{tree}\n\nContinúa con tu respuesta."})
                try:
                    raw2 = ask_g4f_with_spinner(follow_messages, model=CURRENT_MODEL, provider_names=CURRENT_PROVIDER_NAMES)
                except Exception as e:
                    safe_print(Fore.RED + f"Error en follow-up: {e}")
                    continue
                text = raw2 if isinstance(raw2, str) else str(raw2)

            parsed = extract_json_from_text(text)

            if parsed is None and FORCE_EXEC_DEFAULT:
                safe_print(Fore.YELLOW + "[Forzando a la IA a devolver JSON conforme al system prompt...]")
                parsed = _request_json_followup(text, user_prompt)

            wants_create = user_requested_creation(user_prompt)
            asked_only_json = user_requested_only_json(user_prompt)

            if parsed and isinstance(parsed, dict) and ("files" in parsed or "run" in parsed):
                if asked_only_json:
                    safe_print(Fore.CYAN + "[La IA devolvió JSON, pediste 'solo JSON' -> No se crearán ni ejecutarán acciones]")
                    safe_print(Fore.GREEN + json.dumps(parsed, indent=2, ensure_ascii=False))
                    continue

                if "files" in parsed and not (wants_create or exec_flag or FORCE_EXEC_DEFAULT):
                    safe_print(Fore.YELLOW + "[La IA devolvió archivos en JSON, pero no detecto intención explícita de creación ni se ha forzado creación.]")
                    safe_print(Fore.YELLOW + "Si quieres crear los archivos añade --exec o activa la opción de forzar en el setup.")
                    safe_print(Fore.GREEN + json.dumps(parsed, indent=2, ensure_ascii=False))
                    if "run" not in parsed:
                        continue

                try:
                    created_paths = sanitize_and_prepare_files(parsed.get("files", []), cwd) if parsed.get("files") else []
                except Exception as e:
                    safe_print(Fore.RED + f"ERROR creando archivos: {e}")
                    safe_print("Respuesta completa de la IA:\n" + text)
                    continue

                if created_paths:
                    safe_print(Fore.GREEN + "📁 Archivos creados:")
                    for p in created_paths:
                        safe_print(Fore.GREEN + " - " + p)

                if "run" in parsed and isinstance(parsed.get("run"), list) and parsed.get("run"):
                    exec_now = FORCE_EXEC_DEFAULT or exec_flag
                    created, exec_resp = _handle_parsed_json_and_execute(parsed, cwd, exec_force=exec_now, force_flag=force_flag)
                    if exec_resp:
                        safe_print(exec_resp)
                continue

            safe_print(Fore.GREEN + text)
            continue

        # Si no es .ask: tratar como comando normal de shell
        res = run_command(raw_inp, cwd)
        cwd = res.get("cwd", cwd)
        if res.get("stdout"):
            safe_print(res["stdout"], end="")
        if res.get("stderr"):
            safe_print(Fore.RED + res["stderr"], end="")
        if not res.get("stdout") and not res.get("stderr"):
            safe_print(Style.DIM + f"[exit code {res.get('code')}]")

if __name__ == "__main__":
    load_config()
    if not os.path.exists(CONFIG_PATH):
        try:
            interactive_setup(quiet=True)
        except Exception as e:
            safe_print(Fore.YELLOW + f"Setup inicial falló o fue cancelado: {e}")

    try:
        main_loop()
    except Exception as e:
        safe_print(Fore.RED + f"Error inesperado: {e}")
        raise
