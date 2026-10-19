"""
Remove AI Tags by Jair Lima - v2.0
Remove metadados de imagens: marcações de procedência e de IA (C2PA / Content Credentials, XMP,
EXIF, IPTC). Útil para privacidade e para limpar arquivos antes de compartilhar.

Uso responsável: remover esses metadados não torna uma imagem "não gerada por IA". Redes sociais, leis e
contratos podem exigir que conteúdo gerado ou alterado por IA seja informado como tal; cumpra essas regras.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os, io, sys, struct, subprocess, threading, shutil, winreg, csv
from pathlib import Path
from datetime import datetime

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
    _BaseClass = TkinterDnD.Tk
except ImportError:
    HAS_DND = False
    _BaseClass = tk.Tk

TITLE   = "Remove AI Tags by Jair Lima"
VERSION = "2.0"
EXE_PATH = Path(sys.executable if getattr(sys, "frozen", False)
                else str(Path.home() / "bin" / "Remove AI Tags by Jair Lima.exe"))

IMG_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp"}

AI_KEYWORDS_BYTES = [
    b"c2pa", b"C2PA", b"jumbf", b"JUMBF",
    b"content credentials", b"Content Credentials",
    b"trainedAlgorithmicMedia", b"trainedalgorithmicmedia",
    b"digitalSourceType", b"digitalsourcetype",
    b"trainedAlgorithm", b"algorithmicMedia",
    b"GenerativeAI", b"generativeai", b"generative_ai",
    b"ai_generated", b"AI_generated", b"AI Generated",
    b"openai", b"OpenAI", b"dall-e", b"DALL-E", b"dalle",
    b"midjourney", b"Midjourney",
    b"stable diffusion", b"StableDiffusion", b"stable_diffusion",
    b"firefly", b"Firefly", b"adobe firefly",
    b"synthid", b"SynthID", b"imageCreator", b"ImageCreator",
    b"software: ai", b"Software: AI",
    b"Adobe Firefly", b"AdobeFirefly",
    b"Creator: AI", b"creator: ai",
]

SUSPICIOUS_EXIF = {
    "Software":         ["ai", "openai", "dall", "midjourney", "firefly", "stable", "generative"],
    "CreatorTool":      ["ai", "openai", "dall", "midjourney", "firefly", "stable", "generative", "canva ai"],
    "Artist":           ["ai", "openai", "artificial intelligence"],
    "ImageDescription": ["ai generated", "ai-generated", "created by ai"],
    "UserComment":      ["ai generated", "ai-generated"],
}

COLORS = dict(
    bg="#1e1e2e", surface="#181825", panel="#313244", muted="#45475a",
    text="#cdd6f4", subtext="#a6adc8", dim="#585b70",
    blue="#89b4fa", cyan="#89dceb", green="#a6e3a1",
    red="#f38ba8", yellow="#fab387", purple="#cba6f7",
)


# ── ExifTool ──────────────────────────────────────────────────────────────────

def _find_exiftool() -> str | None:
    candidates = [
        "exiftool",
        str(Path.home() / "bin" / "exiftool.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "ExifTool", "ExifTool.exe"),
        r"C:\Windows\exiftool.exe",
        r"C:\Program Files\ExifTool\exiftool.exe",
    ]
    for c in candidates:
        try:
            r = subprocess.run([c, "-ver"], capture_output=True, timeout=5)
            if r.returncode == 0:
                return c
        except Exception:
            pass
    return None

EXIFTOOL = _find_exiftool()


# ── JPEG parser ───────────────────────────────────────────────────────────────

def _jpeg_segments(data: bytes):
    pos = 2
    while pos < len(data):
        if data[pos] != 0xFF:
            yield None, pos, len(data), data[pos:]
            break
        m = data[pos + 1]
        if m in (0xD8, 0xD9):
            yield m, pos, pos + 2, b""
            pos += 2
            continue
        if m == 0xDA:
            yield m, pos, len(data), data[pos + 2:]
            break
        if 0xD0 <= m <= 0xD7:
            yield m, pos, pos + 2, b""
            pos += 2
            continue
        if pos + 4 > len(data):
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        end = pos + 2 + seg_len
        yield m, pos, end, data[pos + 4:end]
        pos = end


def strip_jpeg(raw: bytes) -> bytes:
    out = io.BytesIO()
    out.write(b"\xff\xd8")
    for m, start, end, payload in _jpeg_segments(raw):
        if m is None:
            out.write(raw[start:end])
            break
        if m == 0xDA:
            out.write(raw[start:end])
            break
        if m == 0xE0:                        # APP0 JFIF — manter
            out.write(raw[start:end])
        elif m == 0xE2 and payload[:12] == b"ICC_PROFILE\x00":  # ICC — manter
            out.write(raw[start:end])
        elif 0xE1 <= m <= 0xEF:              # APP1-APP15 — remover
            pass
        elif m == 0xFE:                      # COM — remover
            pass
        else:
            out.write(raw[start:end])
    return out.getvalue()


# ── PNG parser ────────────────────────────────────────────────────────────────

def strip_png(raw: bytes) -> bytes:
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        return raw
    out = io.BytesIO()
    out.write(raw[:8])
    pos = 8
    while pos + 12 <= len(raw):
        clen = struct.unpack(">I", raw[pos:pos + 4])[0]
        ctype = raw[pos + 4:pos + 8]
        cend = pos + 12 + clen
        if ctype not in (b"tEXt", b"zTXt", b"iTXt", b"eXIf"):
            out.write(raw[pos:cend])
        pos = cend
    return out.getvalue()


# ── Análise ───────────────────────────────────────────────────────────────────

def scan_file(filepath: str) -> list[dict]:
    findings = []
    try:
        raw = Path(filepath).read_bytes()
        raw_lower = raw.lower()
        seen = set()
        for kw in AI_KEYWORDS_BYTES:
            kl = kw.lower()
            if kl in seen or kl not in raw_lower:
                continue
            seen.add(kl)
            pos = raw_lower.find(kl)
            ctx = raw[max(0, pos - 15):min(len(raw), pos + len(kl) + 50)]
            ctx_str = "".join(c if 0x20 <= ord(c) < 0x7F else "·"
                              for c in ctx.decode("utf-8", errors="replace"))
            sev = "alto" if any(h in kl for h in [b"c2pa", b"jumbf", b"openai",
                                                    b"dall", b"synthid", b"generativeai",
                                                    b"trainedalg"]) else "medio"
            findings.append({"type": "Byte marker",
                              "keyword": kw.decode("utf-8", errors="replace"),
                              "context": ctx_str.strip(), "severity": sev})
        try:
            import piexif
            exif = piexif.load(filepath)
            for ifd in ("0th", "1st", "Exif"):
                for tag_id, val in exif.get(ifd, {}).items():
                    tag_name = piexif.TAGS.get(ifd, {}).get(tag_id, {}).get("name", "")
                    if tag_name not in SUSPICIOUS_EXIF:
                        continue
                    if isinstance(val, bytes):
                        val = val.decode("utf-8", errors="replace").rstrip("\x00")
                    val_s = str(val).lower()
                    if any(s in val_s for s in SUSPICIOUS_EXIF[tag_name]):
                        findings.append({"type": "EXIF tag",
                                         "keyword": f"{tag_name}: {str(val)[:60]}",
                                         "context": "", "severity": "alto"})
        except Exception:
            pass
    except Exception as e:
        findings.append({"type": "Erro", "keyword": str(e), "context": "", "severity": "info"})

    # Deduplicar
    seen_keys, unique = set(), []
    for f in findings:
        k = f["keyword"].lower()
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(f)
    return unique


# ── Remoção ───────────────────────────────────────────────────────────────────

def remove_metadata(src: str, dst: str, use_exiftool: bool = True) -> tuple[bool, str]:
    ext = Path(src).suffix.lower()
    size_before = os.path.getsize(src)

    if use_exiftool and EXIFTOOL:
        try:
            shutil.copy2(src, dst)
            r = subprocess.run([EXIFTOOL, "-all=", "-overwrite_original", dst],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                saved = size_before - os.path.getsize(dst)
                return True, f"ExifTool — {saved:+d} bytes removidos"
            return False, r.stderr.strip()
        except Exception as e:
            return False, str(e)

    try:
        raw = Path(src).read_bytes()
        if ext in (".jpg", ".jpeg"):
            clean = strip_jpeg(raw)
            method = "Parser JPEG"
        elif ext == ".png":
            clean = strip_png(raw)
            method = "Parser PNG"
        else:
            img = Image.open(src)
            buf = io.BytesIO()
            fmt = "JPEG" if ext in (".jpg", ".jpeg") else img.format or "PNG"
            img.save(buf, fmt, quality=95, exif=b"") if fmt == "JPEG" else img.save(buf, fmt)
            clean = buf.getvalue()
            method = f"Pillow {fmt}"

        Path(dst).write_bytes(clean)
        saved = size_before - len(clean)
        return True, f"{method} — {saved:+d} bytes ({size_before:,} → {len(clean):,})"
    except Exception as e:
        return False, str(e)


# ── Menu de contexto do Windows ───────────────────────────────────────────────

def register_context_menu(exe: str) -> tuple[bool, str]:
    try:
        for ext in IMG_EXTS:
            key_path = rf"Software\Classes\{ext}\shell\Remove AI Tags by Jair Lima"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Remover Tags de IA")
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, f"{exe},0")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path + r"\command") as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f'"{exe}" "%1"')
        unregister_universal_context_menu()
        return True, "Menu de contexto registrado para arquivos de imagem."
    except Exception as e:
        return False, str(e)


def unregister_universal_context_menu() -> bool:
    """Remove o registro legado feito sob '*' (aplicava a TODOS os tipos de
    arquivo, não só imagens — bug corrigido em 2026-07)."""
    base = r"Software\Classes\*\shell\Remove AI Tags by Jair Lima"
    try:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + r"\command")
        except FileNotFoundError:
            pass
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base)
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False


def check_context_menu() -> bool:
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                       r"Software\Classes\.png\shell\Remove AI Tags by Jair Lima")
        return True
    except FileNotFoundError:
        return False


# ── Relatório ─────────────────────────────────────────────────────────────────

def export_report(session_log: list[dict], dst_path: str):
    with open(dst_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Arquivo", "Marcadores encontrados", "Palavras-chave", "Limpeza", "Detalhes", "Data"])
        for entry in session_log:
            w.writerow([
                entry.get("file", ""),
                entry.get("markers", 0),
                "; ".join(entry.get("keywords", [])),
                "Sim" if entry.get("cleaned") else "Não",
                entry.get("msg", ""),
                entry.get("ts", ""),
            ])


# ── Aplicação ─────────────────────────────────────────────────────────────────

class App(_BaseClass):
    def __init__(self):
        super().__init__()
        self.title(TITLE)
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(bg=COLORS["bg"])

        self._files: list[str] = []
        self._selected: int = -1
        self._findings: dict[str, list] = {}
        self._clean_cache: dict[str, bytes] = {}   # {src: cleaned_bytes}
        self._session_log: list[dict] = []
        self._preview_refs = [None, None]          # before, after
        self._showing_after: dict[str, bool] = {}  # por arquivo

        self._build_ui()
        self._auto_setup()

        # Aceitar argumentos da linha de comando (menu de contexto)
        if len(sys.argv) > 1:
            self.after(200, lambda: self._load_paths(sys.argv[1:]))

    # ── Setup automático ──────────────────────────────────────────────────────

    def _auto_setup(self):
        # Migração: remove o registro legado sob '*' (aplicava a todos os arquivos)
        unregister_universal_context_menu()
        # Registrar menu de contexto se o .exe existir e ainda não estiver registrado
        if EXE_PATH.exists() and not check_context_menu():
            ok, msg = register_context_menu(str(EXE_PATH))
            self._ctx_menu_var.set("Menu contexto: ✓" if ok else "Menu contexto: ✗")
        elif check_context_menu():
            self._ctx_menu_var.set("Menu contexto: ✓")

    # ── Construção da UI ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        body = tk.Frame(self, bg=COLORS["bg"])
        body.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self._build_file_panel(body)
        self._build_preview_panel(body)
        self._build_analysis_panel(body)
        self._build_footer()

    def _build_header(self):
        h = tk.Frame(self, bg=COLORS["surface"], pady=8)
        h.pack(fill="x")
        tk.Label(h, text=TITLE, font=("Segoe UI", 15, "bold"),
                 bg=COLORS["surface"], fg=COLORS["text"]).pack(side="left", padx=16)

        right = tk.Frame(h, bg=COLORS["surface"])
        right.pack(side="right", padx=16)

        exif_text = f"ExifTool {EXIFTOOL} ✓" if EXIFTOOL else "ExifTool: não encontrado"
        exif_color = COLORS["green"] if EXIFTOOL else COLORS["red"]
        tk.Label(right, text=exif_text, font=("Segoe UI", 8),
                 bg=COLORS["surface"], fg=exif_color).pack(anchor="e")

        self._ctx_menu_var = tk.StringVar(value="Menu contexto: verificando...")
        tk.Label(right, textvariable=self._ctx_menu_var, font=("Segoe UI", 8),
                 bg=COLORS["surface"], fg=COLORS["subtext"]).pack(anchor="e")

        dnd_text = "Drag & Drop: ✓" if HAS_DND else "Drag & Drop: instale tkinterdnd2"
        tk.Label(right, text=dnd_text, font=("Segoe UI", 8),
                 bg=COLORS["surface"], fg=COLORS["green"] if HAS_DND else COLORS["yellow"]).pack(anchor="e")

    def _build_file_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg"], width=230)
        frame.pack(side="left", fill="y", padx=(0, 6))
        frame.pack_propagate(False)

        tk.Label(frame, text="Arquivos", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg"], fg=COLORS["blue"]).pack(anchor="w", pady=(4, 2))

        list_wrap = tk.Frame(frame, bg=COLORS["panel"])
        list_wrap.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(list_wrap, orient="vertical")
        self._lb = tk.Listbox(list_wrap, bg=COLORS["panel"], fg=COLORS["text"],
                              selectbackground=COLORS["muted"], selectforeground=COLORS["text"],
                              font=("Consolas", 9), relief="flat", bd=0,
                              yscrollcommand=sb.set, activestyle="none")
        sb.config(command=self._lb.yview)
        sb.pack(side="right", fill="y")
        self._lb.pack(fill="both", expand=True, padx=2, pady=2)
        self._lb.bind("<<ListboxSelect>>", self._on_select)

        if HAS_DND:
            self._lb.drop_target_register(DND_FILES)
            self._lb.dnd_bind("<<Drop>>", self._on_drop)

        # Botões
        for row in [
            [("+ Arquivos", self._add_files, COLORS["blue"]),
             ("+ Pasta",    self._add_folder, COLORS["cyan"])],
            [("Remover",    self._remove_file, COLORS["red"]),
             ("Limpar tudo",self._clear_all,   COLORS["dim"])],
        ]:
            f = tk.Frame(frame, bg=COLORS["bg"])
            f.pack(fill="x", pady=1)
            for txt, cmd, col in row:
                self._btn(f, txt, cmd, col).pack(side="left", padx=(0, 3), fill="x", expand=True)

        # Contador
        self._count_var = tk.StringVar(value="0 arquivos")
        tk.Label(frame, textvariable=self._count_var, font=("Segoe UI", 8),
                 bg=COLORS["bg"], fg=COLORS["dim"]).pack(anchor="w", pady=2)

    def _build_preview_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg"], width=340)
        frame.pack(side="left", fill="y", padx=(0, 6))
        frame.pack_propagate(False)

        hdr = tk.Frame(frame, bg=COLORS["bg"])
        hdr.pack(fill="x", pady=(4, 2))
        tk.Label(hdr, text="Prévia", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg"], fg=COLORS["blue"]).pack(side="left")
        self._toggle_btn = self._btn(hdr, "Ver: Original", self._toggle_preview,
                                     COLORS["purple"], w=14)
        self._toggle_btn.pack(side="right")

        # Duas labels de preview (antes / depois)
        pf = tk.Frame(frame, bg=COLORS["surface"])
        pf.pack(fill="both", expand=True)

        self._lbl_before_title = tk.Label(pf, text="ORIGINAL", font=("Segoe UI", 8, "bold"),
                                          bg=COLORS["surface"], fg=COLORS["yellow"])
        self._lbl_before_title.pack()
        self._lbl_before = tk.Label(pf, bg=COLORS["surface"], text="Nenhuma imagem",
                                    fg=COLORS["dim"], font=("Segoe UI", 9))
        self._lbl_before.pack(fill="both", expand=True)
        self._lbl_before_info = tk.Label(pf, text="", font=("Segoe UI", 8),
                                         bg=COLORS["surface"], fg=COLORS["subtext"])
        self._lbl_before_info.pack()

        ttk.Separator(pf, orient="horizontal").pack(fill="x", pady=4)

        self._lbl_after_title = tk.Label(pf, text="APÓS LIMPEZA", font=("Segoe UI", 8, "bold"),
                                         bg=COLORS["surface"], fg=COLORS["green"])
        self._lbl_after_title.pack()
        self._lbl_after = tk.Label(pf, bg=COLORS["surface"], text="Não processado ainda",
                                   fg=COLORS["dim"], font=("Segoe UI", 9))
        self._lbl_after.pack(fill="both", expand=True)
        self._lbl_after_info = tk.Label(pf, text="", font=("Segoe UI", 8),
                                        bg=COLORS["surface"], fg=COLORS["subtext"])
        self._lbl_after_info.pack()

    def _build_analysis_panel(self, parent):
        frame = tk.Frame(parent, bg=COLORS["bg"])
        frame.pack(side="left", fill="both", expand=True)

        tk.Label(frame, text="Análise de Metadados", font=("Segoe UI", 10, "bold"),
                 bg=COLORS["bg"], fg=COLORS["blue"]).pack(anchor="w", pady=(4, 2))

        self._txt = scrolledtext.ScrolledText(
            frame, bg=COLORS["surface"], fg=COLORS["text"],
            font=("Consolas", 9), relief="flat", bd=0, state="disabled", wrap="word")
        self._txt.pack(fill="both", expand=True)
        for tag, color in [("alto", COLORS["red"]), ("medio", COLORS["yellow"]),
                           ("info", COLORS["blue"]), ("ok", COLORS["green"]),
                           ("dim", COLORS["dim"]), ("header", COLORS["purple"])]:
            self._txt.tag_configure(tag, foreground=color,
                                    font=("Consolas", 9, "bold") if tag == "header" else ("Consolas", 9))

        # Botões de ação (2 linhas)
        for row in [
            [("Analisar Arquivo",  self._analyze_one,  COLORS["blue"]),
             ("Analisar Todos",    self._analyze_all,  COLORS["cyan"])],
            [("Limpar Arquivo",    self._clean_one,    COLORS["green"]),
             ("Limpar Todos",      self._clean_all,    COLORS["purple"])],
        ]:
            f = tk.Frame(frame, bg=COLORS["bg"])
            f.pack(fill="x", pady=2)
            for txt, cmd, col in row:
                self._btn(f, txt, cmd, col).pack(side="left", padx=(0, 4), fill="x", expand=True)

        # Opções
        opt = tk.Frame(frame, bg=COLORS["bg"])
        opt.pack(fill="x", pady=2)
        self._opt_overwrite  = tk.BooleanVar(value=False)
        self._opt_exiftool   = tk.BooleanVar(value=bool(EXIFTOOL))
        self._opt_subfolder  = tk.BooleanVar(value=True)
        for text, var in [("Sobrescrever original", self._opt_overwrite),
                          ("Usar ExifTool",          self._opt_exiftool),
                          ("Subpastas ao add. pasta",self._opt_subfolder)]:
            tk.Checkbutton(opt, text=text, variable=var, bg=COLORS["bg"], fg=COLORS["subtext"],
                           selectcolor=COLORS["panel"], activebackground=COLORS["bg"],
                           activeforeground=COLORS["text"], font=("Segoe UI", 8)).pack(side="left", padx=4)

        # Relatório e menu contexto
        bot = tk.Frame(frame, bg=COLORS["bg"])
        bot.pack(fill="x", pady=(4, 0))
        self._btn(bot, "Exportar Relatório CSV",    self._export_report,         COLORS["yellow"]).pack(side="left", padx=(0, 4))
        self._btn(bot, "Registrar Menu Contexto",   self._register_ctx_menu_ui,  COLORS["cyan"]).pack(side="left")

    def _build_footer(self):
        f = tk.Frame(self, bg=COLORS["surface"], pady=6)
        f.pack(fill="x", side="bottom")
        self._progress = ttk.Progressbar(f, mode="determinate", length=280)
        self._progress.pack(side="left", padx=10)
        self._status = tk.StringVar(value="Pronto. Arraste imagens ou use o botão + Arquivos.")
        tk.Label(f, textvariable=self._status, bg=COLORS["surface"],
                 fg=COLORS["subtext"], font=("Segoe UI", 9)).pack(side="left", padx=6)

    # ── Helpers UI ────────────────────────────────────────────────────────────

    def _btn(self, parent, text, cmd, color, w=None):
        kw = {"width": w} if w else {}
        return tk.Button(parent, text=text, command=cmd, bg=COLORS["panel"], fg=color,
                         activebackground=COLORS["muted"], activeforeground=color,
                         relief="flat", bd=0, font=("Segoe UI", 9),
                         cursor="hand2", padx=8, pady=4, **kw)

    def _write_txt(self, text: str, tag: str = "dim"):
        self._txt.config(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.insert("end", text, tag)
        self._txt.config(state="disabled")

    def _append_txt(self, text: str, tag: str = "dim"):
        self._txt.config(state="normal")
        self._txt.insert("end", text, tag)
        self._txt.config(state="disabled")
        self._txt.see("end")

    # ── Drag & Drop ───────────────────────────────────────────────────────────

    def _on_drop(self, event):
        # tkinterdnd2 retorna caminhos entre {} se houver espaços
        raw = event.data.strip()
        paths = []
        if raw.startswith("{"):
            import re
            paths = re.findall(r"\{([^}]+)\}", raw)
            remainder = re.sub(r"\{[^}]+\}", "", raw).split()
            paths += remainder
        else:
            paths = raw.split()
        self._load_paths([p.strip() for p in paths if p.strip()])

    # ── Carregamento de arquivos ──────────────────────────────────────────────

    def _load_paths(self, paths: list[str]):
        added = 0
        for p in paths:
            p = p.strip('"').strip("'")
            if os.path.isfile(p) and Path(p).suffix.lower() in IMG_EXTS and p not in self._files:
                self._files.append(p)
                self._lb.insert("end", Path(p).name)
                added += 1
        self._update_count()
        if added:
            self._lb.selection_clear(0, "end")
            self._lb.selection_set(len(self._files) - 1)
            self._lb.see(len(self._files) - 1)
            self._on_select()

    def _add_files(self):
        paths = filedialog.askopenfilenames(
            title="Selecionar imagens",
            filetypes=[("Imagens", "*.jpg *.jpeg *.png *.webp *.tiff *.tif *.bmp"),
                       ("Todos", "*.*")])
        self._load_paths(list(paths))

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Selecionar pasta")
        if not folder:
            return
        glob_fn = Path(folder).rglob if self._opt_subfolder.get() else Path(folder).glob
        paths = [str(p) for p in glob_fn("*") if p.suffix.lower() in IMG_EXTS]
        if not paths:
            messagebox.showinfo("Pasta vazia", "Nenhuma imagem encontrada na pasta selecionada.")
            return
        self._load_paths(sorted(paths))
        self._status.set(f"{len(paths)} imagem(ns) encontrada(s) em {Path(folder).name}")

    def _remove_file(self):
        sel = self._lb.curselection()
        if not sel:
            return
        idx = sel[0]
        fp = self._files.pop(idx)
        self._lb.delete(idx)
        self._findings.pop(fp, None)
        self._clean_cache.pop(fp, None)
        self._selected = -1
        self._update_count()
        self._write_txt("", "dim")
        self._clear_previews()

    def _clear_all(self):
        self._lb.delete(0, "end")
        self._files.clear()
        self._findings.clear()
        self._clean_cache.clear()
        self._selected = -1
        self._update_count()
        self._write_txt("", "dim")
        self._clear_previews()

    def _update_count(self):
        n = len(self._files)
        self._count_var.set(f"{n} arquivo(s)")

    # ── Seleção ───────────────────────────────────────────────────────────────

    def _on_select(self, event=None):
        sel = self._lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._files):
            return
        self._selected = idx
        fp = self._files[idx]
        self._load_preview_before(fp)
        self._load_preview_after(fp)
        if fp in self._findings:
            self._show_findings(fp, self._findings[fp])
        else:
            self._write_txt(f"Arquivo: {Path(fp).name}\n\nClique em 'Analisar Arquivo'.\n", "dim")

    # ── Preview ───────────────────────────────────────────────────────────────

    def _clear_previews(self):
        for lbl in (self._lbl_before, self._lbl_after):
            lbl.config(image="", text="Nenhuma imagem", fg=COLORS["dim"])
        self._lbl_before_info.config(text="")
        self._lbl_after_info.config(text="")
        self._preview_refs = [None, None]

    def _make_thumb(self, src, max_w=310, max_h=200) -> ImageTk.PhotoImage | None:
        try:
            img = Image.open(src) if isinstance(src, str) else Image.open(io.BytesIO(src))
            img.thumbnail((max_w, max_h), Image.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception:
            return None

    def _load_preview_before(self, fp: str):
        photo = self._make_thumb(fp)
        if photo:
            self._lbl_before.config(image=photo, text="")
            self._preview_refs[0] = photo
            size = os.path.getsize(fp)
            markers = len(self._findings.get(fp, []))
            badge = f"{markers} marker(s)" if markers else "analisar para verificar"
            self._lbl_before_info.config(text=f"{size:,} bytes  |  {badge}")
        else:
            self._lbl_before.config(image="", text="Sem prévia", fg=COLORS["dim"])

    def _load_preview_after(self, fp: str):
        if fp in self._clean_cache:
            clean_bytes = self._clean_cache[fp]
            photo = self._make_thumb(clean_bytes)
            if photo:
                self._lbl_after.config(image=photo, text="")
                self._preview_refs[1] = photo
                saved = os.path.getsize(fp) - len(clean_bytes)
                pct = saved / os.path.getsize(fp) * 100 if os.path.getsize(fp) else 0
                self._lbl_after_info.config(
                    text=f"{len(clean_bytes):,} bytes  |  LIMPO  |  -{abs(saved):,} bytes ({pct:.1f}%)",
                    fg=COLORS["green"])
                return
        self._lbl_after.config(image="", text="Processe o arquivo\npara ver o resultado", fg=COLORS["dim"])
        self._lbl_after_info.config(text="")
        self._preview_refs[1] = None

    def _toggle_preview(self):
        # Não há muito o que alternar visualmente (antes/depois já estão visíveis).
        # Este botão ativa análise rápida + limpeza prévia (pré-processamento para preview).
        if self._selected < 0 or self._selected >= len(self._files):
            return
        fp = self._files[self._selected]
        if fp not in self._clean_cache:
            self._status.set("Gerando prévia limpa...")
            self.update_idletasks()
            dst = Path(fp)
            tmp = str(dst.parent / f"__tmp_preview__{dst.name}")
            ok, msg = remove_metadata(fp, tmp, use_exiftool=self._opt_exiftool.get())
            if ok:
                self._clean_cache[fp] = Path(tmp).read_bytes()
                os.remove(tmp)
            self._load_preview_after(fp)
            self._status.set("Prévia limpa gerada." if ok else f"Erro: {msg}")

    # ── Análise ───────────────────────────────────────────────────────────────

    def _analyze_one(self):
        if self._selected < 0:
            messagebox.showinfo("Aviso", "Selecione um arquivo na lista.")
            return
        fp = self._files[self._selected]
        self._status.set(f"Analisando {Path(fp).name}...")
        self.update_idletasks()
        findings = scan_file(fp)
        self._findings[fp] = findings
        self._show_findings(fp, findings)
        self._load_preview_before(fp)
        self._update_count()
        self._status.set("Análise concluída.")

    def _analyze_all(self):
        if not self._files:
            messagebox.showinfo("Aviso", "Adicione arquivos primeiro.")
            return

        def worker():
            total = len(self._files)
            positives = 0
            for i, fp in enumerate(self._files):
                self._status.set(f"Analisando {i+1}/{total}: {Path(fp).name}")
                self._progress["value"] = (i + 1) / total * 100
                self.update_idletasks()
                f = scan_file(fp)
                self._findings[fp] = f
                if f:
                    positives += 1
                    self._lb.itemconfig(i, fg=COLORS["red"])
                else:
                    self._lb.itemconfig(i, fg=COLORS["green"])
            self._progress["value"] = 0
            self._status.set(f"Análise completa: {positives}/{total} com marcadores de IA.")
            self._write_txt(
                f"Análise completa: {total} arquivo(s)\n"
                f"  Com marcadores de IA: {positives}\n"
                f"  Limpos:               {total - positives}\n\n"
                "Arquivos em vermelho contêm marcadores.\n"
                "Selecione um para ver os detalhes.\n", "info")

        threading.Thread(target=worker, daemon=True).start()

    def _show_findings(self, fp: str, findings: list[dict]):
        self._txt.config(state="normal")
        self._txt.delete("1.0", "end")
        name = Path(fp).name
        self._txt.insert("end", f"{name}\n", "header")
        self._txt.insert("end", f"{os.path.getsize(fp):,} bytes\n\n", "dim")
        if not findings:
            self._txt.insert("end", "Nenhum marcador de IA detectado.\n", "ok")
            self._txt.insert("end", "\nArquivo parece limpo nos metadados verificados.\n", "dim")
            self._txt.insert("end", "\nNota: watermarks SynthID nos pixels requerem ExifTool.\n", "dim")
        else:
            self._txt.insert("end", f"⚠  {len(findings)} marcador(es) encontrado(s):\n\n", "alto")
            for f in findings:
                icon = "🔴" if f["severity"] == "alto" else "🟡"
                self._txt.insert("end", f"{icon} [{f['type']}] ", "dim")
                self._txt.insert("end", f"{f['keyword']}\n", f["severity"])
                if f.get("context"):
                    self._txt.insert("end", f"   ...{f['context'][:70]}...\n", "dim")
            self._txt.insert("end", "\nUse 'Limpar Arquivo' para remover esses metadados.\n", "info")
        self._txt.config(state="disabled")

    # ── Limpeza ───────────────────────────────────────────────────────────────

    def _do_clean(self, file_list: list[str]):
        overwrite = self._opt_overwrite.get()
        use_exif  = self._opt_exiftool.get()

        def worker():
            total = len(file_list)
            ok_count = 0
            self._txt.config(state="normal")
            self._txt.delete("1.0", "end")
            self._txt.insert("end", f"Limpando {total} arquivo(s)...\n\n", "header")
            self._txt.config(state="disabled")

            for i, fp in enumerate(file_list):
                self._status.set(f"Limpando {i+1}/{total}: {Path(fp).name}")
                self._progress["value"] = (i + 1) / total * 100
                self.update_idletasks()

                dst = fp if overwrite else str(
                    Path(fp).parent / f"{Path(fp).stem}-limpo{Path(fp).suffix}")

                ok, msg = remove_metadata(fp, dst, use_exiftool=use_exif)

                if ok:
                    ok_count += 1
                    # Cache para preview após
                    self._clean_cache[fp] = Path(dst).read_bytes()
                    self._findings.pop(fp, None)
                    # Atualizar cor na listbox
                    try:
                        idx = self._files.index(fp)
                        self._lb.itemconfig(idx, fg=COLORS["green"])
                    except ValueError:
                        pass

                self._session_log.append({
                    "file": Path(fp).name,
                    "markers": len(self._findings.get(fp, [])),
                    "keywords": [f["keyword"] for f in self._findings.get(fp, [])],
                    "cleaned": ok,
                    "msg": msg,
                    "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

                icon = "✓" if ok else "✗"
                self._append_txt(f"{icon} {Path(fp).name}\n",
                                 "ok" if ok else "alto")
                dst_name = Path(dst).name
                self._append_txt(f"  → {dst_name}\n  {msg}\n\n", "dim")

            self._progress["value"] = 0
            self._status.set(f"{ok_count}/{total} arquivo(s) limpo(s) com sucesso.")

            # Atualizar preview se o arquivo selecionado foi limpo
            if self._selected >= 0 and self._selected < len(self._files):
                self.after(0, lambda: self._load_preview_after(self._files[self._selected]))

        threading.Thread(target=worker, daemon=True).start()

    def _clean_one(self):
        if self._selected < 0:
            messagebox.showinfo("Aviso", "Selecione um arquivo na lista.")
            return
        self._do_clean([self._files[self._selected]])

    def _clean_all(self):
        if not self._files:
            messagebox.showinfo("Aviso", "Adicione arquivos primeiro.")
            return
        if not messagebox.askyesno("Confirmar", f"Limpar {len(self._files)} arquivo(s)?"):
            return
        self._do_clean(self._files[:])

    # ── Relatório ─────────────────────────────────────────────────────────────

    def _export_report(self):
        if not self._session_log:
            messagebox.showinfo("Relatório", "Nenhuma operação registrada ainda.\nAnalise ou limpe arquivos primeiro.")
            return
        dst = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
            initialfile=f"relatorio_ai_tags_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
        if not dst:
            return
        export_report(self._session_log, dst)
        self._status.set(f"Relatório exportado: {Path(dst).name}")
        messagebox.showinfo("Relatório", f"Salvo em:\n{dst}")

    # ── Menu de contexto ──────────────────────────────────────────────────────

    def _register_ctx_menu_ui(self):
        if not EXE_PATH.exists():
            messagebox.showwarning(
                "Executável não encontrado",
                f"O arquivo .exe não foi encontrado em:\n{EXE_PATH}\n\n"
                "Execute o build.bat primeiro para gerar o executável.")
            return
        ok, msg = register_context_menu(str(EXE_PATH))
        self._ctx_menu_var.set("Menu contexto: ✓" if ok else "Menu contexto: ✗")
        if ok:
            messagebox.showinfo("Sucesso",
                "Menu de contexto registrado!\n\n"
                "Agora você pode clicar com botão direito em qualquer imagem\n"
                "e escolher 'Remover Tags de IA'.")
        else:
            messagebox.showerror("Erro", f"Falha ao registrar:\n{msg}")


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
