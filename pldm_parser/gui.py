"""Tkinter GUI for the PLDM-over-MCTP parser.

Run with:
    python -m pldm_parser.gui
or use the launcher script ``run_app.py`` / ``run_app.bat`` at the project root.

Features:
- Severity-tagged notes (info/warning/error) with colored rows.
- Live input syntax validation while typing.
- Debug log panel that captures the parser logger output.
- Exception-guarded handlers (no silent crashes from bad input).
"""

from __future__ import annotations

import logging
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .hexutil import HexParseError, parse_hex_stream, to_hex
from .parser import Note, ParsedFrame, Severity, parse_frame
from .pldm_platform import GetPdrRequest, GetPdrResponse


APP_TITLE = "PLDM-over-MCTP Frame Parser"
MAX_INPUT_CHARS = 1_000_000  # protective upper bound on pasted text

EXAMPLE_REQ = (
    "72:00:10:05:00:41:30:7F:00:40:1A:B4:01:09:11:C8\n"
    "01:88:02:51:00:00:00:00:00:00:00:00:01:50:00:00\n"
    "00"
)
EXAMPLE_RSP = (
    "72:00:00:09:00:40:10:7F:00:41:1A:B4:01:11:09:C0\n"
    "01:08:02:51:00:02:00:00:00:00:00:00:00:05:13:00\n"
    "01:00:00:00:01:01:00:00:09:00:01:00:01:15:00:00\n"
    "01:01:08"
)

# Color palette (light theme).
COLOR_BG = "#f5f6f8"
COLOR_PANEL = "#ffffff"
COLOR_ACCENT = "#0a64a8"
COLOR_OK = "#137333"
COLOR_WARN = "#b06000"
COLOR_ERR = "#c5221f"
COLOR_INFO = "#1a73e8"
COLOR_MUTED = "#5f6368"


class _TextHandler(logging.Handler):
    """Forwards logging records into a Tk Text widget."""

    def __init__(self, widget: tk.Text):
        super().__init__()
        self.widget = widget
        self.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S"
        ))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        tag = {
            logging.ERROR: "err",
            logging.WARNING: "warn",
            logging.INFO: "info",
            logging.DEBUG: "muted",
        }.get(record.levelno, "muted")
        try:
            self.widget.after(0, self._append, msg + "\n", tag)
        except RuntimeError:
            pass

    def _append(self, msg: str, tag: str) -> None:
        try:
            self.widget.configure(state=tk.NORMAL)
            self.widget.insert(tk.END, msg, tag)
            self.widget.see(tk.END)
            self.widget.configure(state=tk.DISABLED)
        except tk.TclError:
            pass


class PldmParserApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x780")
        self.minsize(960, 620)
        self.configure(bg=COLOR_BG)

        self._log_handler: Optional[_TextHandler] = None

        self._build_style()
        self._build_menu()
        self._build_layout()
        self._install_logging()

        # Catch any uncaught Tk callback exception with a friendly dialog.
        self.report_callback_exception = self._report_callback_exception

        self.input_text.bind("<<Modified>>", self._on_input_modified)
        self._validate_input()

    # ------------------------------------------------------------------ UI
    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=COLOR_BG)
        style.configure("Panel.TFrame", background=COLOR_PANEL, relief="flat")
        style.configure("TLabel", background=COLOR_BG, foreground="#202124")
        style.configure("Header.TLabel", font=("Segoe UI", 11, "bold"),
                        foreground=COLOR_ACCENT, background=COLOR_BG)
        style.configure("Muted.TLabel", foreground=COLOR_MUTED, background=COLOR_BG)
        style.configure("Status.TLabel", padding=(10, 5), background="#e7e9ee")
        style.configure("StatusOK.TLabel", padding=(10, 5), background="#e6f4ea",
                        foreground=COLOR_OK)
        style.configure("StatusWarn.TLabel", padding=(10, 5), background="#fef7e0",
                        foreground=COLOR_WARN)
        style.configure("StatusErr.TLabel", padding=(10, 5), background="#fce8e6",
                        foreground=COLOR_ERR)
        style.configure("TButton", padding=(10, 6))
        style.configure("Accent.TButton", padding=(12, 6),
                        foreground="white", background=COLOR_ACCENT)
        style.map("Accent.TButton",
                  background=[("active", "#084e85"), ("pressed", "#063e6b")])
        style.configure("TNotebook.Tab", padding=(14, 6))
        style.configure("Treeview", rowheight=22, background=COLOR_PANEL,
                        fieldbackground=COLOR_PANEL)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open hex file...", command=self.on_open_file,
                             accelerator="Ctrl+O")
        filemenu.add_command(label="Save report...", command=self.on_save_report,
                             accelerator="Ctrl+S")
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filemenu)

        examples = tk.Menu(menubar, tearoff=0)
        examples.add_command(label="Load GetPDR Request example",
                             command=lambda: self.set_input(EXAMPLE_REQ))
        examples.add_command(label="Load GetPDR Response example",
                             command=lambda: self.set_input(EXAMPLE_RSP))
        menubar.add_cascade(label="Examples", menu=examples)

        viewmenu = tk.Menu(menubar, tearoff=0)
        self.show_log_var = tk.BooleanVar(value=True)
        viewmenu.add_checkbutton(label="Show debug log", variable=self.show_log_var,
                                 command=self._toggle_log)
        viewmenu.add_command(label="Clear debug log", command=self._clear_log)
        menubar.add_cascade(label="View", menu=viewmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.on_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.config(menu=menubar)
        self.bind_all("<Control-o>", lambda _e: self.on_open_file())
        self.bind_all("<Control-s>", lambda _e: self.on_save_report())
        self.bind_all("<Control-Return>", lambda _e: self.on_parse())

    def _build_layout(self) -> None:
        toolbar = ttk.Frame(self, padding=(10, 8))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(toolbar, text="Intel sideband prefix:").pack(side=tk.LEFT)
        self.prefix_var = tk.StringVar(value="auto")
        for label in ("auto", "force on", "force off"):
            ttk.Radiobutton(toolbar, text=label, value=label,
                            variable=self.prefix_var).pack(side=tk.LEFT, padx=4)

        ttk.Button(toolbar, text="Parse  (Ctrl+Enter)", style="Accent.TButton",
                   command=self.on_parse).pack(side=tk.RIGHT)
        ttk.Button(toolbar, text="Clear", command=self.on_clear).pack(side=tk.RIGHT, padx=6)
        ttk.Button(toolbar, text="Validate", command=self._validate_input).pack(
            side=tk.RIGHT, padx=6)

        self.vpaned = ttk.Panedwindow(self, orient=tk.VERTICAL)
        self.vpaned.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        top_frame = ttk.Frame(self.vpaned)
        self.vpaned.add(top_frame, weight=4)

        paned = ttk.Panedwindow(top_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # ----- LEFT: input -----
        left = ttk.Frame(paned, padding=8, style="Panel.TFrame")
        paned.add(left, weight=1)

        ttk.Label(left, text="Hex frame input", style="Header.TLabel").pack(anchor=tk.W)
        ttk.Label(left,
                  text="Bytes separated by ':', spaces, '-', ',' or ';'. Newlines OK.",
                  style="Muted.TLabel").pack(anchor=tk.W, pady=(0, 4))

        input_container = ttk.Frame(left)
        input_container.pack(fill=tk.BOTH, expand=True)
        self.input_text = tk.Text(input_container, wrap=tk.WORD, font=("Consolas", 10),
                                  height=14, undo=True, maxundo=200,
                                  bg=COLOR_PANEL, relief="solid", borderwidth=1)
        in_scroll = ttk.Scrollbar(input_container, orient=tk.VERTICAL,
                                  command=self.input_text.yview)
        self.input_text.configure(yscrollcommand=in_scroll.set)
        self.input_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        in_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.input_text.insert("1.0", EXAMPLE_RSP)

        self.validation_var = tk.StringVar(value="")
        self.validation_lbl = ttk.Label(left, textvariable=self.validation_var,
                                        style="Muted.TLabel")
        self.validation_lbl.pack(anchor=tk.W, pady=(4, 0))

        # ----- RIGHT: notebook -----
        right = ttk.Frame(paned, padding=8, style="Panel.TFrame")
        paned.add(right, weight=2)

        ttk.Label(right, text="Decoded frame", style="Header.TLabel").pack(anchor=tk.W)
        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        # Tab 1 - structured tree
        tree_frame = ttk.Frame(notebook)
        notebook.add(tree_frame, text="Structured")
        self.tree = ttk.Treeview(tree_frame, columns=("value",), show="tree headings")
        self.tree.heading("#0", text="Field")
        self.tree.heading("value", text="Value")
        self.tree.column("#0", width=340, anchor=tk.W)
        self.tree.column("value", width=560, anchor=tk.W)
        self.tree.tag_configure("info",    foreground=COLOR_INFO)
        self.tree.tag_configure("warning", foreground=COLOR_WARN)
        self.tree.tag_configure("error",   foreground=COLOR_ERR,
                                font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("section", font=("Segoe UI", 9, "bold"))
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                      command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 2 - text report
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text="Text report")
        self.report_text = tk.Text(text_frame, wrap=tk.NONE, font=("Consolas", 10),
                                   bg=COLOR_PANEL, relief="solid", borderwidth=1)
        ys = ttk.Scrollbar(text_frame, orient=tk.VERTICAL,
                           command=self.report_text.yview)
        xs = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL,
                           command=self.report_text.xview)
        self.report_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set,
                                   state=tk.DISABLED)
        self.report_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        # Tab 3 - notes list
        notes_frame = ttk.Frame(notebook)
        notebook.add(notes_frame, text="Notes")
        self.notes_list = ttk.Treeview(notes_frame, columns=("msg",),
                                       show="headings", height=8)
        self.notes_list.heading("msg", text="Message")
        self.notes_list.column("msg", anchor=tk.W, width=900)
        ny = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL,
                           command=self.notes_list.yview)
        self.notes_list.configure(yscrollcommand=ny.set)
        self.notes_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ny.pack(side=tk.RIGHT, fill=tk.Y)
        self.notes_list.tag_configure("info",    foreground=COLOR_INFO)
        self.notes_list.tag_configure("warning", foreground=COLOR_WARN)
        self.notes_list.tag_configure("error",   foreground=COLOR_ERR,
                                      font=("Segoe UI", 9, "bold"))

        # ----- BOTTOM: log -----
        self.log_frame = ttk.Frame(self.vpaned)
        self.vpaned.add(self.log_frame, weight=1)
        ttk.Label(self.log_frame, text="Debug log",
                  style="Header.TLabel").pack(anchor=tk.W, padx=2)
        log_container = ttk.Frame(self.log_frame)
        log_container.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(log_container, height=8, wrap=tk.NONE,
                                font=("Consolas", 9), bg="#1e1e1e", fg="#dcdcdc",
                                insertbackground="#dcdcdc", state=tk.DISABLED,
                                relief="solid", borderwidth=1)
        lys = ttk.Scrollbar(log_container, orient=tk.VERTICAL,
                            command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=lys.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lys.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.tag_configure("err",   foreground="#ff7b72",
                                    font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("warn",  foreground="#f0b400")
        self.log_text.tag_configure("info",  foreground="#79c0ff")
        self.log_text.tag_configure("muted", foreground="#8b949e")

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        self.status_lbl = ttk.Label(self, textvariable=self.status_var,
                                    style="Status.TLabel", anchor=tk.W)
        self.status_lbl.pack(side=tk.BOTTOM, fill=tk.X)

    def _install_logging(self) -> None:
        logger = logging.getLogger("pldm_parser")
        logger.setLevel(logging.DEBUG)
        handler = _TextHandler(self.log_text)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        self._log_handler = handler
        logger.info("GUI initialized.")

    # --------------------------------------------------------------- helpers
    def _set_status(self, msg: str, severity: Optional[Severity] = None) -> None:
        style = {
            Severity.INFO:    "Status.TLabel",
            Severity.WARNING: "StatusWarn.TLabel",
            Severity.ERROR:   "StatusErr.TLabel",
            None:             "StatusOK.TLabel",
        }[severity]
        self.status_lbl.configure(style=style)
        self.status_var.set(msg)

    def _report_callback_exception(self, exc, val, tb) -> None:
        logging.getLogger("pldm_parser").error(
            "Unhandled exception in callback: %s", val, exc_info=(exc, val, tb)
        )
        messagebox.showerror(
            APP_TITLE,
            "An unexpected error occurred:\n\n"
            f"{exc.__name__}: {val}\n\n"
            "Details have been written to the debug log.",
        )
        self._set_status(f"Internal error: {exc.__name__}: {val}", Severity.ERROR)

    # --------------------------------------------------------------- actions
    def set_input(self, text: str) -> None:
        if len(text) > MAX_INPUT_CHARS:
            messagebox.showwarning(
                APP_TITLE,
                f"Input truncated to {MAX_INPUT_CHARS} characters (was {len(text)}).",
            )
            text = text[:MAX_INPUT_CHARS]
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert("1.0", text)
        self._set_status("Example loaded. Press Parse.")
        self._validate_input()

    def on_clear(self) -> None:
        self.input_text.delete("1.0", tk.END)
        self._clear_results()
        self._set_status("Cleared.")
        self._validate_input()

    def on_open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open hex file",
            filetypes=[("Text/hex files", "*.txt *.hex *.log"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(MAX_INPUT_CHARS + 1)
        except (OSError, UnicodeError) as exc:
            messagebox.showerror(APP_TITLE, f"Cannot open file:\n{exc}")
            self._set_status(f"Open failed: {exc}", Severity.ERROR)
            return
        self.set_input(content)

    def on_save_report(self) -> None:
        report = self.report_text.get("1.0", tk.END).strip()
        if not report:
            messagebox.showinfo(APP_TITLE, "Nothing to save -- parse a frame first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Cannot save file:\n{exc}")
            self._set_status(f"Save failed: {exc}", Severity.ERROR)
            return
        self._set_status(f"Saved report to {path}")

    def on_about(self) -> None:
        messagebox.showinfo(
            APP_TITLE,
            "PLDM-over-MCTP Frame Parser\n\n"
            "Decodes Intel sideband prefix, MCTP transport,\n"
            "PLDM common header and PLDM Platform GetPDR (0x51).\n\n"
            "References: DMTF DSP0240, DSP0245, DSP0248, DSP0236.",
        )

    def _toggle_log(self) -> None:
        if self.show_log_var.get():
            try:
                self.vpaned.add(self.log_frame, weight=1)
            except tk.TclError:
                pass
        else:
            try:
                self.vpaned.forget(self.log_frame)
            except tk.TclError:
                pass

    def _clear_log(self) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _on_input_modified(self, _event=None) -> None:
        try:
            self.input_text.edit_modified(False)
        except tk.TclError:
            return
        self._validate_input()

    def _validate_input(self) -> None:
        raw_text = self.input_text.get("1.0", tk.END)
        if len(raw_text) > MAX_INPUT_CHARS:
            self.validation_var.set(
                f"Input too large ({len(raw_text)} chars > {MAX_INPUT_CHARS})."
            )
            self.validation_lbl.configure(foreground=COLOR_ERR)
            return
        stripped = raw_text.strip()
        if not stripped:
            self.validation_var.set("Empty input.")
            self.validation_lbl.configure(foreground=COLOR_MUTED)
            return
        try:
            data = parse_hex_stream(stripped)
        except HexParseError as exc:
            self.validation_var.set(f"Invalid hex: {exc}")
            self.validation_lbl.configure(foreground=COLOR_ERR)
            return
        self.validation_var.set(f"OK -- {len(data)} byte(s) ready to parse.")
        self.validation_lbl.configure(foreground=COLOR_OK)

    def on_parse(self) -> None:
        raw_text = self.input_text.get("1.0", tk.END).strip()
        if not raw_text:
            messagebox.showwarning(APP_TITLE, "Please paste a hex frame first.")
            self._set_status("Nothing to parse.", Severity.WARNING)
            return
        if len(raw_text) > MAX_INPUT_CHARS:
            messagebox.showerror(
                APP_TITLE,
                f"Input is too large ({len(raw_text)} chars > {MAX_INPUT_CHARS}).",
            )
            self._set_status("Input too large.", Severity.ERROR)
            return

        prefix_choice = self.prefix_var.get()
        has_prefix: Optional[bool] = None
        if prefix_choice == "force on":
            has_prefix = True
        elif prefix_choice == "force off":
            has_prefix = False

        try:
            frame = parse_frame(raw_text, has_intel_prefix=has_prefix)
        except HexParseError as exc:
            messagebox.showerror(APP_TITLE, f"Invalid hex input:\n{exc}")
            self._set_status(f"Hex error: {exc}", Severity.ERROR)
            return
        except TypeError as exc:
            messagebox.showerror(APP_TITLE, f"Bad input:\n{exc}")
            self._set_status(f"Type error: {exc}", Severity.ERROR)
            return
        except Exception as exc:
            logging.getLogger("pldm_parser").error(
                "Parser crashed: %s\n%s", exc, traceback.format_exc()
            )
            messagebox.showerror(APP_TITLE, f"Parser crashed:\n{exc}")
            self._set_status(f"Parser crashed: {exc}", Severity.ERROR)
            return

        self._render_results(frame)
        self._update_status_from_frame(frame)

    def _update_status_from_frame(self, frame: ParsedFrame) -> None:
        n_err = sum(1 for n in frame.notes if n.severity is Severity.ERROR)
        n_warn = sum(1 for n in frame.notes if n.severity is Severity.WARNING)
        n_info = sum(1 for n in frame.notes if n.severity is Severity.INFO)
        if n_err:
            self._set_status(
                f"Parsed {len(frame.raw)} B with {n_err} error(s), "
                f"{n_warn} warning(s).",
                Severity.ERROR,
            )
        elif n_warn:
            self._set_status(
                f"Parsed {len(frame.raw)} B with {n_warn} warning(s), "
                f"{n_info} info note(s).",
                Severity.WARNING,
            )
        else:
            self._set_status(
                f"Parsed {len(frame.raw)} B successfully. "
                + (f"{n_info} info note(s)." if n_info else "No issues."),
                None,
            )

    # ---------------------------------------------------------- rendering
    def _clear_results(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for iid in self.notes_list.get_children():
            self.notes_list.delete(iid)
        self.report_text.configure(state=tk.NORMAL)
        self.report_text.delete("1.0", tk.END)
        self.report_text.configure(state=tk.DISABLED)

    def _render_results(self, frame: ParsedFrame) -> None:
        self._render_tree(frame)
        self._render_report(frame.to_text())
        self._render_notes(frame.notes)

    def _render_report(self, text: str) -> None:
        self.report_text.configure(state=tk.NORMAL)
        self.report_text.delete("1.0", tk.END)
        self.report_text.insert("1.0", text)
        self.report_text.configure(state=tk.DISABLED)

    def _render_notes(self, notes: list[Note]) -> None:
        for iid in self.notes_list.get_children():
            self.notes_list.delete(iid)
        for note in notes:
            self.notes_list.insert(
                "", tk.END,
                values=(f"[{note.severity.value.upper()}] {note.message}",),
                tags=(note.severity.value,),
            )

    def _render_tree(self, frame: ParsedFrame) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        root = self.tree.insert(
            "", tk.END, text=f"Raw frame ({len(frame.raw)} B)",
            values=(to_hex(frame.raw),), tags=("section",), open=True,
        )

        if frame.intel_prefix is not None:
            n = self.tree.insert(root, tk.END, text="Intel sideband prefix",
                                 values=("",), tags=("section",), open=True)
            for line in frame.intel_prefix.describe():
                self._add_kv(n, line)

        if frame.mctp_header is not None:
            n = self.tree.insert(root, tk.END, text="MCTP transport header",
                                 values=("",), tags=("section",), open=True)
            for line in frame.mctp_header.describe():
                self._add_kv(n, line)

        if frame.mctp_msg_type is not None:
            n = self.tree.insert(root, tk.END, text="MCTP message type",
                                 values=("",), tags=("section",), open=True)
            for line in frame.mctp_msg_type.describe():
                self._add_kv(n, line)

        if frame.pldm_header is not None:
            kind = "Request" if frame.pldm_header.is_request else "Response"
            n = self.tree.insert(
                root, tk.END,
                text=f"PLDM header ({kind})",
                values=(f"{frame.pldm_header.type_name} / "
                        f"{frame.pldm_header.command_name}",),
                tags=("section",), open=True,
            )
            for line in frame.pldm_header.describe():
                self._add_kv(n, line)

            payload_node = self.tree.insert(
                root, tk.END,
                text=f"PLDM payload ({len(frame.pldm_payload_raw)} B)",
                values=(to_hex(frame.pldm_payload_raw),),
                tags=("section",), open=True,
            )
            payload = frame.pldm_payload
            if isinstance(payload, (GetPdrRequest, GetPdrResponse)):
                kind = "Request" if isinstance(payload, GetPdrRequest) else "Response"
                dec = self.tree.insert(payload_node, tk.END,
                                       text=f"Decoded GetPDR {kind}",
                                       values=("",), tags=("section",), open=True)
                for line in payload.describe():
                    self._add_kv(dec, line)
                if isinstance(payload, GetPdrResponse) and payload.pdr is not None:
                    pdr_node = self.tree.insert(dec, tk.END, text="PDR",
                                                values=("",), tags=("section",),
                                                open=True)
                    hdr_node = self.tree.insert(pdr_node, tk.END, text="PDR header",
                                                values=("",), tags=("section",),
                                                open=True)
                    for line in payload.pdr.header.describe():
                        self._add_kv(hdr_node, line)
                    self.tree.insert(
                        pdr_node, tk.END,
                        text=f"PDR body raw ({len(payload.pdr.body_raw)} B)",
                        values=(to_hex(payload.pdr.body_raw),),
                    )
                    if payload.pdr.body is not None and hasattr(payload.pdr.body, "describe"):
                        body_node = self.tree.insert(
                            pdr_node, tk.END,
                            text=f"Decoded {payload.pdr.header.type_name}",
                            values=("",), tags=("section",), open=True,
                        )
                        for line in payload.pdr.body.describe():
                            self._add_kv(body_node, line)
            elif payload is not None and hasattr(payload, "describe"):
                # Generic decoded payload from the platform_commands registry.
                kind = "Request" if frame.pldm_header.is_request else "Response"
                dec = self.tree.insert(
                    payload_node, tk.END,
                    text=f"Decoded {frame.pldm_header.command_name} {kind}",
                    values=("",), tags=("section",), open=True,
                )
                for line in payload.describe():
                    self._add_kv(dec, line)

        if frame.trailing:
            self.tree.insert(
                root, tk.END,
                text=f"Trailing bytes ({len(frame.trailing)} B)",
                values=(to_hex(frame.trailing),),
                tags=("warning",),
            )

        if frame.notes:
            n = self.tree.insert(root, tk.END, text="Notes", values=("",),
                                 tags=("section",), open=True)
            for note in frame.notes:
                self.tree.insert(
                    n, tk.END,
                    text=note.severity.value.upper(),
                    values=(note.message,),
                    tags=(note.severity.value,),
                )

    def _add_kv(self, parent: str, line: str) -> None:
        if "=" in line:
            key, _, val = line.partition("=")
            self.tree.insert(parent, tk.END, text=key.strip(), values=(val.strip(),))
        else:
            self.tree.insert(parent, tk.END, text=line, values=("",))


def main() -> int:
    app = PldmParserApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
