# © 2025 Fr0zst. All rights reserved. 
# Unauthorized copying prohibited.
#!/usr/bin/env python3
"""
Jar Surgeon — drag-and-drop JAR editor/decompiler/rebuilder with auto-recompile, search, and replace

Workflow:
1. Drag & drop .jar onto window.
2. Edit text or .java files.
3. Press **Recompile** to run javac on the .java and update .class.
4. Press **Rebuild JAR** to package and drop result into ~/Downloads/jar_surgeon_bin.
5. Press **Ctrl+F** to search all extracted files for a keyword (like Notepad’s Find in Files).
6. Press **Ctrl+G** to find next occurrence across files in order.
7. Use **Replace in Files** to replace across the entire project:
   - Text-like files: normal replacements.
   - .class files: SAFE same-length ASCII string replacement inside the binary.
   - Nested .jar files: recurse into them and apply the same rules.

Requirements:
- Python 3.9+
- PySide6 (`pip install PySide6`)
- JDK (javac, javap, jar on PATH)

Disclaimer: only use on software you’re allowed to modify.
"""

import os
import re
import sys
import io
import shutil
import tempfile
import subprocess
import zipfile
from pathlib import Path

from PySide6.QtCore import Qt, QDir, QModelIndex, QSize
from PySide6.QtGui import QAction, QKeySequence, QTextOption
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QSplitter, QTreeView, QFileSystemModel,
    QPlainTextEdit, QMessageBox, QTabWidget, QStatusBar, QToolBar, QStyle,
    QInputDialog
)

TEXT_EXTS = {'.java', '.kt', '.xml', '.txt', '.properties', '.json', '.yml', '.yaml', '.md', '.gradle', '.csv', '.mf'}


# --- Helpers ---
def is_text_like(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS


def read_text_auto(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        return path.read_text(encoding='latin-1')


def write_text_auto(path: Path, content: str) -> None:
    path.write_text(content, encoding='utf-8', newline='\n')


def hex_dump(path: Path, length: int = 1024 * 1024) -> str:
    data = path.read_bytes()[:length]
    out = io.StringIO()
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = ' '.join(f"{b:02X}" for b in chunk)
        asciipart = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        out.write(f"{i:08X}  {hexpart:<47}  {asciipart}\n")
    if len(path.read_bytes()) > length:
        out.write("\n… truncated …\n")
    return out.getvalue()


def sniff_strings(path: Path, min_len: int = 4) -> str:
    data = path.read_bytes()
    s = re.findall(rb"[\x20-\x7E]{%d,}" % min_len, data)
    return '\n'.join(x.decode('latin-1', errors='ignore') for x in s)


def find_java_tool(tool: str) -> str | None:
    if shutil.which(tool):
        return tool
    java_home = os.environ.get('JAVA_HOME')
    if java_home:
        cand = Path(java_home) / 'bin' / (tool + ('.exe' if os.name == 'nt' else ''))
        if cand.exists():
            return str(cand)
    return None


def replace_bytes_same_length(data: bytes, old: bytes, new: bytes) -> tuple[bytes, int]:
    """Replace occurrences of 'old' with 'new' in data, only if len(old)==len(new).
    Returns (new_data, count)."""
    if len(old) != len(new):
        return data, 0
    count = 0
    idx = 0
    out = bytearray()
    L = len(old)
    while True:
        j = data.find(old, idx)
        if j == -1:
            out.extend(data[idx:])
            break
        out.extend(data[idx:j])
        out.extend(new)
        idx = j + L
        count += 1
    return bytes(out), count


def process_class_file(path: Path, search_b: bytes, replace_b: bytes) -> int:
    """Safely replace same-length ASCII strings inside a .class file.
    Returns number of replacements."""
    data = path.read_bytes()
    new_data, count = replace_bytes_same_length(data, search_b, replace_b)
    if count:
        path.write_bytes(new_data)
    return count


def process_nested_jar(jar_path: Path, search_b: bytes, replace_b: bytes, search_text: str, replace_text: str) -> tuple[int, int, int]:
    """Recurse into a nested JAR, applying replacements.
    Returns (text_repl, class_repl, nested_jar_count)."""
    tmp_dir = Path(tempfile.mkdtemp(prefix='jar_surgeon_nested_'))
    text_total = 0
    class_total = 0
    nested_count = 0
    try:
        with zipfile.ZipFile(jar_path, 'r') as z:
            z.extractall(tmp_dir)
        # walk and apply replacements
        for root, dirs, files in os.walk(tmp_dir):
            for f in files:
                p = Path(root) / f
                suf = p.suffix.lower()
                if is_text_like(p):
                    try:
                        t = read_text_auto(p)
                        if search_text in t:
                            text_total += t.count(search_text)
                            write_text_auto(p, t.replace(search_text, replace_text))
                    except Exception:
                        pass
                elif suf == '.class':
                    class_total += process_class_file(p, search_b, replace_b)
                elif suf == '.jar':
                    # recurse further
                    t2, c2, n2 = process_nested_jar(p, search_b, replace_b, search_text, replace_text)
                    text_total += t2; class_total += c2; nested_count += (n2 + 1)
        # rebuild jar in place
        tmp_out = jar_path.with_suffix('.jar.tmp')
        with zipfile.ZipFile(tmp_out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(tmp_dir):
                for f in files:
                    abs_path = Path(root) / f
                    rel = abs_path.relative_to(tmp_dir)
                    z.write(abs_path, arcname=str(rel).replace('\\', '/'))
        shutil.move(tmp_out, jar_path)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return text_total, class_total, nested_count


class Editor(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setWordWrapMode(QTextOption.NoWrap)
        self.setTabStopDistance(4 * self.fontMetrics().horizontalAdvance(' '))


class JarSurgeon(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Jar Surgeon — drag & drop JAR editor')
        self.resize(1200, 800)
        self.setAcceptDrops(True)

        self.temp_root: Path | None = None
        self.current_file: Path | None = None

        self.model = QFileSystemModel()
        self.model.setReadOnly(False)

        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setHeaderHidden(True)
        self.tree.clicked.connect(self.on_tree_clicked)

        self.tabs = QTabWidget()
        self.editor = Editor()
        self.disasm = Editor(); self.disasm.setReadOnly(True)
        self.hexview = Editor(); self.hexview.setReadOnly(True)
        self.stringsview = Editor(); self.stringsview.setReadOnly(True)
        self.tabs.addTab(self.editor, 'Editor')
        self.tabs.addTab(self.disasm, 'Disasm / Decompile')
        self.tabs.addTab(self.hexview, 'Hex')
        self.tabs.addTab(self.stringsview, 'Strings')

        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        self.status = QStatusBar(); self.setStatusBar(self.status)
        self.setup_toolbar()

        # Shortcuts for search
        find_files_act = QAction('Find in Files', self)
        find_files_act.setShortcut(QKeySequence.Find)
        find_files_act.triggered.connect(self.search_all_files)
        self.addAction(find_files_act)

        find_next_act = QAction('Find Next', self)
        find_next_act.setShortcut(QKeySequence('Ctrl+G'))
        find_next_act.triggered.connect(self.find_next_across_files)
        self.addAction(find_next_act)

        self.last_search_term: str | None = None
        self.matches: list[tuple[Path, int, int]] = []  # (file, line, col)
        self.match_index: int = -1

    # --- Drag & Drop ---
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            for url in e.mimeData().urls():
                if url.toLocalFile().lower().endswith('.jar'):
                    e.acceptProposedAction(); return
        e.ignore()

    def dropEvent(self, e):
        for url in e.mimeData().urls():
            path = url.toLocalFile()
            if path.lower().endswith('.jar'):
                self.open_jar(Path(path))
                break

    # --- UI ---
    def setup_toolbar(self):
        tb = QToolBar('Main')
        tb.setIconSize(QSize(20, 20))
        self.addToolBar(tb)

        open_act = QAction(self.style().standardIcon(QStyle.SP_DialogOpenButton), 'Open JAR…', self)
        open_act.setShortcut(QKeySequence.Open)
        open_act.triggered.connect(self.open_dialog)
        tb.addAction(open_act)

        save_act = QAction(self.style().standardIcon(QStyle.SP_DialogSaveButton), 'Save File', self)
        save_act.setShortcut(QKeySequence.Save)
        save_act.triggered.connect(self.save_current_file)
        tb.addAction(save_act)

        recompile_act = QAction(self.style().standardIcon(QStyle.SP_ArrowRight), 'Recompile .java', self)
        recompile_act.triggered.connect(self.recompile_current_java)
        tb.addAction(recompile_act)

        rebuild_act = QAction(self.style().standardIcon(QStyle.SP_DriveHDIcon), 'Rebuild JAR', self)
        rebuild_act.triggered.connect(self.rebuild_jar)
        tb.addAction(rebuild_act)

        replace_act = QAction('Replace in Files', self)
        replace_act.triggered.connect(self.replace_in_files)
        tb.addAction(replace_act)

    # --- Core actions ---
    def open_dialog(self):
        fn, _ = QFileDialog.getOpenFileName(self, 'Open JAR', QDir.homePath(), 'JAR files (*.jar)')
        if fn:
            self.open_jar(Path(fn))

    def open_jar(self, jar_path: Path):
        if self.temp_root and self.temp_root.exists():
            shutil.rmtree(self.temp_root, ignore_errors=True)
        self.temp_root = Path(tempfile.mkdtemp(prefix='jar_surgeon_'))
        with zipfile.ZipFile(jar_path, 'r') as z:
            z.extractall(self.temp_root)
        root_index = self.model.setRootPath(str(self.temp_root))
        self.tree.setRootIndex(root_index)
        self.tree.expand(self.model.index(str(self.temp_root)))
        self.status.showMessage(f'Opened {jar_path}', 5000)

    def on_tree_clicked(self, index: QModelIndex):
        path = Path(self.model.filePath(index))
        if path.is_dir():
            return
        self.open_file_in_editor(path)

    def open_file_in_editor(self, path: Path, line_no: int | None = None, keyword: str | None = None):
        self.current_file = path
        try:
            if is_text_like(path):
                self.editor.setPlainText(read_text_auto(path))
                if line_no:
                    cursor = self.editor.textCursor()
                    block = self.editor.document().findBlockByLineNumber(line_no - 1)
                    cursor.setPosition(block.position())
                    if keyword:
                        i = block.text().find(keyword)
                        if i != -1:
                            cursor.movePosition(cursor.Right, cursor.MoveAnchor, i)
                            cursor.movePosition(cursor.Right, cursor.KeepAnchor, len(keyword))
                    self.editor.setTextCursor(cursor)
                    self.editor.setFocus()
            else:
                self.editor.setPlainText('')
            self.hexview.setPlainText(hex_dump(path))
            self.stringsview.setPlainText(sniff_strings(path))
            self.disasm.setPlainText(self.get_disasm_or_source(path))
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def get_disasm_or_source(self, path: Path) -> str:
        if path.suffix.lower() == '.class':
            javap = find_java_tool('javap')
            if javap:
                try:
                    out = subprocess.check_output([javap, '-c', '-p', str(path)], stderr=subprocess.STDOUT)
                    return out.decode('utf-8', errors='ignore')
                except Exception as e:
                    return f"javap failed: {e}"
            return 'No javap found.'
        return ''

    def save_current_file(self):
        if not self.current_file:
            return
        if is_text_like(self.current_file):
            write_text_auto(self.current_file, self.editor.toPlainText())
            self.status.showMessage(f'Saved {self.current_file}', 4000)

    def recompile_current_java(self):
        if not self.current_file or self.current_file.suffix.lower() != '.java':
            QMessageBox.information(self, 'No .java', 'Select a .java file to recompile.')
            return
        self.save_current_file()
        javac = find_java_tool('javac')
        if not javac:
            QMessageBox.critical(self, 'No javac', 'javac not found. Install JDK.')
            return
        try:
            subprocess.check_call([javac, '-d', str(self.temp_root), str(self.current_file)])
            self.status.showMessage(f'Recompiled {self.current_file}', 5000)
            QMessageBox.information(self, 'Recompiled', f'{self.current_file} recompiled successfully.')
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, 'Compile failed', f'javac error: {e}')

    def rebuild_jar(self):
        if not self.temp_root:
            return
        out_dir = Path.home() / 'Downloads' / 'jar_surgeon_bin'
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / 'rebuilt.jar'
        try:
            with zipfile.ZipFile(out_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
                for root, dirs, files in os.walk(self.temp_root):
                    for f in files:
                        abs_path = Path(root) / f
                        rel = abs_path.relative_to(self.temp_root)
                        z.write(abs_path, arcname=str(rel).replace('\\', '/'))
            self.status.showMessage(f'Rebuilt JAR -> {out_path}', 8000)
            QMessageBox.information(self, 'Success', f'Rebuilt JAR saved to: {out_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Rebuild failed', str(e))

    def search_all_files(self):
        if not self.temp_root:
            QMessageBox.information(self, 'No project', 'Open a JAR first.')
            return
        keyword, ok = QInputDialog.getText(self, 'Find in Files', 'Enter search text:')
        if not ok or not keyword:
            return
        self.last_search_term = keyword
        self.matches.clear()
        for root, dirs, files in os.walk(self.temp_root):
            for f in files:
                path = Path(root) / f
                if is_text_like(path):
                    try:
                        text = read_text_auto(path)
                        for i, line in enumerate(text.splitlines(), 1):
                            col = line.find(keyword)
                            if col != -1:
                                self.matches.append((path, i, col))
                    except Exception:
                        pass
        if not self.matches:
            QMessageBox.information(self, 'No matches', f'No occurrences of "{keyword}" found.')
        else:
            self.match_index = -1
            QMessageBox.information(self, 'Search Results', f'Found {len(self.matches)} matches. Press Ctrl+G to cycle.')

    def find_next_across_files(self):
        if not self.matches:
            return
        self.match_index = (self.match_index + 1) % len(self.matches)
        path, line, col = self.matches[self.match_index]
        if self.current_file != path:
            idx = self.model.index(str(path))
            if idx.isValid():
                self.tree.setCurrentIndex(idx)
                self.on_tree_clicked(idx)
        try:
            # position cursor at the found location
            full_text = self.editor.toPlainText()
            lines = full_text.splitlines()
            start_pos = sum(len(l)+1 for l in lines[:line-1]) + col
            cursor = self.editor.textCursor()
            cursor.setPosition(start_pos)
            cursor.movePosition(cursor.Right, cursor.KeepAnchor, len(self.last_search_term or ''))
            self.editor.setTextCursor(cursor)
        except Exception:
            pass

    def replace_in_files(self):
        if not self.temp_root:
            QMessageBox.information(self, 'No project', 'Open a JAR first.')
            return
        search, ok1 = QInputDialog.getText(self, 'Replace in Files', 'Search for:')
        if not ok1 or not search:
            return
        replace, ok2 = QInputDialog.getText(self, 'Replace in Files', f'Replace "{search}" with (SAME LENGTH for .class):')
        if not ok2:
            return

        # Prepare bytes for class/jar processing
        search_b = search.encode('latin-1', errors='ignore')
        replace_b = replace.encode('latin-1', errors='ignore')

        if len(search_b) != len(replace_b):
            warn = (
                "For .class files, replacement must be the SAME length to avoid corruption.\n"
                "I'll skip .class replacements this run and only change text files and nested jars' text."
            )
            QMessageBox.warning(self, 'Length Mismatch', warn)
            allow_class = False
        else:
            allow_class = True

        text_count = 0
        class_count = 0
        nested_jar_count = 0

        # walk current extracted tree
        for root, dirs, files in os.walk(self.temp_root):
            for f in files:
                p = Path(root) / f
                suf = p.suffix.lower()
                try:
                    if is_text_like(p):
                        t = read_text_auto(p)
                        if search in t:
                            text_count += t.count(search)
                            write_text_auto(p, t.replace(search, replace))
                    elif suf == '.class' and allow_class:
                        class_count += process_class_file(p, search_b, replace_b)
                    elif suf == '.jar':
                        t2, c2, n2 = process_nested_jar(p, search_b, replace_b, search, replace)
                        text_count += t2; class_count += c2; nested_jar_count += (n2 + 1)
                except Exception:
                    # continue on errors (corrupt files, perms, etc.)
                    pass

        summary = (
            f"Text replacements: {text_count}\n"
            f".class replacements (same-length only): {class_count}\n"
            f"Nested .jar files processed: {nested_jar_count}"
        )
        QMessageBox.information(self, 'Replace Done', summary)

    def closeEvent(self, event):
        try:
            if self.temp_root and self.temp_root.exists():
                shutil.rmtree(self.temp_root, ignore_errors=True)
        except Exception:
            pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    win = JarSurgeon()
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
