import sys
import os
import tarfile
import threading
import tempfile
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
    QToolBar, QAction, QFileDialog, QTextEdit, QStatusBar,
    QListWidget, QListWidgetItem, QProgressDialog, QMessageBox,
    QInputDialog, QDialog, QFormLayout, QCheckBox, QComboBox, QPushButton, QLineEdit
)
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QObject

import zstandard as zstd
import py7zr
import pyzipper
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

ASSETS_PATH = resource_path('assets')

class DragDropListWidget(QListWidget):
    fileDropped = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        self.fileDropped.emit(files)


class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal()
    error = pyqtSignal(str)


class AESHelper:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        salt = secrets.token_bytes(16)
        key = AESHelper.derive_key(password, salt)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        encrypted = encryptor.update(data) + encryptor.finalize()
        return salt + iv + encrypted

    @staticmethod
    def decrypt(encrypted: bytes, password: str) -> bytes:
        salt = encrypted[:16]
        iv = encrypted[16:32]
        ciphertext = encrypted[32:]
        key = AESHelper.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = decrypted[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")
        return decrypted[:-pad_len]
class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_settings=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(350, 150)
        layout = QFormLayout(self)

        self.format_combo = QComboBox()
        self.format_combo.addItems(['.arcx (Encrypted Zstd Tar)', '.zip', '.7z'])
        if current_settings:
            fmt = current_settings.get('default_format', '.arcx')
            idx = {'.arcx (Encrypted Zstd Tar)': 0, '.zip': 1, '.7z': 2}.get(fmt, 0)
            self.format_combo.setCurrentIndex(idx)
        layout.addRow("Default Compression Format:", self.format_combo)

        self.password_check = QCheckBox("Always prompt for password")
        if current_settings:
            self.password_check.setChecked(current_settings.get('password_prompt', True))
        layout.addRow(self.password_check)

        self.theme_button = QPushButton("Toggle Theme (Current: Light)")
        layout.addRow(self.theme_button)
        self.theme_button.clicked.connect(self.toggle_theme_clicked)

        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        layout.addRow(self.ok_button, self.cancel_button)
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        self._theme_toggle_callback = None

    def toggle_theme_clicked(self):
        if self._theme_toggle_callback:
            self._theme_toggle_callback()

    def set_theme_toggle_callback(self, callback):
        self._theme_toggle_callback = callback

    def get_settings(self):
        fmt = self.format_combo.currentText()
        fmt = '.arcx' if fmt.startswith('.arcx') else '.zip' if fmt.startswith('.zip') else '.7z'
        return {
            'default_format': fmt,
            'password_prompt': self.password_check.isChecked(),
        }

    def set_current_theme(self, dark_mode):
        text = "Toggle Theme (Current: Dark)" if dark_mode else "Toggle Theme (Current: Light)"
        self.theme_button.setText(text)


class ArkiveMainWindow(QMainWindow):
    def select_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder_path:
            self.add_file_to_list(folder_path)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Arkive")
        self.setGeometry(200, 100, 900, 600)
        self.setWindowIcon(QIcon(os.path.join(ASSETS_PATH, 'arkive_logo.png')))

        self.files_to_compress = []
        self.dark_mode = False
        self.settings = {
            'default_format': '.arcx',
            'password_prompt': True,
        }
        self.password = None
        self.initUI()
    def initUI(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        home_action = QAction(QIcon(os.path.join(ASSETS_PATH, 'icon_home.png')), "Home", self)
        compress_action = QAction(QIcon(os.path.join(ASSETS_PATH, 'icon_compress.png')), "Compress", self)
        extract_action = QAction(QIcon(os.path.join(ASSETS_PATH, 'icon_extract.png')), "Extract", self)
        settings_action = QAction(QIcon(os.path.join(ASSETS_PATH, 'icon_settings.png')), "Settings", self)
        add_folder_action = QAction(QIcon(os.path.join(ASSETS_PATH, 'icon_compress.png')), "Add Folder", self)


        toolbar.addAction(home_action)
        toolbar.addAction(compress_action)
        toolbar.addAction(extract_action)
        toolbar.addAction(settings_action)
        toolbar.addAction(add_folder_action)
        add_folder_action.triggered.connect(self.select_folder)





        home_action.triggered.connect(self.show_home)
        compress_action.triggered.connect(self.compress_files)
        extract_action.triggered.connect(self.extract_files)
        settings_action.triggered.connect(self.open_settings)

        toolbar.addAction(home_action)
        toolbar.addAction(compress_action)
        toolbar.addAction(extract_action)
        toolbar.addAction(settings_action)

        self.main_widget = QWidget()
        self.layout = QVBoxLayout()

        self.logo = QLabel()
        self.logo.setAlignment(Qt.AlignCenter)
        logo_path = os.path.join(ASSETS_PATH, 'arkive_logo.png')
        if os.path.exists(logo_path):
            self.logo.setPixmap(QPixmap(logo_path).scaled(128, 128, Qt.KeepAspectRatio))
        else:
            self.logo.setText("Arkive Logo Missing")
        self.layout.addWidget(self.logo)

        self.file_list = QListWidget()
        self.file_list.setAcceptDrops(True)
        self.file_list.dragEnterEvent = self.dragEnterEvent
        self.file_list.dropEvent = self.dropEvent
        self.layout.addWidget(self.file_list)

        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.layout.addWidget(self.info_text)

        self.main_widget.setLayout(self.layout)
        self.setCentralWidget(self.main_widget)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        for f in files:
            if os.path.exists(f):
                self.add_file_to_list(f)

    def add_file_to_list(self, filepath):
        if filepath not in self.files_to_compress:
            self.files_to_compress.append(filepath)
            item = QListWidgetItem(os.path.basename(filepath))
            item.setToolTip(filepath)
            self.file_list.addItem(item)
            self.info_text.append(f"Added: {filepath}")

    def show_home(self):
        self.info_text.setPlainText(
            "Welcome to Arkive.\n\n"
            "Drag & drop files or folders into the list to prepare for compression.\n"
            "Use the toolbar buttons to compress or extract archives.\n"
            "Supports multi-folder compression preserving structure.\n"
            "Beta '.arcx' uses AES-encrypted Zstandard compressed tarballs.\n"
            "Toggle dark mode in Settings."
        )
    def compress_files(self):
        if not self.files_to_compress:
            paths, _ = QFileDialog.getOpenFileNames(self, "Select Files or Folders to Compress")
            if not paths:
                return
            for p in paths:
                self.add_file_to_list(p)

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Archive As", "",
            "Arkive Archive (*.arcx);;Zip Archive (*.zip);;7z Archive (*.7z);;Tar Archive (*.tar)"
        )
        if not save_path:
            return

        ext = os.path.splitext(save_path)[1].lower()
        self.password = None
        if ext in ['.arcx', '.7z', '.zip'] and self.settings.get('password_prompt', True):
            pw, ok = QInputDialog.getText(self, "Password", "Enter password (leave empty for none):",
                                          echo=QLineEdit.EchoMode.Password)
            if not ok:
                return
            self.password = pw.strip() if pw.strip() != "" else None

        self.progress_dialog = QProgressDialog("Compressing...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()

        self.worker_signals = WorkerSignals()
        self.worker_signals.progress.connect(self.progress_dialog.setValue)
        self.worker_signals.finished.connect(lambda: self.status_bar.showMessage("Compression completed"))
        self.worker_signals.finished.connect(self.progress_dialog.close)
        self.worker_signals.error.connect(self.report_error)

        self.toggle_ui(False)

        thread = threading.Thread(target=self._compress_thread, args=(save_path, ext, self.worker_signals))
        thread.start()

    def _compress_thread(self, save_path, ext, signals: WorkerSignals):
        try:
            paths_to_add = []
            for path in self.files_to_compress:
                if os.path.isfile(path):
                    paths_to_add.append(('', path))
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for f in files:
                            full_path = os.path.join(root, f)
                            relative_path = os.path.relpath(full_path, os.path.dirname(path))
                            paths_to_add.append((relative_path, full_path))

            if ext == '.arcx':
                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tar_path = tf.name
                with tarfile.open(tar_path, 'w') as tar:
                    for i, (arcname, full_path) in enumerate(paths_to_add):
                        tar.add(full_path, arcname=arcname or os.path.basename(full_path))
                        signals.progress.emit(int((i / len(paths_to_add)) * 50))
                with open(tar_path, 'rb') as f_in:
                    tar_data = f_in.read()
                os.unlink(tar_path)

                cctx = zstd.ZstdCompressor()
                compressed = cctx.compress(tar_data)
                signals.progress.emit(70)

                final_data = AESHelper.encrypt(compressed, self.password) if self.password else compressed
                with open(save_path, 'wb') as f_out:
                    f_out.write(final_data)
                signals.progress.emit(100)

            elif ext == '.zip':
                with pyzipper.AESZipFile(save_path, 'w', compression=pyzipper.ZIP_DEFLATED,
                                         encryption=pyzipper.WZ_AES if self.password else None) as zipf:
                    if self.password:
                        zipf.setpassword(self.password.encode())
                    for i, (arcname, full_path) in enumerate(paths_to_add):
                        zipf.write(full_path, arcname or os.path.basename(full_path))
                        signals.progress.emit(int((i / len(paths_to_add)) * 100))

            elif ext == '.7z':
                with py7zr.SevenZipFile(save_path, 'w', password=self.password) as archive:
                    for arcname, full_path in paths_to_add:
                        archive.write(full_path, arcname or os.path.basename(full_path))
                    signals.progress.emit(100)

            elif ext == '.tar':
                with tarfile.open(save_path, 'w') as tar:
                    for i, (arcname, full_path) in enumerate(paths_to_add):
                        tar.add(full_path, arcname or os.path.basename(full_path))
                        signals.progress.emit(int((i / len(paths_to_add)) * 100))

            else:
                signals.error.emit(f"Unsupported format: {ext}")
                return

            self.files_to_compress.clear()
            self.file_list.clear()
            signals.finished.emit()

        except Exception as e:
            signals.error.emit(f"Compression error: {str(e)}")
        finally:
            self.toggle_ui(True)
    def extract_files(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Archive to Extract", "",
            "Archives (*.arcx *.zip *.tar *.gz *.bz2 *.xz *.7z)"
        )
        if not file_path:
            return

        extract_dir = QFileDialog.getExistingDirectory(self, "Select Extraction Folder")
        if not extract_dir:
            return

        ext = os.path.splitext(file_path)[1].lower()
        self.password = None

        if ext in ['.arcx', '.zip', '.7z'] and self.settings.get('password_prompt', True):
            pw, ok = QInputDialog.getText(self, "Password", "Enter password (leave empty if none):",
                                          echo=QLineEdit.EchoMode.Password)
            if not ok:
                return
            self.password = pw.strip() if pw.strip() != "" else None

        self.progress_dialog = QProgressDialog("Extracting...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()

        self.worker_signals = WorkerSignals()
        self.worker_signals.progress.connect(self.progress_dialog.setValue)
        self.worker_signals.finished.connect(lambda: self.status_bar.showMessage("Extraction completed"))
        self.worker_signals.finished.connect(self.progress_dialog.close)
        self.worker_signals.error.connect(self.report_error)

        self.toggle_ui(False)

        thread = threading.Thread(target=self._extract_thread, args=(file_path, extract_dir, ext, self.worker_signals))
        thread.start()

    def _extract_thread(self, archive_path, extract_dir, ext, signals: WorkerSignals):
        try:
            if ext == '.arcx':
                with open(archive_path, 'rb') as f:
                    encrypted = f.read()
                decrypted = AESHelper.decrypt(encrypted, self.password) if self.password else encrypted
                dctx = zstd.ZstdDecompressor()
                tar_data = dctx.decompress(decrypted)

                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(tar_data)
                    tar_path = tf.name

                with tarfile.open(tar_path, 'r') as tar:
                    members = tar.getmembers()
                    for i, member in enumerate(members):
                        tar.extract(member, path=extract_dir)
                        signals.progress.emit(int((i / len(members)) * 100))
                os.unlink(tar_path)

            elif ext == '.zip':
                with pyzipper.AESZipFile(archive_path, 'r') as zipf:
                    if self.password:
                        zipf.setpassword(self.password.encode())
                    members = zipf.infolist()
                    for i, member in enumerate(members):
                        zipf.extract(member, extract_dir)
                        signals.progress.emit(int((i / len(members)) * 100))

            elif ext == '.7z':
                with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as archive:
                    files = archive.getnames()
                    for i, f in enumerate(files):
                        archive.extract(path=extract_dir, targets=[f])
                        signals.progress.emit(int((i / len(files)) * 100))

            elif ext in ['.tar', '.gz', '.bz2', '.xz']:
                with tarfile.open(archive_path, 'r:*') as tar:
                    members = tar.getmembers()
                    for i, member in enumerate(members):
                        tar.extract(member, path=extract_dir)
                        signals.progress.emit(int((i / len(members)) * 100))

            else:
                signals.error.emit("Unsupported format.")
                return

            signals.finished.emit()

        except Exception as e:
            signals.error.emit(f"Extraction error: {str(e)}")

        finally:
            self.toggle_ui(True)

    def open_settings(self):
        dlg = SettingsDialog(self, current_settings=self.settings)
        dlg.set_theme_toggle_callback(self.toggle_theme)
        dlg.set_current_theme(self.dark_mode)
        if dlg.exec():
            self.settings.update(dlg.get_settings())
            self.status_bar.showMessage("Settings updated")

    def toggle_theme(self):
        if self.dark_mode:
            self.setStyleSheet("")
            self.dark_mode = False
            self.status_bar.showMessage("Light Mode")
        else:
            self.setStyleSheet("""
                QWidget { background-color: #2e2e2e; color: #f0f0f0; }
                QTextEdit, QListWidget { background-color: #3e3e3e; color: #f0f0f0; }
                QToolBar, QStatusBar { background-color: #222; }
                QPushButton { background-color: #444; border: none; color: #f0f0f0; }
            """)
            self.dark_mode = True
            self.status_bar.showMessage("Dark Mode")
    def toggle_ui(self, enabled: bool):
        """Enable or disable UI elements during processing."""
        for widget in [self.file_list, *self.findChildren(QToolBar)]:
            widget.setEnabled(enabled)

    def report_error(self, msg):
        QMessageBox.critical(self, "Error", msg)
        self.status_bar.showMessage("Error occurred")

def main():
    app = QApplication(sys.argv)
    window = ArkiveMainWindow()
    window.show()
    window.show_home()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()