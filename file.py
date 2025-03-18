# code from Grok  2025/02/28
# python.exe -m pip install --upgrade pip
# pip install PyQt6 cryptography pyinstaller
# pyinstaller --onefile --noconsole ???.py

import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QFileDialog,
                             QFrame, QMessageBox, QLineEdit)
from PyQt6.QtCore import QRect
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import logging

# 設置日誌
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


class FileCryptoTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.encrypt_file_path = ''
        self.decrypt_file_path = ''
        self.key_file_path = ''
        self.password = ''
        self.initUI()

    def initUI(self):
        """初始化圖形化介面"""
        self.setWindowTitle('檔案加解密工具')
        self.setGeometry(100, 100, 350, 450)
        self.setAcceptDrops(True)

        container = QWidget()
        self.setCentralWidget(container)
        layout = QVBoxLayout(container)
        layout.setSpacing(20)

        # === 密鑰檔案選擇 ===
        self.key_file_label = QLabel('尚未選擇密鑰檔案（請選擇或拖曳一個檔案作為密鑰，10MB以內）')
        layout.addWidget(self.key_file_label)

        key_btn_layout = QHBoxLayout()
        self.key_select_btn = QPushButton('選擇密鑰檔案')
        self.key_select_btn.clicked.connect(self.select_key_file)
        key_btn_layout.addWidget(self.key_select_btn)

        self.key_clear_btn = QPushButton('清除密鑰檔案')  # 新增清除按鈕
        self.key_clear_btn.clicked.connect(self.clear_key_file)
        key_btn_layout.addWidget(self.key_clear_btn)

        layout.addLayout(key_btn_layout)

        # === 手動輸入密碼 ===
        self.password_label = QLabel('尚未輸入密碼')
        layout.addWidget(self.password_label)

        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('輸入密碼（可選）')
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.update_password)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)

        layout.addSpacing(20)
        self.separator1 = QFrame()
        self.separator1.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(self.separator1)
        layout.addSpacing(20)

        # === 加密部分 ===
        self.encrypt_widget = QWidget()
        encrypt_layout = QVBoxLayout(self.encrypt_widget)
        self.encrypt_file_label = QLabel('尚未選擇加密檔案')
        encrypt_layout.addWidget(self.encrypt_file_label)

        encrypt_btn_layout = QHBoxLayout()
        self.encrypt_select_btn = QPushButton('選擇加密檔案')
        self.encrypt_select_btn.clicked.connect(self.select_encrypt_file)
        encrypt_btn_layout.addWidget(self.encrypt_select_btn)
        encrypt_layout.addLayout(encrypt_btn_layout)

        self.encrypt_btn = QPushButton('開始加密')
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.encrypt_btn.setEnabled(False)
        encrypt_layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.encrypt_widget)

        layout.addSpacing(20)
        self.separator2 = QFrame()
        self.separator2.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(self.separator2)
        layout.addSpacing(20)

        # === 解密部分 ===
        self.decrypt_widget = QWidget()
        decrypt_layout = QVBoxLayout(self.decrypt_widget)
        self.decrypt_file_label = QLabel('尚未選擇解密檔案')
        decrypt_layout.addWidget(self.decrypt_file_label)

        decrypt_btn_layout = QHBoxLayout()
        self.decrypt_select_btn = QPushButton('選擇解密檔案')
        self.decrypt_select_btn.clicked.connect(self.select_decrypt_file)
        decrypt_btn_layout.addWidget(self.decrypt_select_btn)
        decrypt_layout.addLayout(decrypt_btn_layout)

        self.decrypt_btn = QPushButton('開始解密')
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        self.decrypt_btn.setEnabled(False)
        decrypt_layout.addWidget(self.decrypt_btn)
        layout.addWidget(self.decrypt_widget)

    def dragEnterEvent(self, event):
        """處理拖曳進入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """處理拖曳放置事件"""
        try:
            file_path = event.mimeData().urls()[0].toLocalFile()
            logging.debug(f"拖曳檔案: {file_path}")
            pos = event.position()
            self.handle_file_drop(file_path, pos)
        except Exception as e:
            logging.error(f"拖曳處理錯誤: {str(e)}")
            QMessageBox.critical(self, '錯誤', f'拖曳檔案失敗: {str(e)}')

    def handle_file_drop(self, file_path, pos):
        """根據拖曳位置處理檔案"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, '錯誤', '拖曳的檔案不存在！')
            return

        if os.path.getsize(file_path) > 10 * 1024 * 1024:
            QMessageBox.warning(self, '錯誤', '密鑰檔案大小超過10MB限制！')
            return

        encrypt_rect = self.encrypt_widget.geometry()
        decrypt_rect = self.decrypt_widget.geometry()
        key_rect = QRect(0, 0, self.width(), self.separator1.y())

        if key_rect.contains(pos.toPoint()):
            self.key_file_path = file_path
            self.key_file_label.setText(f'密鑰檔案: {file_path}')
            self.update_password_label()
            self.update_buttons()
            logging.debug(f"更新密鑰檔案為: {file_path}")
        elif encrypt_rect.contains(pos.toPoint()):
            if not self.key_file_path and not self.password:
                QMessageBox.warning(self, '錯誤', '請先選擇或拖曳密鑰檔案，或輸入密碼！')
                return
            self.encrypt_file_path = file_path
            self.encrypt_file_label.setText(f'加密檔案: {file_path}')
            self.update_buttons()
        elif decrypt_rect.contains(pos.toPoint()):
            if not self.key_file_path and not self.password:
                QMessageBox.warning(self, '錯誤', '請先選擇或拖曳密鑰檔案，或輸入密碼！')
                return
            self.decrypt_file_path = file_path
            self.decrypt_file_label.setText(f'解密檔案: {file_path}')
            self.update_buttons()
        else:
            logging.debug(f"拖曳位置未匹配任何區域: {pos.x()}, {pos.y()}")

    def update_password(self, text):
        """即時更新密碼並觸發相關更新"""
        self.password = text
        self.update_password_label()
        self.update_buttons()

    def update_password_label(self):
        """更新密碼標籤顯示"""
        if self.password and self.key_file_path:
            self.password_label.setText(f'已輸入密碼並選擇檔案: {self.key_file_path}')
        elif self.password:
            self.password_label.setText('已輸入密碼')
        elif self.key_file_path:
            self.password_label.setText(f'密鑰檔案: {self.key_file_path}')
        else:
            self.password_label.setText('尚未輸入密碼或選擇檔案')

    def update_buttons(self):
        """更新按鈕啟用狀態"""
        has_key = bool(self.key_file_path or self.password)
        self.encrypt_btn.setEnabled(has_key and bool(self.encrypt_file_path))
        self.decrypt_btn.setEnabled(has_key and bool(self.decrypt_file_path))
        logging.debug(f"按鈕狀態 - 加密: {self.encrypt_btn.isEnabled()}, 解密: {self.decrypt_btn.isEnabled()}")

    def select_key_file(self):
        """選擇密鑰檔案"""
        file_path, _ = QFileDialog.getOpenFileName(self, '選擇密鑰檔案')
        if file_path and os.path.exists(file_path):
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                QMessageBox.warning(self, '錯誤', '密鑰檔案大小超過10MB限制！')
                return
            self.key_file_path = file_path
            self.key_file_label.setText(f'密鑰檔案: {file_path}')
            self.update_password_label()
            self.update_buttons()
            logging.debug(f"選擇密鑰檔案: {file_path}")

    def clear_key_file(self):
        """清除已選擇的密鑰檔案"""
        self.key_file_path = ''
        self.key_file_label.setText('尚未選擇密鑰檔案（請選擇或拖曳一個檔案作為密鑰，10MB以內）')
        self.update_password_label()
        self.update_buttons()
        logging.debug("已清除密鑰檔案")

    def select_encrypt_file(self):
        """選擇要加密的檔案"""
        if not self.key_file_path and not self.password:
            QMessageBox.warning(self, '錯誤', '請先選擇或拖曳密鑰檔案，或輸入密碼！')
            return
        file_path, _ = QFileDialog.getOpenFileName(self, '選擇加密檔案')
        if file_path and os.path.exists(file_path):
            self.encrypt_file_path = file_path
            self.encrypt_file_label.setText(f'加密檔案: {file_path}')
            self.update_buttons()
            logging.debug(f"選擇加密檔案: {file_path}")

    def select_decrypt_file(self):
        """選擇要解密的檔案"""
        if not self.key_file_path and not self.password:
            QMessageBox.warning(self, '錯誤', '請先選擇或拖曳密鑰檔案，或輸入密碼！')
            return
        file_path, _ = QFileDialog.getOpenFileName(self, '選擇解密檔案', filter='AES files (*.aes)')
        if file_path and os.path.exists(file_path):
            self.decrypt_file_path = file_path
            self.decrypt_file_label.setText(f'解密檔案: {file_path}')
            self.update_buttons()
            logging.debug(f"選擇解密檔案: {file_path}")

    def generate_key(self):
        """生成加密金鑰，結合密碼和檔案內容"""
        if not self.key_file_path and not self.password:
            QMessageBox.critical(self, '錯誤', '未選擇有效的密鑰檔案或輸入密碼！')
            return None

        try:
            key_content = b''
            if self.key_file_path:
                with open(self.key_file_path, 'rb') as f:
                    key_content += f.read()
            if self.password:
                key_content += self.password.encode('utf-8')

            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_content))
            logging.debug("成功生成金鑰")
            return key, salt
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'無法生成金鑰: {str(e)}')
            logging.error(f"生成金鑰失敗: {str(e)}")
            return None

    def encrypt_file(self):
        """加密檔案"""
        if not self.key_file_path and not self.password:
            QMessageBox.critical(self, '錯誤', '請確保已選擇密鑰檔案或輸入密碼！')
            return
        if not self.encrypt_file_path:
            QMessageBox.critical(self, '錯誤', '請選擇要加密的檔案！')
            return

        result = self.generate_key()
        if result is None:
            return
        key, salt = result

        try:
            iv = secrets.token_bytes(16)
            fernet = Fernet(key)
            with open(self.encrypt_file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = fernet.encrypt(file_data)
            default_path = os.path.splitext(self.encrypt_file_path)[0]
            save_path, _ = QFileDialog.getSaveFileName(self, '儲存加密檔案', default_path)
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(salt + iv + encrypted_data)
                self.encrypt_file_label.setText(f'加密完成！儲存至: {save_path}')
                logging.debug(f"加密完成，儲存至: {save_path}")
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'加密失敗: {str(e)}')
            logging.error(f"加密失敗: {str(e)}")

    def decrypt_file(self):
        """解密檔案"""
        if not self.key_file_path and not self.password:
            QMessageBox.critical(self, '錯誤', '請確保已選擇密鑰檔案或輸入密碼！')
            return
        if not self.decrypt_file_path:
            QMessageBox.critical(self, '錯誤', '請選擇要解密的檔案！')
            return

        try:
            with open(self.decrypt_file_path, 'rb') as f:
                file_data = f.read()
                if len(file_data) < 32:
                    raise ValueError("檔案格式錯誤，無法提取salt和IV")
                salt = file_data[:16]
                iv = file_data[16:32]
                encrypted_data = file_data[32:]

            key_content = b''
            if self.key_file_path:
                with open(self.key_file_path, 'rb') as f:
                    key_content += f.read()
            if self.password:
                key_content += self.password.encode('utf-8')

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_content))
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            default_path = os.path.splitext(self.decrypt_file_path)[0]
            save_path, _ = QFileDialog.getSaveFileName(self, '儲存解密檔案', default_path)
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                self.decrypt_file_label.setText(f'解密完成！儲存至: {save_path}')
                logging.debug(f"解密完成，儲存至: {save_path}")
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'解密失敗: {str(e)}')
            logging.error(f"解密失敗: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = FileCryptoTool()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()