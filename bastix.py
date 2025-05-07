import sys
import os
import subprocess
import re
from PyQt5.QtCore import Qt,QTimer,QPoint,QThread,pyqtSignal
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QTextEdit,QHBoxLayout,QMenu,QSplitter,
                             QMessageBox,QListWidget, QTableWidget, QTableWidgetItem,QLabel,QAction,QMenuBar,QMainWindow)
from PyQt5.QtWidgets import QHeaderView,QDialog,QFormLayout,QLineEdit,QComboBox,QCheckBox
from PyQt5.QtGui import QFont
import platform
import requests
from bs4 import BeautifulSoup

class RDRManagementDialog(QDialog):
    """Bastille RDR 管理ダイアログ (Add, List, Clear を完全サポート)"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bastille RDR Management")
        self.setModal(True)

        # メインレイアウト
        layout = QVBoxLayout(self)

        # 対象 Jail の選択
        self.jail_combo = QComboBox(self)
        self.jail_combo.setPlaceholderText("Loading Jails...")
        layout.addWidget(QLabel("Select Jail:"))
        layout.addWidget(self.jail_combo)



        # プロトコル選択
        self.protocol_combo = QComboBox(self)
        self.protocol_combo.addItems(["tcp", "udp"])
        layout.addWidget(QLabel("Select Protocol:"))
        layout.addWidget(self.protocol_combo)

        # ホストポート
        self.host_port_input = QLineEdit(self)
        self.host_port_input.setPlaceholderText("Enter Host Port (e.g., 8080)")
        layout.addWidget(QLabel("Host Port:"))
        layout.addWidget(self.host_port_input)

        # Jail ポート
        self.jail_port_input = QLineEdit(self)
        self.jail_port_input.setPlaceholderText("Enter Jail Port (e.g., 80)")
        layout.addWidget(QLabel("Jail Port:"))
        layout.addWidget(self.jail_port_input)

        # ログオプション
        self.log_checkbox = QCheckBox("Enable Logging")
        self.log_options_input = QLineEdit(self)
        self.log_options_input.setPlaceholderText("Log options (optional)")
        layout.addWidget(self.log_checkbox)
        layout.addWidget(self.log_options_input)

        # ボタンレイアウト
        button_layout = QHBoxLayout()

        self.add_button = QPushButton("Add RDR Rule", self)
        self.add_button.clicked.connect(self.add_rdr_rule)
        button_layout.addWidget(self.add_button)

        self.list_button = QPushButton("List Rules", self)
        self.list_button.clicked.connect(self.list_rdr_rules)
        button_layout.addWidget(self.list_button)

        self.clear_button = QPushButton("Clear Rules", self)
        self.clear_button.clicked.connect(self.clear_rdr_rules)
        button_layout.addWidget(self.clear_button)

        layout.addLayout(button_layout)

        # ログエリア
        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        layout.addWidget(QLabel("Output Logs:"))
        layout.addWidget(self.log_area)

        # 初期化: Jail リストをロード
        self.load_jail_list()

    def load_jail_list(self):
        """bastille list から Jail リストをロードする"""
        try:
            process = subprocess.run(["bastille", "list","-a"], capture_output=True, text=True)
            if process.returncode == 0:
                data_lines = process.stdout.splitlines()[1:]  # 2行目以降がデータ

                # データ行を解析して辞書形式で格納
                jail_list = []
                for line in data_lines:
                    # 各フィールドをスペースで分割
                    fields = line.split()

                    # 必要なフィールドが揃っていない場合はスキップ
                    if len(fields) < 7:
                        continue

                    # フィールドを辞書形式で格納
                    jail_list.append(fields[4])
                self.jail_combo.addItems(jail_list)
            else:
                QMessageBox.critical(self, "Error", f"Failed to load Jails:\n{process.stderr}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading Jail list:\n{str(e)}")

    def add_rdr_rule(self):
        """RDR ルールを追加"""
        jail = self.jail_combo.currentText()
        protocol = self.protocol_combo.currentText()
        host_port = self.host_port_input.text()
        jail_port = self.jail_port_input.text()
        log_flag = self.log_checkbox.isChecked()
        log_options = self.log_options_input.text()

        if not jail or not host_port or not jail_port:
            QMessageBox.warning(self, "Input Error", "All fields must be filled.")
            return

        # コマンド構築
        command = ["bastille", "rdr", jail]

        # 残りの引数を追加
        command.extend([protocol, host_port, jail_port])

        if log_flag:
                command.append("log")
                if log_options:
                    command.append(f"({log_options})")

        self.run_command(command, "Added RDR Rule")

    def list_rdr_rules(self):
        """RDR ルールを一覧表示"""
        jail = self.jail_combo.currentText()
        if not jail:
            QMessageBox.warning(self, "Input Error", "Please select a Jail.")
            return

        command = ["bastille", "rdr", jail, "list"]
        self.run_command(command, "Listed RDR Rules")

    def clear_rdr_rules(self):
        """すべての RDR ルールをクリア"""
        jail = self.jail_combo.currentText()
        if not jail:
            QMessageBox.warning(self, "Input Error", "Please select a Jail.")
            return

        command = ["bastille", "rdr", jail, "clear"]
        self.run_command(command, "Cleared RDR Rules")

    def run_command(self, command, success_message):
        """コマンドを実行してログに出力"""
        try:
            process = subprocess.run(command, capture_output=True, text=True)

            if process.returncode == 0:
                self.log_area.append(f"{success_message}:\n{process.stdout}")
                QMessageBox.information(self, "Success", success_message)
            else:
                self.log_area.append(f"Command failed:\n{process.stderr}")
                QMessageBox.critical(self, "Error", f"Command failed:\n{process.stderr}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")


class BootstrapWorker(QThread):
    """Bootstrap処理を別スレッドで実行するワーカー"""
    progress = pyqtSignal(str)  # ログの進行状況をメインスレッドに伝える
    finished = pyqtSignal(bool, str)  # 完了時の状態（成功/失敗）を伝える

    def __init__(self, release, parent=None):
        super().__init__(parent)
        self.release = release

    def run(self):
        """`bastille bootstrap` コマンドを実行"""
        try:
            command = ["bastille", "bootstrap", self.release]
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # 出力をリアルタイムで取得して送信
            for line in iter(process.stdout.readline, ""):
                self.progress.emit(line.strip())
            process.stdout.close()
            process.wait()

            if process.returncode == 0:
                self.finished.emit(True, "Bootstrap completed successfully!")
            else:
                error_msg = process.stderr.read()
                process.stderr.close()
                self.finished.emit(False, f"Bootstrap failed:\n{error_msg}")

        except Exception as e:
            self.finished.emit(False, f"An unexpected error occurred:\n{str(e)}")


class BootstrapDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bootstrap Release")
        self.setModal(True)  # コンテキストをブロックするモーダルダイアログ

        # レイアウト
        layout = QVBoxLayout(self)

        # OSリリース選択 (e.g., 13.2-RELEASE, 12.4-RELEASE)
        self.release_combo = QComboBox(self)
        # 既知のリリース候補をあらかじめ追加（動的に取得も可能）
        self.release_combo.addItems(self.get_freebsd_versions_by_arch())
        layout.addWidget(QLabel("Select OS Release:"))
        layout.addWidget(self.release_combo)

        # プログレス情報を表示するテキストエリア
        self.log_text_area = QTextEdit(self)
        self.log_text_area.setReadOnly(True)
        self.log_text_area.setPlaceholderText("Bootstrap logs will appear here...")
        layout.addWidget(self.log_text_area)

        # 実行ボタンとキャンセルボタン
        self.bootstrap_button = QPushButton("Start Bootstrap", self)
        self.bootstrap_button.clicked.connect(self.start_bootstrap)
        layout.addWidget(self.bootstrap_button)

        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)


    def start_bootstrap(self):
        """選択されたリリースのブートストラップを開始"""
        release = self.release_combo.currentText()

        if not release:  # リリースが空でないことを確認
            QMessageBox.warning(self, "Input Error", "Please select a release to bootstrap.")
            return

        # ボタンを無効化して誤操作を防止
        self.bootstrap_button.setEnabled(False)
        self.log_text_area.clear()
        self.log_text_area.append(f"Starting bootstrap for release: {release}...\n")

        # ワーカースレッドを作成
        self.worker_thread = BootstrapWorker(release)
        self.worker_thread.progress.connect(self.update_log)
        self.worker_thread.finished.connect(self.on_finished)
        self.worker_thread.start()

    def update_log(self, message):
        """ログをリアルタイムで更新"""
        self.log_text_area.append(message)

    def on_finished(self, success, message):
        """Bootstrap終了時の処理"""
        # ボタンを再度有効化
        self.bootstrap_button.setEnabled(True)

        if success:
            self.log_text_area.append("\n" + message)
            QMessageBox.information(self, "Success", message)
        else:
            self.log_text_area.append("\n" + message)
            QMessageBox.critical(self, "Error", message)

        # スレッドをクリーンアップ
        self.worker_thread = None

    def detect_arch(self):
            machine = platform.machine()
            # FreeBSDで使われる表記に合わせる
            arch_map = {
                "x86_64": "amd64",
                "amd64": "amd64",
                "aarch64": "arm64",
                "arm64": "arm64",
                "i386": "i386",
                "armv7l": "armv7"
            }
            return arch_map.get(machine, machine)

    def get_freebsd_versions_by_arch(self,arch=None):
        if arch is None:
            arch = self.detect_arch()

        url = f"https://download.freebsd.org/ftp/releases/{arch}/{arch}/"
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        versions = []

        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href.endswith("-RELEASE/"):
                versions.append(href.rstrip("/"))

        return sorted(versions,reverse=True)


class CreateJailDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create New Jail")
        self.setModal(True)  # モーダルダイアログ

        layout = QFormLayout(self)

        # Jail 名, リリース, IP アドレス
        self.name_input = QLineEdit(self)
        self.release_input = QLineEdit(self)
        self.ip_input = QLineEdit(self)
        layout.addRow("Jail Name:", self.name_input)
        layout.addRow("Base Release:", self.release_input)
        layout.addRow("IP Address:", self.ip_input)

        # VNET 設定
        self.vnet_combo = QComboBox(self)
        self.vnet_combo.addItems(["Disable VNET", "New Virtual Bridge", "Attach to Existing Bridge"])
        self.vnet_combo.currentIndexChanged.connect(self.vnet_selection_changed)
        layout.addRow("VNET Option:", self.vnet_combo)

        # 既存インターフェイス入力（初期状態は非表示）
        self.interface_input = QLineEdit(self)
        self.interface_input.setPlaceholderText("Enter interface (e.g., epair0b)")
        self.interface_input.setEnabled(False)

        layout.addRow("Interface Name:", self.interface_input)

        # ボタン
        self.create_button = QPushButton("Create", self)
        self.create_button.clicked.connect(self.accept)
        layout.addWidget(self.create_button)

        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

    def vnet_selection_changed(self, index):
        """VNET 設定に応じて入力フィールドを表示・非表示"""
        if index == 2 or index == 1:  # Attach to Existing Bridge
            self.interface_input.setEnabled(True)
        else:
            self.interface_input.setEnabled(False)

    def get_inputs(self):
        """ダイアログの入力内容を取得"""
        return {
            "name": self.name_input.text(),
            "release": self.release_input.text(),
            "ip": self.ip_input.text(),
            "vnet_option": self.vnet_combo.currentText(),
            "interface": self.interface_input.text(),
        }



class BastilleGUI(QMainWindow):
    def __init__(self):
        if os.geteuid() != 0:
            app = QApplication(sys.argv)
            QMessageBox.critical(None, "Permission Error", "このアプリはroot権限で実行してください。")
            sys.exit(1)

        super().__init__()
        self.setWindowTitle("Bastille Jail Manager")

        self.resize(800, 600)
        self.jails = []
        # メインウィジェット
        self.central_widget = QTextEdit()
        self.central_widget.setReadOnly(True)
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # テーブルウィジェット
        self.jail_table = QTableWidget()
        self.jail_table.setColumnCount(6)  # JID, State, Hostname, Path,Action,Console
        self.jail_table.setHorizontalHeaderLabels(["State","JID", "Hostname", "Path","Action","Console"])
        self.jail_table.cellClicked.connect(self.display_jail_details)

        # 詳細表示用のテキストエリア
        self.output = QTextEdit()
        self.output.setReadOnly(True)


        self.jail_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.jail_table.customContextMenuRequested.connect(self.show_context_menu)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.jail_table)
        splitter.addWidget(self.output)
        # テーブルヘッダーの設定
        header = self.jail_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)  # コンテンツに応じてサイズ調整
        header.setSectionResizeMode(3, QHeaderView.Stretch)         # Path列を残り幅で埋める


        # スプリッター初期設定（テーブル: 70%, 出力: 30%）
        splitter.setSizes([400, 200])  # 上部が400px、下部が200pxの初期サイズ

        # レイアウトにスプリッターを追加
        layout = QVBoxLayout()
        layout.addWidget(splitter)
        central_widget.setLayout(layout)

        # TODO: RDR is something went wrang. It makes syntax error but does not
        #  occur any error. and this function is not working in my env.

        # self.port_forwarding_button = QPushButton("Port Forwarding", self)
        # self.port_forwarding_button.clicked.connect(self.port_forwarding)
        # layout.addWidget(self.port_forwarding_button)


        # メニューバーとアクション
        self.menu_bar = QMenuBar(self)
        self.setMenuBar(self.menu_bar)

        # File メニュー
        file_menu = self.menu_bar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)




        jails_menu = self.menu_bar.addMenu("Jails")
        self.refresh_action = QAction("Refresh", self)
        self.refresh_action.triggered.connect(self.list_jails)  # 手動更新アクション
        jails_menu.addAction(self.refresh_action)

        # Help メニュー
        help_menu = self.menu_bar.addMenu("Help")
        about_action = QAction("About this app", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Create アクション
        self.bootstrap_action = QAction("Bootstrap", self)
        self.bootstrap_action.triggered.connect(self.bootstrap_release)
        jails_menu.addAction(self.bootstrap_action)

        # Create アクション
        self.create_action = QAction("Create Jail", self)
        self.create_action.triggered.connect(self.create_jail)
        jails_menu.addAction(self.create_action)

        # Destroy アクション
        self.destroy_action = QAction("Destroy Jail", self)
        self.destroy_action.triggered.connect(self.destroy_jail)
        jails_menu.addAction(self.destroy_action)

        # タイマー (一定間隔で更新)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.list_jails)
        self.timer.start(10000)  # 10秒間隔 (10000ミリ秒)

        # 起動時にリストを取得＆表示
        self.list_jails()

    def get_bastille_version(self):
        try:
            result = subprocess.run(['bastille', '--version'],
                                    capture_output=True,
                                    text=True,
                                    check=True)
            version_text = result.stdout.strip()
            match = re.match(r'(\d+)\.(\d+)\.(\d+)', version_text)
            if match:
                major, minor, build = match.groups()
                return {
                    'major': int(major),
                    'minor': int(minor),
                    'build': int(build),
                    'text': version_text
                }
            return {'major': 0, 'minor': 0, 'build': 0, 'text': version_text}
        except (subprocess.SubprocessError, OSError):
            return {'major': 0, 'minor': 0, 'build': 0, 'text': 'unknown'}


    def show_about_dialog(self):
        """About ダイアログを表示"""
        version_text = self.get_bastille_version()['text']
        QMessageBox.about(self, "About Bastix",
                          "Bastix v1.1\n\n"
                          f"Running with bastille version: {version_text}\n\n"
                          "A GUI for managing Bastille configurations and jails on FreeBSD.\n"
                          "Features include jail creation,destroy,start/stop,console login.\n\n"
                          "Author: Yuto Yamada(y.saffrontea@gmail.com)\n"
                          "License: MIT"
                          )


    def show_context_menu(self, pos: QPoint):
        """右クリックメニューを表示する"""
        # コンテキストメニューを表示するターゲットセルを取得
        item = self.jail_table.itemAt(pos)
        if item is None:
            return

        row = item.row()
        jail = self.jails[row]  # 選択されたJailデータを取得

        # コンテキストメニューを作成
        menu = QMenu(self)

        # 「開始」アクションを作成
        start_action = QAction("Start", self)
        start_action.triggered.connect(lambda: self.start_jail(jail["Hostname"]))
        start_action.setEnabled(jail["State"].lower() == "down")  # 状態が「down」で有効化

        # 「停止」アクションを作成
        stop_action = QAction("Stop", self)
        stop_action.triggered.connect(lambda: self.stop_jail(jail["Hostname"]))
        stop_action.setEnabled(jail["State"].lower() == "up")  # 状態が「up」で有効化

        restart_action = QAction("Restart", self)
        restart_action.triggered.connect(lambda: self.restart_jail(jail["Hostname"]))

        destroy_action = QAction("Destroy", self)
        destroy_action.triggered.connect(lambda: self.destroy_jail())
        destroy_action.setEnabled(jail["State"].lower() == "down")  # 状態が「down」で有効化


    # 「コンソール」アクションを作成
        console_action = QAction("Open Console", self)
        console_action.triggered.connect(lambda: self.start_console_in_terminal(jail["Hostname"]))


        # メニューにアクションを追加
        menu.addAction(start_action)
        menu.addAction(stop_action)
        menu.addAction(restart_action)
        menu.addAction(destroy_action)
        menu.addAction(console_action)

    # メニューを表示
        menu.exec(self.jail_table.viewport().mapToGlobal(pos))


    @staticmethod
    def parse_jail_list(output):

        try:
            result = subprocess.run(['bastille', '--version'],
                                    capture_output=True,
                                    text=True,
                                    check=True)
            version_text = result.stdout.strip()
            match = re.match(r'(\d+)\.(\d+)\.(\d+)', version_text)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
            else:
                major, minor = 0, 0
        except (subprocess.SubprocessError, OSError):
            major, minor = 0, 0

        lines = output.strip().split("\n")

        if len(lines) <= 1:
            return []

        data_lines = lines[1:]

        # Version Check
        if major == 0 and minor <= 13:
            columns = [
                "JID",
                "State",
                "IP Address",
                "Published Ports",
                "Hostname",
                "Release"
            ]
        else:
            columns = [
                "JID",
                "Boot",
                "Prio",
                "State",
                "IP Address",
                "Published Ports",
                "Hostname",
                "Release"
            ]

        jail_list = []
        for line in data_lines:
            # 各フィールドをスペースで分割
            fields = line.split()

            # 必要なフィールドが揃っていない場合はスキップ
            min_fields = len(columns)
            if len(fields) < min_fields:
                continue

            # フィールドを辞書形式で格納
            jail_data = {}
            for i, column in enumerate(columns):
                if i < len(fields):
                    jail_data[column] = fields[i]

            path_index = len(columns)
            if len(fields) > path_index:
                jail_data["Path"] = " ".join(fields[path_index:])
            else:
                jail_data["Path"] = ""

            jail_list.append(jail_data)
        return jail_list




    def list_jails(self):
        result = subprocess.run(["bastille", "list", "-a"], capture_output=True, text=True)
        if result.returncode != 0:
            self.central_widget.setText(f"error: {result.stderr}")
        else:
            self.jails = self.parse_jail_list(result.stdout)

            # QTableWidget にデータを表示
            self.jail_table.setRowCount(len(self.jails))  # 行数を設定
            for row, jail in enumerate(self.jails):
                # JID列
                jid_item = QTableWidgetItem(jail["JID"])
                jid_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # 左寄せ＆中央揃え
                jid_item.setFont(QFont("Arial", 10))  # フォント調整
                self.jail_table.setItem(row,1, jid_item)


                # Hostname列
                hostname_item = QTableWidgetItem(jail["Hostname"])
                hostname_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # 左寄せ＆中央揃え
                hostname_item.setFont(QFont("Arial", 10))  # 余白感を出すためのフォント調整
                self.jail_table.setItem(row, 2, hostname_item)

                # Path列
                path_item = QTableWidgetItem(jail["Path"])
                path_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                self.jail_table.setItem(row, 3, path_item)

                # 状態を表すカスタムラベル (QLabel) を作成
                state_label = QLabel()
                state_label.setAlignment(Qt.AlignCenter)  # 中央揃え
                state_label.setText(self.get_state_icon_html(jail["State"]))  # HTML適用
                state_label.setStyleSheet("font-size: 16px;")  # 必要に応じてサイズ調整
                self.jail_table.setCellWidget(row, 0, state_label)  # カスタムセルとしてセット

                # 操作ボタンの設定
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(0, 0, 0, 0)

                # 「停止」「開始」の各ボタンを作成
                if jail["State"].lower() == "up":
                    stop_button = QPushButton("Stop")
                    stop_button.clicked.connect(lambda _, h=jail["Hostname"]: self.stop_jail(h))
                    action_layout.addWidget(stop_button)
                else:
                    start_button = QPushButton("Start")
                    start_button.clicked.connect(lambda _, h=jail["Hostname"]: self.start_jail(h))
                    action_layout.addWidget(start_button)

                action_widget.setLayout(action_layout)
                self.jail_table.setCellWidget(row, 4, action_widget)

                # Console列
                console_button = QPushButton("Console")
                console_button.clicked.connect(lambda _, h=jail["Hostname"]: self.start_console_in_terminal(h))
                self.jail_table.setCellWidget(row, 5, console_button)



            # 列幅の調整
            self.adjust_table_column_width()

    @staticmethod
    def get_state_icon_html(state):
        # 状態を色付きのHTML絵文字で表現
        if state.lower() == "up":
            return '<span style="color: green;padding 2px 0;margin 0 0;text-align:center;">🟢</span>'
        elif state.lower() == "down":
            return '<span style="color: red;padding 2px 0;margin 0 0;text-align:center;">🔴</span>'
        else:
            return '<span style="color: gray;padding 2px 0;margin 0 0;text-align:center;">?</span>'


    def display_jail_details(self, row, column):
        if row < 0 or row >= len(self.jails):
            return

        jail = self.jails[row]

        details = f"<b>Information of {jail.get('Hostname', 'Unknown')}:</b><br><br>"

        primary_fields = [
            "JID", "Boot", "Prio", "State", "IP Address",
            "Published Ports", "Hostname", "Release", "Path"
        ]

        for field in primary_fields:
            if field in jail:
                value = jail[field]
                if value == "" or value == "-":
                    value = "<i>None</i>"
                details += f"<b>{field}:</b> {value}<br>"

        # その他の追加フィールド（バージョンによって追加される可能性のあるもの）
        other_fields = [f for f in jail.keys() if f not in primary_fields]
        for field in sorted(other_fields):  # アルファベット順に表示
            value = jail[field]
            if value == "" or value == "-":
                value = "<i>None</i>"
            details += f"<b>{field}:</b> {value}<br>"

        # 詳細情報を表示（既存のUIコンポーネントに応じて設定）
        if hasattr(self, 'output') and self.output is not None:
            self.output.setHtml(details)


    def adjust_table_column_width(self):
        """テーブルのカラム幅を調整"""
        # 自動幅調整
        self.jail_table.resizeColumnsToContents()

        # 手動調整 (特定列の幅を最適化)
        self.jail_table.setColumnWidth(1, 50)  # JID
        self.jail_table.setColumnWidth(0, 100)  # State
        self.jail_table.setColumnWidth(2, 150)  # Hostname
        self.jail_table.setColumnWidth(3, 300)  # Path
        self.jail_table.setColumnWidth(4, 100)  # 操作


        # 必要であれば調整を加える
        for col in range(self.jail_table.columnCount()):
            # カラム幅が狭すぎる場合は最低幅を設定
            if self.jail_table.columnWidth(col) < 100:
                self.jail_table.setColumnWidth(col, 100)

    def start_jail(self, hostname):
        """指定されたJailを開始"""
        result = subprocess.run(["bastille", "start", hostname], capture_output=True, text=True)
        if result.returncode == 0:
            self.output.setText(f"Started Jail {hostname} \n"
                                f"{result.stdout}")
        else:
            self.output.setText(f"error while starting jail {hostname}: {result.stderr}")
        self.list_jails()

    def stop_jail(self, hostname):
        """指定されたJailを停止"""
        result = subprocess.run(["bastille", "stop", hostname], capture_output=True, text=True)
        if result.returncode == 0:
            self.output.setText(f"Stopped Jail {hostname} \n"
                                f"{result.stdout}")
        else:
            self.output.setText(f"error while stopping jail {hostname}: {result.stderr}")
        self.list_jails()

    def restart_jail(self, hostname):
        """指定されたJailを開始"""
        result = subprocess.run(["bastille", "restart", hostname], capture_output=True, text=True)
        if result.returncode == 0:
            self.output.setText(f"Restarted Jail {hostname}\n"
                                f"{result.stdout}")
        else:
            self.output.setText(f"error while restarting jail {hostname}: {result.stderr}")
        self.list_jails()

    def start_console_in_terminal(self, hostname):
        """指定されたJailのコンソールに入る (xtermを使用)"""
        self.output.setText(f"Opening Console: {hostname}")
        try:
            subprocess.Popen(["xterm", "-e", f"bastille console {hostname}|| (echo \"press any key...\" &&read str)"])
        except FileNotFoundError:
            self.output.setText("error: Cant find xterm")

    def run_bastille_command(self, command):
        """Bastilleコマンドを実行して出力を表示"""
        result = subprocess.run(["bastille", *command], capture_output=True, text=True)
        if result.returncode == 0:
            self.output.setText(f"Running command:{command}\n"
                f"{result.stdout}")
        else:
            self.output.setText(f"error: {result.stderr}")



    def create_jail(self):
        """新しい Jail を作成する"""
        dialog = CreateJailDialog(self)
        if dialog.exec() == QDialog.Accepted:
            inputs = dialog.get_inputs()

            name = inputs["name"]
            release = inputs["release"]
            ip = inputs["ip"]
            vnet_option = inputs["vnet_option"]
            interface = inputs["interface"]

            # bastille create コマンドを構築
            command = ["bastille", "create"]

            if vnet_option == "New Virtual Bridge":
                command.append("-V")
            elif vnet_option == "Attach to Existing Bridge" and interface:
                command.append(f"-B")

            if name and release:
                command.append(name)
                command.append(release)
            else:
                QMessageBox.warning(self, "Input Error", "Name and Release are required fields!")
                return

            if ip:
                command.append(ip)

            # VNET 設定を追加 (オプションの選択に応じて)
            if vnet_option == "Attach to Existing Bridge" and interface:
                command.append(f"{interface}")

            # コマンド実行
            try:
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode == 0:
                    QMessageBox.information(self, "Success", f"Jail '{name}' created successfully!")
                    self.list_jails()
                else:
                    QMessageBox.critical(self, "Error", f"Failed to create Jail:\n{result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")


    def destroy_jail(self):
        """Jail を削除する"""
        selected_items = self.jail_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a Jail to destroy.")
            return

        # テーブルから選択した Jail の Hostname を取得
        row = selected_items[0].row()  # 最初に選択された行
        hostname = self.jail_table.item(row, 2).text()  # 3列目（Hostname）

        # 警告ダイアログを表示
        reply = QMessageBox.warning(
            self,
            "Confirm Deletion",
            f"Are you sure you want to destroy the Jail '{hostname}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        # Yes を選択した場合のみ削除
        if reply == QMessageBox.Yes:
            try:
                result = subprocess.run(["bastille", "destroy", hostname], capture_output=True, text=True)
                if result.returncode == 0:
                    QMessageBox.information(self, "Success", f"Jail '{hostname}' destroyed successfully!")
                    self.list_jails()
                else:
                    QMessageBox.critical(self, "Error", f"Failed to destroy Jail:\n{result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")

    def bootstrap_release(self):
        """Bootstrapダイアログを呼び出す"""
        dialog = BootstrapDialog(self)
        dialog.exec()

    def port_forwarding(self):
        dialog = RDRManagementDialog(self)
        dialog.exec()






if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BastilleGUI()
    window.show()
    sys.exit(app.exec_())

