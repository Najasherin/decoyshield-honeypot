import csv
import sys
import sqlite3
import threading
import os
from PyQt5.QtCore import QUrl
from folium.plugins import AntPath
import folium
from PyQt5.QtWebEngineWidgets import QWebEngineView
import main
from database import init_db
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5.QtWidgets import (
    QApplication, QFormLayout, QGridLayout, QHeaderView, QWidget, QVBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem,QHBoxLayout,QLineEdit,
    QMessageBox,QScrollArea,QStackedWidget,QTabWidget,QCheckBox,QComboBox)
from PyQt5.QtWidgets import QSystemTrayIcon, QMenu
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtCore import pyqtSignal
from alerts import send_email_alert
from background_monitor import start_background_monitor
from datetime import datetime
from ports import generate_ports
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # for .exe
    except Exception:
        base_path = os.path.abspath(".")  # for normal run
    return os.path.join(base_path, relative_path)
DB_NAME = "decoyshield.db"
HONEYPOT_LAT = 10.8505
HONEYPOT_LON = 76.2711
COUNTRY_COORDS = {
    "United States": (37.0902, -95.7129),
    "China": (35.8617, 104.1954),
    "Russia": (61.5240, 105.3188),
    "Germany": (51.1657, 10.4515),
    "India": (20.5937, 78.9629),
    "Brazil": (-14.2350, -51.9253),
    "United Kingdom": (55.3781, -3.4360),
    "France": (46.2276, 2.2137),
    "Japan": (36.2048, 138.2529),
    "South Korea": (35.9078, 127.7669)
}
window=None
class ThreatChart(FigureCanvas):
        def __init__(self, parent=None):
             self.figure = Figure(facecolor="#121212")
             super().__init__(self.figure)
             self.setParent(parent)
        def plot(self, data):
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            ax.set_facecolor("#121212")
            labels = []
            sizes = []
            colors = []
            for level, count in data:
                labels.append(level)
                sizes.append(count)
                if level == "HIGH":
                    colors.append("red")
                elif level == "MEDIUM":
                    colors.append("orange")
                else:
                    colors.append("green")
            if not sizes or sum(sizes) == 0:
                ax.text(
                    0.5,0.5,
                    "No Attack Data yet",
                    color="white",
                    fontsize=14,
                    ha='center'
                )
            else:    
                wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                wedgeprops=dict(width=0.45),
                textprops={'color': 'white','fontsize':11}
            )
            ax.set_title("Threat Distribution", color="cyan", fontsize=14)
            self.draw()
            
class Dashboard(QWidget):
    attack_signal=pyqtSignal()    
    def __init__(self):
        super().__init__()
        self.honeypot_thread = None
        self.blocked_ips=[]
        self.setWindowTitle("DecoyShield Threat Monitoring System")
        self.setWindowIcon(QIcon(resource_path("icon.ico")))   
        QApplication.setWindowIcon(QIcon(resource_path("icon.ico"))) 
        self.tray = QSystemTrayIcon(QIcon(resource_path("icon.ico")), self)
        self.tray.setVisible(True)
        self.tray.setToolTip("DecoyShield Running")
        self.tray.show()
        self.setGeometry(200, 200, 800, 600)
        self.main_layout = QHBoxLayout()
        self.sidebar = QVBoxLayout()
        self.stack = QStackedWidget()
        self.dashboard_page = QWidget()
        self.logs_page = QWidget()
        self.reports_page = QWidget()
        self.settings_page = QWidget()
        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.logs_page)
        self.stack.addWidget(self.reports_page)
        self.stack.addWidget(self.settings_page)
        self.dashboard_scroll = QScrollArea()
        self.dashboard_scroll.setWidgetResizable(True)
        self.dashboard_container = QWidget()
        self.content_layout = QVBoxLayout(self.dashboard_container)
        self.dashboard_scroll.setWidget(self.dashboard_container)
        dashboard_layout = QVBoxLayout(self.dashboard_page)
        dashboard_layout.addWidget(self.dashboard_scroll)
        
        # Sidebar Container
        self.sidebar_widget = QWidget()
        self.sidebar_widget.setFixedWidth(200)
        self.sidebar_widget.setStyleSheet("""
            background-color: #0d1b2a;
            border-right: 1px solid #00FFCC;
        """)
        self.sidebar.addWidget(QLabel("DECOYSHIELD"))
        self.sidebar.addSpacing(20)
        sidebar_buttons = ["Dashboard", "Logs", "Reports", "Settings"]
        for name in sidebar_buttons:
            btn = QPushButton(name)
            btn.setFixedHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1e293b;
                    border: none;
                    text-align: left;
                    padding-left: 15px;
                }
                QPushButton:hover {
                    background-color: #334155;
                }
            """)
            btn.clicked.connect(lambda checked, name=name:self.switch_page(name))

            
            self.sidebar.addWidget(btn)
        self.sidebar.addStretch()
       
        self.sidebar.addStretch()
        self.sidebar_widget.setLayout(self.sidebar)
        self.main_layout.addWidget(self.sidebar_widget)
        self.main_layout.addWidget(self.stack)
        self.setLayout(self.main_layout)
        # Title
        self.title = QLabel("DECOYSHIELD LIVE THREAT DASHBOARD")
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.content_layout.addWidget(self.title)
        ports = generate_ports()
        port_count = len(ports)
        self.system_status = QLabel(
            f"🛡️ DecoyShield Status: ACTIVE | Monitoring {port_count} Ports"
        )

        self.system_status.setAlignment(Qt.AlignCenter)
        self.system_status.setStyleSheet("""
        background-color:#1e1e1e;
        color:#00FFC6;
        font-size:15px;
        font-weight:bold;
        padding:6px;
        border:2px solid #00FF88;
        """)

        self.content_layout.addWidget(self.system_status)
        # 🚨 Alert Banner
        self.alert_label = QLabel("")
        self.alert_label.setAlignment(Qt.AlignCenter)
        self.alert_label.setStyleSheet("""
            background-color: #330000;
            color: red;
            font-size: 16px;
            font-weight: bold;
            padding: 8px;
        """)
        self.alert_label.setVisible(False)  # Hidden by default
        self.content_layout.addWidget(self.alert_label)
        self.alerted_ips = set()
        
        # Stats labels
        self.stats_layout = QHBoxLayout()
        self.total_label = QLabel()
        self.threat_label = QLabel()
        self.top_ip_label = QLabel()
        self.top_port_label = QLabel()
        for label in [self.total_label, self.threat_label, self.top_ip_label, self.top_port_label]:
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("""
            background-color:#1e1e1e;
            border-radius:8px;
            padding:20px;
            min-height:90px;
            font-size:17px;
            font-weight:bold;
            """)
            self.stats_layout.addWidget(label)
        self.content_layout.addLayout(self.stats_layout)
        self.effectiveness_label = QLabel()
        self.effectiveness_label.setAlignment(Qt.AlignCenter)
        self.effectiveness_label.setStyleSheet("""
            border: 1px solid #00FFCC;
            padding: 15px;
            font-size: 15px;
            font-weight: bold;
        """)
        self.content_layout.addWidget(self.effectiveness_label)
        # 🔍 Search Bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by IP, Port or Threat Level...")
        self.search_bar.textChanged.connect(self.filter_table)
        self.content_layout.addWidget(self.search_bar)
        # 📊 Threat Distribution Chart and 📈 Attack Timeline Chart
        self.charts_layout = QHBoxLayout()
        # 🌍 World Attack Map
        self.map_view = QWebEngineView()
        self.map_view.setMinimumHeight(350)
        self.content_layout.addWidget(self.map_view)
        self.chart = ThreatChart(self)
        self.timeline_figure = Figure(facecolor="#121212")
        self.timeline_canvas = FigureCanvas(self.timeline_figure)
        self.chart.setMinimumHeight(280)
        self.timeline_canvas.setMinimumHeight(280)
        self.charts_layout.addWidget(self.chart)
        self.charts_layout.addWidget(self.timeline_canvas,1)
        self.content_layout.addLayout(self.charts_layout,1)
        # Table
        self.table = QTableWidget()
        self.table.cellDoubleClicked.connect(self.show_attack_details)
        self.table.setStyleSheet("""
            QHeaderView::section {
                background-color: #111111;
                color: cyan;
                padding: 8px;
                border: 1px solid #00ffff;
                font-weight: bold;
                font-size: 15px;                 
            }
        """)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)  # Hide row numbers
        self.table.setShowGrid(True)
        self.table.setStyleSheet("""
                                 QTableWidget::item:selected{
                                     background-color: #00ffaa;
                                     color: black;
                                 }
        """)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setSortingEnabled(False)
        self.table.clicked.connect(self.select_row)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.content_layout.addWidget(self.table,stretch=3)
        # Refresh button
        self.button_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.export_button = QPushButton("Export CSV")
        self.block_button = QPushButton("Block IP")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.clear_button = QPushButton("Clear")
        self.refresh_button.clicked.connect(self.refresh_dashboard)
        self.clear_button.clicked.connect(self.clear_logs)
        self.export_button.clicked.connect(self.export_to_csv)
        self.block_button.clicked.connect(self.block_selected_ip)
        self.start_button.clicked.connect(self.start_honeypot)
        self.stop_button.clicked.connect(self.stop_honeypot)
        for btn in [
            self.refresh_button,
            self.clear_button,
            self.export_button,
            self.block_button,
            self.start_button,
            self.stop_button
            
        ]:
            btn.setFixedHeight(35)
            self.button_layout.addWidget(btn)
        self.content_layout.addLayout(self.button_layout)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
                color: #00FFCC;
                font-family: Segoe UI;
                font-size: 15px;
                font-weight: bold;           
            }
            QPushButton {
                background-color: #1f1f1f;
                border: 1px solid #00FFCC;
                padding: 8px;
                font-weight: bold;           
            }
            QPushButton:hover {
                background-color: #2a2a2a;
            }
            QTableWidget {
                background-color: #181818;
                gridline-color: #00FFCC;
                font-size: 14px;
                font-weight: bold;
            }
            QHeaderView::section {
                background-color: #111111;
                color: cyan;
                padding: 10px;
                border: 1px solid #00ffff;
                font-weight: bold;
                font-size: 15px;                 
            }   
            QTableWidget::item:selected{
                background-color: #00FFCC;
                color: black;
                font-weight: bold;
            }  
            QTableWidget::item:hover{
                background-color:#003333;
                }  
            QTabWidget::pane {
            border:1px solid #00FFCC;
            }
            QTabBar::tab {
            font-size:16px;
            padding:8px;
            }                                      
        """)
        # 🚨 Blinking effect timer
        self.blink_state = False
        self.blink_timer = QTimer()
        self.blink_timer.setInterval(500)   # Blink every 500ms
        self.blink_timer.timeout.connect(self.toggle_alert_color)
        init_db()
        self.init_logs_page()
        self.init_reports_page()
        self.init_settings_page()
        self.load_data() 
        self.attack_signal.connect(self.load_data)
     # Connect signal to refresh dashboard on new attack
        self.timer = QTimer() #auto refresh timer
        self.timer.timeout.connect(self.load_data)
        self.timer.start(2000)

    def load_data(self):
        conn = sqlite3.connect(DB_NAME,timeout=5)
        cursor = conn.cursor()
        # Total attacks
        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0]
        self.total_label.setText(f"""
        🛡 TOTAL ATTACKS
                                 
        {total}
        """)
        cursor.execute("""
            SELECT threat_level, COUNT(*)
            FROM attacks
            GROUP BY threat_level
        """)
        distribution = cursor.fetchall()
        self.chart.plot(distribution)
        threat_text = "Threat Levels: "
        for level, count in distribution:
            threat_text += f"{level}: {count}  "
        self.threat_label.setText(threat_text)

        # Top attacker
        cursor.execute("""
            SELECT ip, COUNT(*)
            FROM attacks
            GROUP BY ip
            ORDER BY COUNT(*) DESC
            LIMIT 1
        """)
        result = cursor.fetchone()
        if result:
            self.top_ip_label.setText(
                f"Top Attacking IP: {result[0]} ({result[1]} attempts)"
            )
        else:
            self.top_ip_label.setText("Top Attacking IP: N/A(0 attempts)")    

        # Most targeted port
        cursor.execute("""
            SELECT port, COUNT(*)
            FROM attacks
            GROUP BY port
            ORDER BY COUNT(*) DESC
            LIMIT 1
        """)
        result = cursor.fetchone()
        if result:
            self.top_port_label.setText(
                f"Most Targeted Port: {result[0]} ({result[1]} hits)"
            )

        # Recent attacks table
        cursor.execute("""
            SELECT ip, country, city, port, timestamp, threat_level, abuse_confidence, session_duration,
            intent, attacker_type,commands           
            FROM attacks
            ORDER BY  id DESC
            LIMIT 50
        """)
        rows = cursor.fetchall()
        # 🔎 Deception Effectiveness Metrics

        cursor.execute("""
            SELECT AVG(session_duration),
                   MAX(session_duration),
                   SUM(session_duration)
            FROM attacks
        """)
        avg_duration, max_duration, total_duration = cursor.fetchone()

        cursor.execute("""
            SELECT ip, SUM(session_duration) as total_time
            FROM attacks
            GROUP BY ip
            ORDER BY total_time DESC
            LIMIT 1
        """)               
 
        top_engaged = cursor.fetchone()

        if avg_duration:
            avg_duration = round(avg_duration, 2)
        else:
            avg_duration = 0

        if max_duration:
            max_duration = round(max_duration, 2)
        else:
            max_duration = 0

        if total_duration:
            total_duration = round(total_duration, 2)
        else:
            total_duration = 0

        if top_engaged:
            engaged_ip = top_engaged[0]
        else:
            engaged_ip = "N/A"

        self.effectiveness_label.setText(f"""
        📊 DECEPTION EFFECTIVENESS

        Avg Session: {avg_duration}s
        Max Session: {max_duration}s
        Total Engagement: {total_duration}s
        Most Engaged IP: {engaged_ip}
    """)
       
        cursor.execute("""
        SELECT ip
        FROM attacks
        WHERE threat_level='HIGH'
        AND timestamp >= datetime('now','-20 seconds')
        ORDER BY timestamp DESC
        LIMIT 1
        """)

        result = cursor.fetchone()

        if result:
            high_threat_ip = result[0]
        else:
            high_threat_ip = None
        if high_threat_ip:
            self.alert_label.setText(f"🚨 HIGH THREAT DETECTED FROM {high_threat_ip}")
            self.alert_label.setVisible(True)

            if not self.blink_timer.isActive():
                self.blink_timer.start(500)

          
            if high_threat_ip not in self.alerted_ips:
                send_email_alert(high_threat_ip, "HIGH")

                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Critical)
                msg.setWindowTitle("Critical Threat Detected")
                msg.setText(f"HIGH threat detected from {high_threat_ip}")
                msg.setStandardButtons(QMessageBox.Ok)
                msg.show()

                self.tray.showMessage(
                    "DecoyShield Alert",
                    f"High Threat from {high_threat_ip}",
                    QSystemTrayIcon.Critical,
                    5000
                )

                self.alerted_ips.add(high_threat_ip)

        else:
            self.alert_label.setVisible(False)
            self.blink_timer.stop()
            self.alerted_ips.clear()
        self.table.clearContents()    
        self.table.setRowCount(len(rows))
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels(
            ["IP", "Country", "City", "Port", "Timestamp", "Threat Level", "Abuse Confidence", "Session Duration(s)","Intent","Attacker Type", "Commands"]
        )
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(9, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(10, QHeaderView.Stretch)
        for row_index, row_data in enumerate(rows):
            for col_index, item in enumerate(row_data):
                cell = QTableWidgetItem(str(item))
                cell.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)  
                cell.setTextAlignment(Qt.AlignCenter)
                if row_index % 2 == 1:
                    cell.setForeground(Qt.black)  
                else:
                     cell.setForeground(Qt.cyan)
                
                if col_index == 5:
                    if item == "HIGH":
                        cell.setBackground(Qt.red)
                        cell.setForeground(Qt.white)

                    elif item == "MEDIUM":
                        cell.setBackground(Qt.darkYellow)

                    elif item == "LOW":
                        cell.setBackground(Qt.darkGreen)

                self.table.setItem(row_index, col_index, cell)
        self.update_timeline_chart()
        if rows and not hasattr(self, 'map_loaded'):            
            self.update_attack_map()
            self.map_loaded = True
        self.table.repaint()   
        conn.close()
    def refresh_dashboard(self):

        print("[REFRESH] Manual refresh triggered")

        self.load_data()

        self.alert_label.setText("🔄 Dashboard Refreshed")
        self.alert_label.setStyleSheet("""
            background-color: #002b36;
            color: cyan;
            font-size: 14px;
            padding: 6px;
        """)
        self.alert_label.setVisible(True)

        QTimer.singleShot(2000, self.reset_alert_label)

    def clear_logs(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM attacks") 
        conn.commit()
        conn.close()
        self.load_data()

    def update_timeline_chart(self):
        from datetime import datetime, timedelta
        conn = sqlite3.connect(DB_NAME,check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
  
        now = datetime.now()
      
        minutes_list = []
        counts_dict = {}
        for i in range(29, -1, -1):
            minute = (now - timedelta(minutes=i)).strftime("%H:%M")
            minutes_list.append(minute)
            counts_dict[minute] = 0

        cursor.execute("""
            SELECT strftime('%H:%M', timestamp) as minute, COUNT(*)
            FROM attacks
            WHERE timestamp >= datetime('now', '-30 minutes')
            GROUP BY minute
        """)
        data = cursor.fetchall()
        conn.close()
        for minute, count in data:
            if minute in counts_dict:
                counts_dict[minute] = count
        counts = [counts_dict[m] for m in minutes_list]
        self.timeline_figure.clear()
        ax = self.timeline_figure.add_subplot(111)
        ax.plot(minutes_list, counts, color="#22d3ee", linewidth=2)
        ax.fill_between(minutes_list, counts, color="#22d3ee", alpha=0.25)
        ax.set_title("Attack Timeline (Last 30 Minutes)", color="cyan",fontsize=14,fontweight="bold")
        ax.set_xlabel("Time", color="white", fontsize=11,fontweight="bold")
        ax.set_ylabel("Attacks", color="white",fontsize=11,fontweight="bold")
        ax.set_facecolor("#121212")
        self.timeline_figure.patch.set_facecolor("#121212")
        ax.tick_params(axis='x', colors='white', rotation=60,labelsize=9)
        ax.tick_params(axis='y', colors='white',labelsize=10)
        ax.grid(True, linestyle="--", alpha=0.3)
        ax.spines['bottom'].set_color('cyan')
        ax.spines['left'].set_color('cyan')
        ax.spines['top'].set_color('cyan')
        ax.spines['right'].set_color('cyan')
        self.timeline_canvas.draw()
  
    def filter_table(self, text):
        text = text.lower().strip()

        for row in range(self.table.rowCount()):
            row_match = False

            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)

                if item and text in item.text().lower():
                    row_match = True
                    break

            self.table.setRowHidden(row, not row_match)

    def export_to_csv(self):
        import csv
        from datetime import datetime
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT ip, port, timestamp, threat_level, abuse_confidence
            FROM attacks
            ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()
        print("GUI DATA:", rows)
        conn.close()
        filename = f"decoyshield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Port", "Timestamp", "Threat Level", "Abuse Confidence"])
            writer.writerows(rows)
        QMessageBox.information(self, "Export Complete", f"Report saved as:\n{filename}")
   
    def block_selected_ip(self):

        selected_row = self.table.currentRow()

        if selected_row == -1:
            QMessageBox.warning(self, "No Selection", "Please select a row to block.")
            return

        ip_item = self.table.item(selected_row, 0)

        if not ip_item:
            return

        ip = ip_item.text()

        confirm = QMessageBox.question(
            self,
            "Confirm Block",
            f"Do you want to block IP {ip} ?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.No:
            return

        import subprocess

        try:
            command = f'netsh advfirewall firewall add rule name="DecoyShield_Block_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(command, shell=True, check=True)

            QMessageBox.information(
                self,
                "IP Blocked",
                f"{ip} has been blocked successfully."
            )

            self.add_blocked_ip(ip)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block IP:\n{str(e)}")  
    def select_row(self,index):
        self.table.selectRow(index.row())        
    def add_blocked_ip(self, ip, port="Unknown", threat="Unknown"):

        block_time = datetime.now().strftime("%H:%M:%S")

        row = self.blocked_table.rowCount()
        self.blocked_table.insertRow(row)

        self.blocked_table.setItem(row, 0, QTableWidgetItem(ip))
        self.blocked_table.setItem(row, 1, QTableWidgetItem(str(port)))
        self.blocked_table.setItem(row, 2, QTableWidgetItem(threat))
        self.blocked_table.setItem(row, 3, QTableWidgetItem(block_time))
        self.blocked_table.setItem(row, 4, QTableWidgetItem("Manual Block"))           
    def show_context_menu(self, pos):

            menu = QMenu()

            copy_ip = menu.addAction("Copy IP")
            block_ip = menu.addAction("Block IP")

            action = menu.exec_(self.table.viewport().mapToGlobal(pos))

            row = self.table.currentRow()
            ip = self.table.item(row,0).text()

            if action == copy_ip:
                QApplication.clipboard().setText(ip)

            if action == block_ip:
                self.block_selected_ip()
    def start_honeypot(self):
        monitor_thread=threading.Thread(target=start_background_monitor,daemon=True)
        monitor_thread.start()
        ports = generate_ports()
        port_count = len(ports)
        self.system_status.setText(
            f"🟢 DecoyShield Status: ACTIVE | Monitoring {port_count} Ports"
        )
        QMessageBox.information(self, "DecoyShield", "Honeypot Monitoring Started Successfully")
        if not self.honeypot_thread:
            self.honeypot_thread = threading.Thread(
                target=main.start_honeypot,
                daemon=True
            )
            self.honeypot_thread.start()
            QMessageBox.information(self, "Started", "Honeypot Started Successfully")

    def stop_honeypot(self):
        main.stop_honeypot()
        self.honeypot_thread = None
        ports = generate_ports()
        port_count = len(ports)

        self.system_status.setText(
            f"🔴 DecoyShield Status: STOPPED | Monitoring {port_count} Ports"
        )
        QMessageBox.information(self, "Stopped", "Honeypot Stopped Successfully")
    def update_attack_map(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, country
            FROM attacks
            WHERE country IS NOT NULL
        """)
        rows = cursor.fetchall()
        conn.close()
        attack_map = folium.Map(
            location=[30,10],
            zoom_start=2,
            control_scale=True,
            tiles="cartodb dark_matter"
        )
        folium.CircleMarker(
            location=[HONEYPOT_LAT, HONEYPOT_LON],
            radius=12,
            color="lime",
            fill=True,
            fill_color="lime",
            fill_opacity=0.9,
            popup="🛡 DECOYSHIELD HONEYPOT"
        ).add_to(attack_map)
        for ip, country in rows:
            if country in COUNTRY_COORDS:
                lat, lon = COUNTRY_COORDS[country]
               
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=6,
                    color="red",
                    fill=True,
                    fill_color="red",
                    popup=f"Attacker IP: {ip}"
                ).add_to(attack_map)
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=8,
                    color="yellow",
                    fill=True,
                    fill_color="yellow",
                    fill_opacity=0.6,
                    popup=f"ATTACK SOURCE: {ip}"
                ).add_to(attack_map)
            
                AntPath(
                    locations=[[lat, lon], [HONEYPOT_LAT, HONEYPOT_LON]],
                    color="red",
                    weight=4,
                    delay=600,
                    dash_array=[15,25],
                    pulse_color="yellow"
                ).add_to(attack_map)

        attack_map.save("attack_map.html")
        self.map_view.setUrl(
            QUrl.fromLocalFile(os.path.abspath("attack_map.html"))
        )
        
    def toggle_alert_color(self):
        if self.blink_state:
            self.alert_label.setStyleSheet("""
                background-color: #330000;
                color: red;
                font-size: 16px;
                font-weight: bold;
                padding: 8px;
            """)
        else:
            self.alert_label.setStyleSheet("""
                background-color: red;
                color: black;
                font-size: 16px;
                font-weight: bold;
                padding: 8px;
         """)

        self.blink_state = not self.blink_state

    def switch_page(self, name):

        if name == "Dashboard":
            self.stack.setCurrentWidget(self.dashboard_page)

        elif name == "Logs":
            self.stack.setCurrentWidget(self.logs_page)
            self.load_logs()

        elif name == "Reports":
            self.stack.setCurrentWidget(self.reports_page)
            self.generate_report()

        elif name == "Settings":
            self.stack.setCurrentWidget(self.settings_page)    
    def init_logs_page(self):
        layout = QVBoxLayout()
        title = QLabel("ATTACK LOGS")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:18px; font-weight:bold")
        self.logs_table = QTableWidget()
        layout.addWidget(title)
        layout.addWidget(self.logs_table)
        self.logs_page.setLayout(layout)
    
    def load_logs(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
        SELECT ip, country, city, port, timestamp,
        threat_level, abuse_confidence, session_duration,
        intent, attacker_type
        FROM attacks
        ORDER BY timestamp DESC
        """)
        rows = cursor.fetchall()
        self.logs_table.setRowCount(len(rows))
        self.logs_table.setColumnCount(10)
        self.logs_table.setHorizontalHeaderLabels(
            ["IP","Country","City","Port","Time","Threat","Abuse Confidence","Session Duration(s)","Intent","Attacker Type"]
        )
        for r,row in enumerate(rows):
            for c,val in enumerate(row):
                self.logs_table.setItem(r,c,QTableWidgetItem(str(val)))
        conn.close()
    def init_reports_page(self):

        layout = QVBoxLayout()

        title = QLabel("SECURITY REPORTS")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:20px; font-weight:bold")
        layout.addWidget(title)
 
        self.report_summary = QLabel()
        self.report_summary.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.report_summary)

        self.intelligence_label = QLabel()
        self.intelligence_label.setAlignment(Qt.AlignCenter)
        cards_layout = QHBoxLayout()

        self.total_incidents = QLabel("Total Incidents\n0")
        self.blocked_ips = QLabel("Blocked IPs\n0")
        for card in [self.total_incidents, self.blocked_ips]:
            card.setAlignment(Qt.AlignCenter)
            card.setStyleSheet("""
                background-color:#1e1e1e;
                border-radius:10px;
                padding:25px;               
                border:1px solid #00FFCC;
                font-size:18px;
            """)
            cards_layout.addWidget(card)
        layout.addLayout(cards_layout)
        self.report_search = QLineEdit()
        self.report_search.setPlaceholderText("Search Attacker IP...")
        self.report_search.textChanged.connect(self.filter_reports)

        layout.addWidget(self.report_search)

        self.report_table = QTableWidget()
        self.report_table.setColumnCount(3)
        self.report_table.setHorizontalHeaderLabels(
            ["Country", "Attack Count", "Threat Level"]
        )
        self.report_table.setMinimumHeight(400)
        self.report_table.horizontalHeader().setStretchLastSection(True)
        self.report_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        layout.addWidget(self.report_table)
        download_btn = QPushButton("Download Report (CSV)")
        download_btn.clicked.connect(self.export_to_csv)
        layout.addWidget(download_btn)

        self.blocked_label = QLabel("Blocked IP Addresses")
        layout.addWidget(self.blocked_label)
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(5)
        self.blocked_table.setHorizontalHeaderLabels([
            "IP Address",
            "Port",
            "Threat Level",
            "Block Time",
            "Reason"
        ])
        self.blocked_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.blocked_table)
     
        export_btn = QPushButton("Export Full Report")
        export_btn.clicked.connect(self.export_to_csv)
        layout.addWidget(export_btn)

        self.reports_page.setLayout(layout)  
        layout.addStretch() 
        layout.setStretch(2,1)
        layout.setStretch(3,3)

    def filter_reports(self,text):

        text = text.lower()

        for row in range(self.report_table.rowCount()):

            match = False

            for col in range(self.report_table.columnCount()):
                item = self.report_table.item(row,col)

                if item and text in item.text().lower():
                    match = True
                    break

            self.report_table.setRowHidden(row, not match)
    def generate_report(self):

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total = cursor.fetchone()[0]

        cursor.execute("""
        SELECT threat_level, COUNT(*)
        FROM attacks
        GROUP BY threat_level
        """)
        threats = cursor.fetchall()

        cursor.execute("""
        SELECT country, COUNT(*),MAX(threat_level)
        FROM attacks
        GROUP BY country
        ORDER BY COUNT(*) DESC
        LIMIT 5
        """)
        countries = cursor.fetchall()

        text = f"Total Attacks Detected: {total}\n\nThreat Distribution:\n"

        for level,count in threats:
            text += f"{level}: {count}\n"

        self.report_summary.setText(text)

        self.report_table.setRowCount(len(countries))

        for r,row in enumerate(countries):
            for c,val in enumerate(row):
                self.report_table.setItem(r,c,QTableWidgetItem(str(val)))

        conn.close()
    
    def init_settings_page(self):

        layout = QGridLayout()

        title = QLabel("SYSTEM SETTINGS")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size:20px;font-weight:bold")

        tabs = QTabWidget()

        tabs.addTab(self.port_settings_tab(), "Port Management")
        tabs.addTab(self.intelligence_tab(), "Intelligence Keys")
        tabs.addTab(self.deception_tab(), "Deception Strategy")

        layout.addWidget(title)
        layout.addWidget(tabs)

        self.settings_page.setLayout(layout)
    def update_refresh_rate(self):

            try:
                value = int(self.refresh_input.text())

                self.timer.stop()
                self.timer.start(3000)  # 2 seconds

                QMessageBox.information(
                    self,
                    "Updated",
                    f"Dashboard refresh set to 3 seconds"
                )

            except:
                QMessageBox.warning(self,"Error","Enter valid number")
    def port_settings_tab(self):

        tab = QWidget()
        main_layout = QHBoxLayout()

        left_panel = QVBoxLayout()

        title = QLabel("Honeypot Services")
        title.setStyleSheet("font-size:16px;font-weight:bold")

        ssh = QCheckBox("Enable SSH Honeypot (22)")
        ftp = QCheckBox("Enable FTP Honeypot (21)")
        http = QCheckBox("Enable HTTP Honeypot (80)")

        left_panel.addWidget(title)
        left_panel.addSpacing(10)
        left_panel.addWidget(ssh)
        left_panel.addWidget(ftp)
        left_panel.addWidget(http)
        left_panel.addStretch()


        right_panel = QVBoxLayout()

        info_title = QLabel("Service Information")
        info_title.setStyleSheet("font-size:16px;font-weight:bold")

        info_text = QLabel(
            "SSH Honeypot:\nCaptures brute-force login attempts.\n\n"
            "FTP Honeypot:\nDetects anonymous login probes.\n\n"
            "HTTP Honeypot:\nCaptures web vulnerability scans."
        )

        info_text.setWordWrap(True)

        right_panel.addWidget(info_title)
        right_panel.addSpacing(10)
        right_panel.addWidget(info_text)
        right_panel.addStretch()


        main_layout.addLayout(left_panel,1)
        main_layout.addLayout(right_panel,2)

        tab.setLayout(main_layout)

        return tab
    def intelligence_tab(self):

        tab = QWidget()
        main_layout = QHBoxLayout()

        left_layout = QVBoxLayout()

        title = QLabel("Threat Intelligence APIs")
        title.setStyleSheet("font-size:18px;font-weight:bold")

        abuse_key = QLineEdit()
        abuse_key.setPlaceholderText("Enter AbuseIPDB API Key")
        abuse_key.setEchoMode(QLineEdit.Password)

        vt_key = QLineEdit()
        vt_key.setPlaceholderText("Enter VirusTotal API Key")
        vt_key.setEchoMode(QLineEdit.Password)

        abuse_key.setStyleSheet("font-size:16px;padding:6px")
        vt_key.setStyleSheet("font-size:16px;padding:6px")

        left_layout.addWidget(title)
        left_layout.addSpacing(10)
        left_layout.addWidget(QLabel("AbuseIPDB API Key"))
        left_layout.addWidget(abuse_key)

        left_layout.addSpacing(10)
        left_layout.addWidget(QLabel("VirusTotal API Key"))
        left_layout.addWidget(vt_key)

        left_layout.addStretch()


        right_layout = QVBoxLayout()

        info_title = QLabel("API Information")
        info_title.setStyleSheet("font-size:18px;font-weight:bold")

        info_text = QLabel(
            "AbuseIPDB:\n"
            "Checks attacker IP reputation and abuse score.\n\n"
            "VirusTotal:\n"
            "Provides threat intelligence about IP addresses,\n"
            "malware indicators, and malicious infrastructure."
        )

        info_text.setWordWrap(True)
        info_text.setStyleSheet("font-size:15px")

        right_layout.addWidget(info_title)
        right_layout.addSpacing(10)
        right_layout.addWidget(info_text)
        right_layout.addStretch()

        main_layout.addLayout(left_layout,1)
        main_layout.addLayout(right_layout,2)

        tab.setLayout(main_layout)

        return tab
    def deception_tab(self):

        tab = QWidget()
        main_layout = QHBoxLayout()

        left_layout = QVBoxLayout()

        title = QLabel("Deception Strategy Configuration")
        title.setStyleSheet("font-size:18px;font-weight:bold")

        level = QComboBox()
        level.addItems(["Low", "Medium", "High"])
        level.setStyleSheet("font-size:16px;padding:5px")

        left_layout.addWidget(title)
        left_layout.addSpacing(15)
        left_layout.addWidget(QLabel("Response Level"))
        left_layout.addWidget(level)

        left_layout.addStretch()


        right_layout = QVBoxLayout()

        info_title = QLabel("Strategy Description")
        info_title.setStyleSheet("font-size:18px;font-weight:bold")

        info_text = QLabel(
            "Low:\n"
            "Basic logging of attacker activity.\n\n"
            "Medium:\n"
            "Simulated responses and extended engagement.\n\n"
            "High:\n"
            "Full deception mode with fake services,\n"
            "interactive shells and prolonged attacker interaction."
        )

        info_text.setWordWrap(True)
        info_text.setStyleSheet("font-size:15px")

        right_layout.addWidget(info_title)
        right_layout.addSpacing(10)
        right_layout.addWidget(info_text)
        right_layout.addStretch()

        main_layout.addLayout(left_layout,1)
        main_layout.addLayout(right_layout,2)

        tab.setLayout(main_layout)

        return tab
    def show_knock_success(self, ip):
        self.alert_label.setText(f"✅ AUTHORIZED ACCESS GRANTED: {ip}")
        self.alert_label.setStyleSheet("""
            background-color: #003300;
            color: #00ff88;
            font-size: 16px;
            font-weight: bold;
            padding: 8px;
        """)
        self.alert_label.setVisible(True)

        QTimer.singleShot(4000, self.reset_alert_label)
    def reset_alert_label(self):
        self.alert_label.setVisible(False)
        self.alert_label.setStyleSheet("""
            background-color: #330000;
            color: red;
            font-size: 16px;
            font-weight: bold;
            padding: 8px;
        """)    

    def show_attack_details(self, row, column):

        ip = self.table.item(row, 0).text()
        country = self.table.item(row, 1).text()
        city = self.table.item(row, 2).text()
        port = self.table.item(row, 3).text()
        timestamp = self.table.item(row, 4).text()
        threat = self.table.item(row, 5).text()
        abuse = self.table.item(row, 6).text()
        duration = self.table.item(row, 7).text()
        intent = self.table.item(row, 8).text()
        attacker_type = self.table.item(row, 9).text()
        cmd_item = self.table.item(row, 10)
        if cmd_item:
            commands=cmd_item.text()
        else:
            commands="no commands executed"    
        QMessageBox.information(
            self,
            "Attack Details",
            f"""
            🚨 ATTACK DETAILS

            IP Address: {ip}

            🌍 Location
            Country: {country}
            City: {city}

            🎯 Target Information
            Port: {port}
            Timestamp: {timestamp}

            ⚠ Threat Intelligence
            Threat Level: {threat}
            Abuse Confidence: {abuse}%

            ⏱ Engagement
            Session Duration: {duration} sec

            🧠 Attack Analysis
            Intent: {intent}
            Attacker Profile: {attacker_type}
            💻Commands Executed:
            {commands}  
            """

        )
window=None
if __name__ == "__main__":
    import ctypes
    import background_monitor
    myappid = 'decoyshield.app.v1'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    background_monitor.start_background_monitor()
    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()

    sys.exit(app.exec_())