# fim_gui_v2_integrated_part1.py — PART 1: Core + Anomaly Detection Integration
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from datetime import datetime
import csv
import json
import winsound
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from tkcalendar import Calendar

# Import the anomaly detector module
from anomaly_detector import AnomalyDetector

# === SETUP ===
CERT_DIR = "certs"
KEY_DIR = "keys"
REVOKED_FILE = "revoked.json"
CONFIG_FILE = "config.json"
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs("CSV_logs", exist_ok=True)

# === PERFECT THEMES ===
THEMES = {
    "cyberpunk": {
        "bg": "#0f0f1e", "fg": "#00ffcc", "btn": "#ff0066", "btn_fg": "white",
        "entry_bg": "#1a1a2e", "text_bg": "#000814", "text_fg": "#00ff88", "select": "#ff3399"
    },
    "dracula": {
        "bg": "#282a36", "fg": "#f8f8f2", "btn": "#bd93f9", "btn_fg": "#282a36",
        "entry_bg": "#44475a", "text_bg": "#21222c", "text_fg": "#f8f8f2", "select": "#ff79c6"
    },
    "light": {
        "bg": "#ffffff", "fg": "#2c3e50", "btn": "#3498db", "btn_fg": "white",
        "entry_bg": "#f0f0f0", "text_bg": "#f8f9fa", "text_fg": "#2c3e50", "select": "#2980b9"
    }
}

# === CONFIG ===
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except:
            pass
    return {
        "theme": "cyberpunk", 
        "alert_sound": True, 
        "alert_popup": True, 
        "window_size": "1400x900",
        "anomaly_detection": True,
        "remote_monitoring": False,
        "remote_port": 5443
    }

def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

config = load_config()

# === AUTH ===
def verify_login(username, password):
    return (username == "admin" and password == "admin") or (username == "prajwal" and password == "123")

# === ENHANCED MONITORING HANDLER WITH ANOMALY DETECTION ===
class RealtimeHandler(FileSystemEventHandler):
    def __init__(self, text_widget, anomaly_detector=None, remote_server=None):
        self.text = text_widget
        self.anomaly_detector = anomaly_detector
        self.remote_server = remote_server
        self.event_count = {"CREATED": 0, "MODIFIED": 0, "DELETED": 0}

    def log(self, action, path):
        timestamp = datetime.now().strftime('%H:%M:%S')
        msg = f"[{timestamp}] {action}: {os.path.basename(path)}\n"
        
        # Update event counter
        self.event_count[action] = self.event_count.get(action, 0) + 1
        
        # Anomaly detection
        anomaly_status = ""
        if self.anomaly_detector and config.get("anomaly_detection", True):
            is_anomaly, current_rate, status = self.anomaly_detector.record_event()
            
            if is_anomaly:
                anomaly_status = f" ⚠️ ANOMALY DETECTED! Rate: {current_rate:.1f}/min"
                msg = f"[{timestamp}] {action}: {os.path.basename(path)}{anomaly_status}\n"
                
                # Extra alert for anomalies
                if config["alert_popup"]:
                    messagebox.showwarning(
                        "⚠️ ANOMALY DETECTED",
                        f"Unusual file activity detected!\n\n"
                        f"Action: {action}\n"
                        f"File: {os.path.basename(path)}\n"
                        f"Rate: {current_rate:.1f} events/min\n"
                        f"Status: {status}"
                    )
                
                if config["alert_sound"]:
                    # Different sound pattern for anomalies
                    for _ in range(3):
                        winsound.Beep(1500, 150)
        
        # Log to text widget
        self.text.configure(state="normal")
        self.text.insert("end", msg)
        self.text.see("end")
        self.text.configure(state="disabled")

        # Regular alerts (if not anomaly)
        if not anomaly_status:
            if config["alert_popup"]:
                title = {"CREATED": "File Created", "MODIFIED": "File Modified", "DELETED": "File Deleted"}
                messagebox.showwarning(title.get(action, "File Change"), msg.strip())

            if config["alert_sound"]:
                freq = 1200 if action == "CREATED" else 800 if action == "DELETED" else 1000
                winsound.Beep(freq, 300)
        
        # Send to remote server if enabled
        if self.remote_server and config.get("remote_monitoring", False):
            try:
                event_data = {
                    "action": action,
                    "path": path,
                    "filename": os.path.basename(path),
                    "timestamp": timestamp,
                    "anomaly": bool(anomaly_status)
                }
                self.remote_server.add_event(event_data)
            except Exception as e:
                print(f"Remote logging error: {e}")

    def on_created(self, e): 
        if not e.is_directory:
            self.log("CREATED", e.src_path)
    
    def on_modified(self, e): 
        if not e.is_directory:
            self.log("MODIFIED", e.src_path)
    
    def on_deleted(self, e): 
        if not e.is_directory:
            self.log("DELETED", e.src_path)

# === MAIN APP ===
class FIMApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecureFIM Pro v2.0")
        self.root.geometry(config["window_size"])
        self.observer = None
        self.monitoring = False
        
        # Initialize Anomaly Detector
        self.anomaly_detector = AnomalyDetector(window_size=60, threshold=2.5)
        
        # Remote server placeholder (will be initialized in Part 2)
        self.remote_server = None

        if not self.show_login():
            self.root.destroy()
            return

        self.root.title(f"SecureFIM Pro — {config.get('last_user', 'User').title()}")
        self.build_ui()
        self.apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Start statistics update loop
        self.update_anomaly_stats()
        
        self.root.mainloop()

    def show_login(self):
        login_win = tk.Toplevel()
        login_win.title("Secure Login")
        login_win.geometry("520x620")
        login_win.configure(bg="#0f0f1e")
        login_win.resizable(False, False)
        login_win.grab_set()
        login_win.attributes("-topmost", True)

        tk.Label(login_win, text="SECUREFIM PRO", font=("Orbitron", 36, "bold"), fg="#00ffcc", bg="#0f0f1e").pack(pady=100)
        tk.Label(login_win, text="Username", fg="#00ffcc", bg="#0f0f1e", font=("Helvetica", 14)).pack(pady=(40,5))
        user_entry = tk.Entry(login_win, font=("Consolas", 16), width=32, justify="center", bg="#1e1e3f", fg="#00ffcc", insertbackground="#00ffcc")
        user_entry.pack(pady=8)

        tk.Label(login_win, text="Password", fg="#00ffcc", bg="#0f0f1e", font=("Helvetica", 14)).pack(pady=(30,5))
        pass_entry = tk.Entry(login_win, show="●", font=("Consolas", 16), width=32, justify="center", bg="#1e1e3f", fg="#00ffcc", insertbackground="#00ffcc")
        pass_entry.pack(pady=8)

        def login():
            u = user_entry.get().strip()
            p = pass_entry.get()
            if verify_login(u, p):
                config["last_user"] = u
                save_config()
                login_win.destroy()
            else:
                messagebox.showerror("Access Denied", "Invalid credentials", parent=login_win)

        tk.Button(login_win, text="LOGIN", command=login, bg="#ff0066", fg="white",
                  font=("bold", 18), width=28, height=2).pack(pady=60)
        login_win.bind("<Return>", lambda e: login())
        self.root.wait_window(login_win)
        return "last_user" in config

    def apply_theme(self):
        t = THEMES[config["theme"]]
        self.root.configure(bg=t["bg"])

        def style(w):
            try:
                if isinstance(w, (tk.Frame, tk.Label, tk.Tk)):
                    w.configure(bg=t["bg"])
                if isinstance(w, tk.Label):
                    w.configure(fg=t["fg"], bg=t["bg"])
                if isinstance(w, tk.Button):
                    w.configure(bg=t["btn"], fg=t["btn_fg"], activebackground=t["select"])
                if isinstance(w, tk.Entry):
                    w.configure(bg=t["entry_bg"], fg=t["fg"], insertbackground=t["fg"])
                if isinstance(w, tk.Text):
                    w.configure(bg=t["text_bg"], fg=t["text_fg"], state="normal")
            except: pass

        for widget in self.root.winfo_children():
            style(widget)
            for child in widget.winfo_children():
                style(child)
                for g in child.winfo_children():
                    style(g)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=t["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=t["btn"], foreground=t["btn_fg"], padding=10)
        style.map("TNotebook.Tab", background=[("selected", t["select"])])

    def build_ui(self):
        t = THEMES[config["theme"]]

        top = tk.Frame(self.root, bg=t["bg"])
        top.pack(fill="x", pady=(0,10))
        
        # Calendar button on the left
        tk.Button(top, text="📅 Calendar", command=self.show_calendar,
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 11), 
                 padx=15, pady=5).pack(side="left", padx=20)
        
        tk.Label(top, text="Theme:", fg=t["fg"], bg=t["bg"], font=12).pack(side="right", padx=20)
        self.theme_combo = ttk.Combobox(top, values=list(THEMES.keys()), state="readonly", width=12)
        self.theme_combo.set(config["theme"])
        self.theme_combo.pack(side="right", padx=10)
        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self.change_theme())

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=10)

        self.home = tk.Frame(self.notebook, bg=t["bg"])
        self.monitor = tk.Frame(self.notebook, bg=t["bg"])
        self.anomaly = tk.Frame(self.notebook, bg=t["bg"])  # NEW TAB
        self.logs = tk.Frame(self.notebook, bg=t["bg"])
        self.dashboard = tk.Frame(self.notebook, bg=t["bg"])
        self.users = tk.Frame(self.notebook, bg=t["bg"])
        self.settings = tk.Frame(self.notebook, bg=t["bg"])

        self.notebook.add(self.home, text="🏠Home")
        self.notebook.add(self.monitor, text="🖥️Monitor")
        self.notebook.add(self.anomaly, text="🔍Anomaly")  # NEW TAB
        self.notebook.add(self.logs, text="📄Logs")
        self.notebook.add(self.dashboard, text="Dashboard")
        self.notebook.add(self.users, text="👤Users")
        self.notebook.add(self.settings, text="⚙️Settings")

        self.build_home()
        self.build_monitor()
        self.build_anomaly_tab()  # NEW
        self.build_logs()
        self.build_dashboard()
        self.build_users()
        self.build_settings()

    def change_theme(self):
        config["theme"] = self.theme_combo.get()
        save_config()
        self.apply_theme()

    def show_calendar(self):
        """Display a calendar in a popup window"""
        cal_win = tk.Toplevel(self.root)
        cal_win.title("Calendar")
        cal_win.geometry("400x450")
        t = THEMES[config["theme"]]
        cal_win.configure(bg=t["bg"])
        cal_win.resizable(False, False)
        
        tk.Label(cal_win, text="📅 Calendar", font=("Helvetica", 18, "bold"), 
                fg=t["fg"], bg=t["bg"]).pack(pady=15)
        
        cal = Calendar(cal_win, selectmode='day', 
                      year=datetime.now().year, 
                      month=datetime.now().month,
                      day=datetime.now().day,
                      background=t["btn"],
                      foreground=t["btn_fg"],
                      selectbackground=t["select"],
                      selectforeground="white",
                      borderwidth=2)
        cal.pack(pady=20, padx=20)
        
        selected_date_label = tk.Label(cal_win, text="", font=("Consolas", 12), 
                                      fg=t["fg"], bg=t["bg"])
        selected_date_label.pack(pady=10)
        
        def show_selected():
            date = cal.get_date()
            selected_date_label.config(text=f"Selected: {date}")
        
        btn_frame = tk.Frame(cal_win, bg=t["bg"])
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Show Selected", command=show_selected, 
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 10), 
                 width=15).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="Close", command=cal_win.destroy, 
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 10), 
                 width=15).pack(side="left", padx=5)

    def build_home(self):
        t = THEMES[config["theme"]]
        tk.Label(self.home, text="SecureFIM Pro v2.0", font=("Orbitron", 38, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=100)
        tk.Label(self.home, text="Real-time • Encrypted • Signed • Tamper-Proof • ML Anomaly Detection", 
                fg=t["fg"], bg=t["bg"], font=("Helvetica", 16)).pack(pady=20)

        self.ticker_frame = tk.Frame(self.home, bg=t["btn"], height=50)
        self.ticker_frame.pack(fill="x", pady=40)
        self.ticker_frame.pack_propagate(False)

        self.ticker_label = tk.Label(
            self.ticker_frame,
            text="",
            font=("Consolas", 14, "bold"),
            fg="white",
            bg=t["btn"],
            anchor="w",
            padx=20
        )
        self.ticker_label.pack(fill="both", expand=True)

        self.ticker_full_text = "   BUILT BY VAYANKAR CODER PRAJWAL   •   ADVANCED FILE INTEGRITY MONITORING   •   PKI + REAL-TIME ALERTS + ML ANOMALY DETECTION   •   VERSION 2.0   "
        self.ticker_text = self.ticker_full_text * 2
        self.ticker_offset = 0

        def scroll_ticker():
            if not hasattr(self, 'home') or not self.home.winfo_exists():
                return
            self.ticker_offset += 1
            if self.ticker_offset >= len(self.ticker_full_text) * 10:
                self.ticker_offset = 0
            start_char = self.ticker_offset // 10
            display = self.ticker_text[start_char:start_char + 120]
            self.ticker_label.config(text=display)
            self.home.after(48, scroll_ticker)

        scroll_ticker()

    def build_monitor(self):
        t = THEMES[config["theme"]]
        f = tk.Frame(self.monitor, bg=t["bg"])
        f.pack(pady=40)
        tk.Label(f, text="Folder to Monitor:", fg=t["fg"], bg=t["bg"], font=14).pack()
        self.folder_path = tk.Entry(f, width=90, font=12, bg=t["entry_bg"], fg=t["fg"])
        self.folder_path.pack(pady=15)
        btns = tk.Frame(f, bg=t["bg"])
        btns.pack(pady=10)
        tk.Button(btns, text="Browse", command=lambda: self.folder_path.delete(0,"end") or self.folder_path.insert(0, filedialog.askdirectory() or ""), 
                 bg=t["btn"], fg=t["btn_fg"]).pack(side="left", padx=10)
        tk.Button(btns, text="Start Monitoring", command=self.toggle_monitor, 
                 bg="#27ae60", fg="white", font=("bold", 12)).pack(side="left", padx=10)
        self.log_output = tk.Text(self.monitor, height=22, bg=t["text_bg"], fg=t["text_fg"], 
                                 font=("Consolas", 11), state="disabled")
        self.log_output.pack(padx=30, pady=20, fill="both", expand=True)

    def toggle_monitor(self):
        if self.monitoring:
            if self.observer:
                self.observer.stop()
                self.observer.join()
            self.monitoring = False
            self.log_output.configure(state="normal")
            self.log_output.insert("end", "\n⏹️ Monitoring STOPPED\n")
            self.log_output.configure(state="disabled")
        else:
            path = self.folder_path.get().strip()
            if not path or not os.path.isdir(path):
                messagebox.showerror("Error", "Please select a valid folder!")
                return
            handler = RealtimeHandler(self.log_output, self.anomaly_detector, self.remote_server)
            self.observer = Observer()
            self.observer.schedule(handler, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            self.log_output.configure(state="normal")
            self.log_output.insert("end", f"▶️ Monitoring started: {path}\n")
            self.log_output.configure(state="disabled")

    # NEW: Anomaly Detection Tab
    def build_anomaly_tab(self):
        t = THEMES[config["theme"]]
        
        # Title
        tk.Label(self.anomaly, text="🔍 ML-Based Anomaly Detection", 
                font=("Helvetica", 20, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Statistics Frame
        stats_frame = tk.LabelFrame(self.anomaly, text="Real-Time Statistics", 
                                   bg=t["bg"], fg=t["fg"], font=("bold", 14), padx=20, pady=20)
        stats_frame.pack(padx=40, pady=20, fill="both")
        
        # Create stat labels
        self.stat_labels = {}
        stats = [
            ("current_rate", "Current Rate (events/min):"),
            ("baseline_rate", "Baseline Rate:"),
            ("total_events", "Total Events:"),
            ("learning_phase", "Learning Phase:"),
            ("learning_progress", "Learning Progress:"),
            ("stdev", "Std Deviation:")
        ]
        
        for key, label in stats:
            frame = tk.Frame(stats_frame, bg=t["bg"])
            frame.pack(fill="x", pady=5)
            tk.Label(frame, text=label, fg=t["fg"], bg=t["bg"], 
                    font=("Consolas", 12), width=30, anchor="w").pack(side="left")
            self.stat_labels[key] = tk.Label(frame, text="0", fg=t["select"], 
                                            bg=t["bg"], font=("Consolas", 12, "bold"), anchor="w")
            self.stat_labels[key].pack(side="left", padx=20)
        
        # Controls Frame
        ctrl_frame = tk.Frame(self.anomaly, bg=t["bg"])
        ctrl_frame.pack(pady=20)
        
        tk.Button(ctrl_frame, text="🔄 Refresh Stats", command=self.refresh_anomaly_stats,
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 11), padx=20, pady=8).pack(side="left", padx=10)
        
        tk.Button(ctrl_frame, text="🗑️ Reset Detector", command=self.reset_anomaly_detector,
                 bg="#e74c3c", fg="white", font=("bold", 11), padx=20, pady=8).pack(side="left", padx=10)
        
        # Threshold adjustment
        threshold_frame = tk.Frame(self.anomaly, bg=t["bg"])
        threshold_frame.pack(pady=20)
        
        tk.Label(threshold_frame, text="Detection Threshold (σ):", fg=t["fg"], 
                bg=t["bg"], font=("Consolas", 12)).pack(side="left", padx=10)
        
        self.threshold_var = tk.DoubleVar(value=2.5)
        threshold_scale = tk.Scale(threshold_frame, from_=1.0, to=5.0, resolution=0.1,
                                  orient="horizontal", variable=self.threshold_var,
                                  command=self.update_threshold, bg=t["entry_bg"], 
                                  fg=t["fg"], length=300)
        threshold_scale.pack(side="left", padx=10)
        
        # Info text
        info_text = tk.Text(self.anomaly, height=8, bg=t["text_bg"], fg=t["text_fg"], 
                           font=("Consolas", 10), wrap="word")
        info_text.pack(padx=40, pady=20, fill="both", expand=True)
        info_text.insert("1.0", 
            "📊 Anomaly Detection Info:\n\n"
            "• Learning Phase: Detector learns normal file activity patterns (50 events)\n"
            "• Detection Phase: Flags unusual spikes in file changes using statistical analysis\n"
            "• Threshold: Number of standard deviations from baseline to trigger alert\n"
            "• Higher threshold = fewer false positives, but may miss subtle anomalies\n"
            "• Lower threshold = more sensitive detection, but more false alarms\n"
        )
        info_text.configure(state="disabled")
    
    def update_anomaly_stats(self):
        """Periodically update anomaly statistics"""
        if hasattr(self, 'stat_labels') and self.stat_labels:
            stats = self.anomaly_detector.get_statistics()
            
            for key, label in self.stat_labels.items():
                value = stats.get(key, "N/A")
                if isinstance(value, bool):
                    value = "Yes" if value else "No"
                label.config(text=str(value))
        
        # Schedule next update
        self.root.after(2000, self.update_anomaly_stats)
    
    def refresh_anomaly_stats(self):
        """Manually refresh statistics"""
        stats = self.anomaly_detector.get_statistics()
        for key, label in self.stat_labels.items():
            value = stats.get(key, "N/A")
            if isinstance(value, bool):
                value = "Yes" if value else "No"
            label.config(text=str(value))
        messagebox.showinfo("Refreshed", "Statistics updated successfully!")
    
    def reset_anomaly_detector(self):
        """Reset the anomaly detector"""
        if messagebox.askyesno("Confirm Reset", "Reset anomaly detector and clear all learned patterns?"):
            self.anomaly_detector.reset()
            self.refresh_anomaly_stats()
            messagebox.showinfo("Reset Complete", "Anomaly detector has been reset!")
    
    def update_threshold(self, value):
        """Update detection threshold"""
        self.anomaly_detector.threshold = float(value)

    # Continue to Part 2 for remaining methods...
    
    def build_logs(self):
        t = THEMES[config["theme"]]
        self.logs_display = tk.Text(self.logs, height=30, bg=t["text_bg"], fg=t["text_fg"], 
                                   font=("Consolas", 10), state="disabled")
        self.logs_display.pack(padx=20, pady=20, fill="both", expand=True)
        tk.Button(self.logs, text="Save Logs to CSV", command=self.save_logs_csv, 
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 12)).pack(pady=10)

    def save_logs_csv(self):
        logs = self.log_output.get("1.0", "end").strip()
        if not logs:
            messagebox.showinfo("Empty", "No logs to save")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialdir="CSV_logs", 
                                           title="Save Logs")
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Action", "File", "Anomaly"])
                for line in logs.split("\n"):
                    if line.strip():
                        # Check for anomaly marker
                        is_anomaly = "ANOMALY" in line
                        parts = line.split(" ", 3)
                        if len(parts) >= 3:
                            row = parts + ([is_anomaly] if len(parts) == 3 else [])
                            writer.writerow(row)
            messagebox.showinfo("Success", f"Logs saved to {os.path.basename(path)}")

    def build_dashboard(self):
        tk.Button(self.dashboard, text="🔄Refresh Chart", command=self.refresh_chart).pack(pady=20)
        self.chart_frame = tk.Frame(self.dashboard)
        self.chart_frame.pack(fill="both", expand=True, padx=20, pady=20)

    def refresh_chart(self):
        for widget in self.chart_frame.winfo_children():
            widget.destroy()
        fig, ax = plt.subplots(figsize=(8,6))
        actions = ["Created", "Modified", "Deleted"]
        counts = [30, 45, 25]
        colors = ["#2ecc71", "#f39c12", "#e74c3c"]
        ax.pie(counts, labels=actions, colors=colors, autopct="%1.1f%%", startangle=90)
        ax.axis("equal")
        ax.set_title("File Activity Summary", fontsize=16, pad=20)
        canvas = FigureCanvasTkAgg(fig, self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def build_users(self):
        t = THEMES[config["theme"]]
        f = tk.Frame(self.users, bg=t["bg"])
        f.pack(pady=40)
        tk.Label(f, text="Username:", fg=t["fg"], bg=t["bg"]).pack(side="left", padx=10)
        self.username_entry = tk.Entry(f, width=30, bg=t["entry_bg"], fg=t["fg"])
        self.username_entry.pack(side="left", padx=10)
        tk.Button(f, text="➕Generate Cert + Key", command=self.generate_cert, 
                 bg=t["btn"], fg=t["btn_fg"]).pack(side="left", padx=10)
        tk.Button(f, text="📄Show Certs", command=self.show_certs).pack(pady=20)
        tk.Button(f, text="🚫Revoke Cert", command=self.revoke_cert).pack(pady=10)
        self.cert_output = tk.Text(self.users, height=20, bg=t["text_bg"], fg=t["text_fg"], 
                                  font=("Consolas", 10))
        self.cert_output.pack(padx=20, pady=20, fill="both", expand=True)

    def generate_cert(self):
        name = self.username_entry.get().strip()
        if not name:
            messagebox.showwarning("Error", "Enter username")
            return
        key = rsa.generate_private_key(65537, 2048)
        with open(f"{KEY_DIR}/{name}_private.pem", "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, 
                                     serialization.PrivateFormat.PKCS8, 
                                     serialization.NoEncryption()))
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject) \
            .public_key(key.public_key()).serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.utcnow()) \
            .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 1)) \
            .sign(key, hashes.SHA256())
        with open(f"{CERT_DIR}/{name}.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        self.cert_output.insert("end", f"✅ Generated cert & key for: {name}\n")

    def show_certs(self):
        self.cert_output.delete(1.0, "end")
        for f in os.listdir(CERT_DIR):
            self.cert_output.insert("end", f"📜 Active: {f}\n")

    def revoke_cert(self):
        name = self.username_entry.get().strip()
        if not name: return
        revoked = []
        if os.path.exists(REVOKED_FILE):
            with open(REVOKED_FILE) as f:
                revoked = json.load(f)
        if name not in revoked:
            revoked.append(name)
            with open(REVOKED_FILE, "w") as f:
                json.dump(revoked, f, indent=2)
            self.cert_output.insert("end", f"🚫 Revoked: {name}\n")

    def build_settings(self):
        t = THEMES[config["theme"]]
        f = tk.Frame(self.settings, bg=t["bg"])
        f.pack(pady=50)
        
        # Title
        tk.Label(f, text="⚙️ Application Settings", font=("Helvetica", 20, "bold"),
                fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        # Alert Settings
        alert_frame = tk.LabelFrame(f, text="Alert Settings", bg=t["bg"], fg=t["fg"], 
                                   font=("bold", 12), padx=20, pady=15)
        alert_frame.pack(fill="x", padx=20, pady=10)
        
        self.sound_var = tk.BooleanVar(value=config.get("alert_sound", True))
        tk.Checkbutton(alert_frame, text="🔊 Sound Alerts", variable=self.sound_var,
                      command=lambda: self.update_setting("alert_sound", self.sound_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=12, 
                      activebackground=t["bg"], activeforeground=t["fg"]).pack(anchor="w", pady=5)
        
        self.popup_var = tk.BooleanVar(value=config.get("alert_popup", True))
        tk.Checkbutton(alert_frame, text="💬 Popup Alerts", variable=self.popup_var,
                      command=lambda: self.update_setting("alert_popup", self.popup_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=12,
                      activebackground=t["bg"], activeforeground=t["fg"]).pack(anchor="w", pady=5)
        
        # Detection Settings
        detect_frame = tk.LabelFrame(f, text="Detection Settings", bg=t["bg"], fg=t["fg"],
                                    font=("bold", 12), padx=20, pady=15)
        detect_frame.pack(fill="x", padx=20, pady=10)
        
        self.anomaly_var = tk.BooleanVar(value=config.get("anomaly_detection", True))
        tk.Checkbutton(detect_frame, text="🔍 Anomaly Detection", variable=self.anomaly_var,
                      command=lambda: self.update_setting("anomaly_detection", self.anomaly_var.get()),
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=12,
                      activebackground=t["bg"], activeforeground=t["fg"]).pack(anchor="w", pady=5)
        
        # Remote Monitoring Settings
        remote_frame = tk.LabelFrame(f, text="Remote Monitoring", bg=t["bg"], fg=t["fg"],
                                    font=("bold", 12), padx=20, pady=15)
        remote_frame.pack(fill="x", padx=20, pady=10)
        
        self.remote_var = tk.BooleanVar(value=config.get("remote_monitoring", False))
        tk.Checkbutton(remote_frame, text="🌐 Enable Remote Monitoring", 
                      variable=self.remote_var,
                      command=self.toggle_remote_monitoring,
                      bg=t["bg"], fg=t["fg"], selectcolor=t["bg"], font=12,
                      activebackground=t["bg"], activeforeground=t["fg"]).pack(anchor="w", pady=5)
        
        # Port setting
        port_frame = tk.Frame(remote_frame, bg=t["bg"])
        port_frame.pack(fill="x", pady=5)
        tk.Label(port_frame, text="Port:", fg=t["fg"], bg=t["bg"], font=12).pack(side="left", padx=5)
        self.port_entry = tk.Entry(port_frame, width=10, bg=t["entry_bg"], fg=t["fg"], font=12)
        self.port_entry.insert(0, str(config.get("remote_port", 5443)))
        self.port_entry.pack(side="left", padx=5)
        
        tk.Button(port_frame, text="Update Port", command=self.update_remote_port,
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 10)).pack(side="left", padx=10)
        
        # Server status
        self.server_status_label = tk.Label(remote_frame, text="Status: Stopped", 
                                           fg="#e74c3c", bg=t["bg"], font=("Consolas", 11, "bold"))
        self.server_status_label.pack(pady=10)
        
        # Server controls
        server_ctrl = tk.Frame(remote_frame, bg=t["bg"])
        server_ctrl.pack(pady=5)
        
        tk.Button(server_ctrl, text="▶️ Start Server", command=self.start_remote_server,
                 bg="#27ae60", fg="white", font=("bold", 10), padx=15).pack(side="left", padx=5)
        
        tk.Button(server_ctrl, text="⏹️ Stop Server", command=self.stop_remote_server,
                 bg="#e74c3c", fg="white", font=("bold", 10), padx=15).pack(side="left", padx=5)
        
        tk.Button(server_ctrl, text="🌐 Open API Docs", command=self.show_api_docs,
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 10), padx=15).pack(side="left", padx=5)
    
    def update_setting(self, key, value):
        """Update a configuration setting"""
        config[key] = value
        save_config()
    
    def toggle_remote_monitoring(self):
        """Toggle remote monitoring on/off"""
        enabled = self.remote_var.get()
        config["remote_monitoring"] = enabled
        save_config()
        
        if enabled and not self.remote_server:
            self.initialize_remote_server()
        
        messagebox.showinfo("Remote Monitoring", 
                          f"Remote monitoring {'enabled' if enabled else 'disabled'}")
    
    def update_remote_port(self):
        """Update remote server port"""
        try:
            port = int(self.port_entry.get())
            if 1024 <= port <= 65535:
                config["remote_port"] = port
                save_config()
                messagebox.showinfo("Port Updated", f"Remote port set to {port}")
                
                # Restart server if running
                if self.remote_server and self.remote_server.is_running:
                    messagebox.showinfo("Restart Required", 
                                      "Server restart required for port change to take effect")
            else:
                messagebox.showerror("Invalid Port", "Port must be between 1024 and 65535")
        except ValueError:
            messagebox.showerror("Invalid Port", "Please enter a valid port number")
    
    def initialize_remote_server(self):
        """Initialize the remote monitoring server"""
        try:
            from remote_monitor_server import RemoteMonitorServer
            port = config.get("remote_port", 5443)
            self.remote_server = RemoteMonitorServer(host='0.0.0.0', port=port)
            return True
        except ImportError:
            messagebox.showerror("Import Error", 
                               "Could not import RemoteMonitorServer. Ensure remote_monitor_server.py is available.")
            return False
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to initialize server: {e}")
            return False
    
    def start_remote_server(self):
        """Start the remote monitoring server"""
        if not self.remote_server:
            if not self.initialize_remote_server():
                return
        
        if self.remote_server.is_running:
            messagebox.showinfo("Already Running", "Remote server is already running")
            return
        
        # Ask about SSL
        use_ssl = messagebox.askyesno("SSL Configuration", 
                                     "Enable SSL/TLS encryption?\n\n"
                                     "(Requires certificate files or will generate self-signed)")
        
        cert_file = None
        key_file = None
        
        if use_ssl:
            # Check for existing certificates
            if os.path.exists("server.crt") and os.path.exists("server.key"):
                cert_file = "server.crt"
                key_file = "server.key"
            else:
                # Generate self-signed certificate
                try:
                    from remote_monitor_server import generate_self_signed_cert
                    cert_file, key_file = generate_self_signed_cert()
                    messagebox.showinfo("Certificate Generated", 
                                      "Self-signed certificate generated for SSL")
                except Exception as e:
                    messagebox.showerror("Certificate Error", 
                                       f"Failed to generate certificate: {e}")
                    return
        
        # Start server
        success, message = self.remote_server.start(use_ssl, cert_file, key_file)
        
        if success:
            protocol = "https" if use_ssl else "http"
            self.server_status_label.config(
                text=f"Status: Running on {protocol}://localhost:{config['remote_port']}", 
                fg="#27ae60"
            )
            messagebox.showinfo("Server Started", message)
        else:
            messagebox.showerror("Server Error", message)
    
    def stop_remote_server(self):
        """Stop the remote monitoring server"""
        if not self.remote_server or not self.remote_server.is_running:
            messagebox.showinfo("Not Running", "Remote server is not running")
            return
        
        success, message = self.remote_server.stop()
        self.server_status_label.config(text="Status: Stopped", fg="#e74c3c")
        messagebox.showinfo("Server Stopped", message)
    
    def show_api_docs(self):
        """Show API documentation in a popup"""
        docs_win = tk.Toplevel(self.root)
        docs_win.title("Remote Monitoring API Documentation")
        docs_win.geometry("800x600")
        t = THEMES[config["theme"]]
        docs_win.configure(bg=t["bg"])
        
        tk.Label(docs_win, text="📡 Remote Monitoring API", 
                font=("Helvetica", 18, "bold"), fg=t["fg"], bg=t["bg"]).pack(pady=20)
        
        docs_text = tk.Text(docs_win, bg=t["text_bg"], fg=t["text_fg"], 
                           font=("Consolas", 10), wrap="word")
        docs_text.pack(padx=20, pady=10, fill="both", expand=True)
        
        api_docs = """
🌐 REMOTE MONITORING API ENDPOINTS

Base URL: http://localhost:{port} (or https:// if SSL enabled)

═══════════════════════════════════════════════════════════

GET /api/status
─────────────────
Get server status and basic info
Response: {{"status": "online", "timestamp": "...", "total_events": 123}}

═══════════════════════════════════════════════════════════

GET /api/events?limit=50
────────────────────────
Get recent events (default limit: 50)
Response: {{"events": [...], "total": 123}}

═══════════════════════════════════════════════════════════

GET /api/events/latest
──────────────────────
Get the most recent event
Response: {{"timestamp": "...", "data": {{...}}}}

═══════════════════════════════════════════════════════════

POST /api/clear
───────────────
Clear all stored events
Response: {{"success": true, "message": "Events cleared"}}

═══════════════════════════════════════════════════════════

📝 EXAMPLE USAGE (Python):

import requests

# Get server status
response = requests.get('http://localhost:5443/api/status')
print(response.json())

# Get recent events
response = requests.get('http://localhost:5443/api/events?limit=100')
events = response.json()['events']

# Get latest event
response = requests.get('http://localhost:5443/api/events/latest')
latest = response.json()

═══════════════════════════════════════════════════════════

🔒 SECURITY NOTES:
• Use HTTPS/SSL in production environments
• Events are stored in memory (max 1000 events)
• No authentication by default - add auth middleware for production
• CORS enabled for cross-origin requests

═══════════════════════════════════════════════════════════
        """.format(port=config.get("remote_port", 5443))
        
        docs_text.insert("1.0", api_docs)
        docs_text.configure(state="disabled")
        
        tk.Button(docs_win, text="Close", command=docs_win.destroy,
                 bg=t["btn"], fg=t["btn_fg"], font=("bold", 11), 
                 padx=30, pady=8).pack(pady=15)

    def on_close(self):
        """Handle application closing"""
        # Stop monitoring
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        # Stop remote server
        if self.remote_server and self.remote_server.is_running:
            self.remote_server.stop()
        
        # Save config
        config["window_size"] = f"{self.root.winfo_width()}x{self.root.winfo_height()}"
        save_config()
        
        self.root.destroy()

# === RUN ===
if __name__ == "__main__":
    FIMApp()