import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import platform
import re
import sys
import os
import ctypes
import socket
import threading

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_SSIDS = ["Group Lancing - Employe 5G", "Group Lancing - Employe 2.4G"]
APP_PORT = 55555  # Fixed port for communication

# Configuration for "National Internet" (Net Melli)
CONFIG_NATIONAL_BASE = {
    "dhcp": False,
    "subnet": "255.255.255.0",
    "gateway": "192.168.80.2",
    "dns": "1.1.1.1 8.8.8.8"
}

# Range of IPs to check for National Internet
NATIONAL_IP_RANGE = [f"192.168.80.{i}" for i in range(5, 10)]

# Configuration for "Normal Internet"
CONFIG_INTERNET = {
    "dhcp": True,
    "ip": "192.168.1.51",
    "subnet": "255.255.255.0",
    "gateway": "192.168.1.2",
    "dns": "1.1.1.1 1.0.0.1"
}

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def is_admin():
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def elevate_privileges():
    if platform.system() == "Windows":
        script = os.path.abspath(sys.argv[0])
        params = " ".join([script] + sys.argv[1:])
        if getattr(sys, 'frozen', False):
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "", None, 1)
        else:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit()
    else:
        args = ['sudo', sys.executable] + sys.argv
        os.execlpe('sudo', *args, os.environ)

# ==========================================
# MAIN APPLICATION
# ==========================================
class NetworkManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GPWAN Network Switcher (Admin)")
        self.root.geometry("600x550")  # Increased width
        
        self.os_type = platform.system()
        self.hostname = socket.gethostname()
        self.current_connected_ssid = None
        
        # Start the listener server in background
        self.server_thread = threading.Thread(target=self.start_listener, daemon=True)
        self.server_thread.start()

        # UI Elements
        self.header = tk.Label(root, text="Network Switcher", font=("Segoe UI", 16, "bold"))
        self.header.pack(pady=10)

        self.status_frame = tk.Frame(root, relief=tk.GROOVE, borderwidth=2)
        self.status_frame.pack(fill=tk.X, padx=20, pady=10)

        self.ssid_label = tk.Label(self.status_frame, text="SSID: Scanning...", font=("Segoe UI", 11))
        self.ssid_label.pack(pady=5)

        self.status_label = tk.Label(self.status_frame, text="Checking...", font=("Segoe UI", 10))
        self.status_label.pack(pady=5)

        self.btn_frame = tk.Frame(root)
        self.btn_frame.pack(pady=10, fill="x", padx=20) # Fill width

        # --- National Internet Section ---
        self.national_frame = tk.LabelFrame(self.btn_frame, text="National Internet (Net Melli)", padx=10, pady=10, font=("Segoe UI", 10, "bold"))
        self.national_frame.pack(pady=5, fill="x")
        
        tk.Label(self.national_frame, text="Select IP Address:").pack(anchor="w")
        
        # Frame for Combo and Refresh Button
        self.combo_frame = tk.Frame(self.national_frame)
        self.combo_frame.pack(fill="x", pady=5)

        # Increased font size and width for better visibility
        self.ip_combo = ttk.Combobox(self.combo_frame, state="readonly", font=("Consolas", 11), width=40)
        self.ip_combo.pack(side=tk.LEFT, fill="x", expand=True)
        
        self.btn_refresh = tk.Button(self.combo_frame, text="↻ Scan IPs", command=self.refresh_ip_list, bg="#f0f0f0")
        self.btn_refresh.pack(side=tk.RIGHT, padx=(5, 0))

        self.btn_national = tk.Button(self.national_frame, text="Apply National IP", 
                                      command=self.set_national, state=tk.DISABLED, 
                                      bg="#e1e1e1", height=2)
        self.btn_national.pack(fill="x", pady=5)

        # --- Normal Internet Section ---
        self.internet_frame = tk.LabelFrame(self.btn_frame, text="Normal Internet", padx=10, pady=10, font=("Segoe UI", 10, "bold"))
        self.internet_frame.pack(pady=10, fill="x")

        self.btn_internet = tk.Button(self.internet_frame, text="Connect to Normal Internet\n(No Iran Sites)", 
                                      command=self.set_internet, state=tk.DISABLED, 
                                      bg="#e1e1e1", height=2)
        self.btn_internet.pack(fill="x", pady=5)
        
        self.log_text = tk.Text(root, height=8, width=60, font=("Consolas", 9))
        self.log_text.pack(pady=10, padx=20, fill="x")

        self.log(f"OS: {self.os_type} | Host: {self.hostname}")
        self.log(f"Listening on port {APP_PORT}...")
        
        # Initial population of list (without scanning to be fast)
        self.ip_combo['values'] = NATIONAL_IP_RANGE
        if NATIONAL_IP_RANGE:
            self.ip_combo.current(0)

        # Start monitoring connection
        self.check_connection()

    def log(self, message):
        self.log_text.insert(tk.END, f"> {message}\n")
        self.log_text.see(tk.END)
        self.root.update()

    # --- Networking Listener ---
    def start_listener(self):
        """Runs a TCP server to respond to other clients scanning this IP."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('0.0.0.0', APP_PORT))
            server_socket.listen(5)
            while True:
                client_socket, addr = server_socket.accept()
                try:
                    # Send my hostname to whoever connects
                    client_socket.send(self.hostname.encode('utf-8'))
                except:
                    pass
                finally:
                    client_socket.close()
        except Exception as e:
            # Port might be busy or permission denied
            print(f"Listener Error: {e}")

    # --- IP Scanner ---
    def refresh_ip_list(self):
        """Scans the target IPs to see if they are running this app."""
        self.log("Scanning IPs for active users...")
        self.btn_refresh.config(state=tk.DISABLED, text="Scanning...")
        
        # Run in thread to not freeze UI
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        display_list = []
        
        for ip in NATIONAL_IP_RANGE:
            status = "Available"
            
            # Check if it's me (simple check)
            # Note: This is tricky if we have multiple interfaces, but we try to connect anyway.
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15) # Fast timeout
                result = s.connect_ex((ip, APP_PORT))
                
                if result == 0:
                    # Connection successful, try to read hostname
                    try:
                        remote_hostname = s.recv(1024).decode('utf-8').strip()
                        status = f"Used by: {remote_hostname}"
                    except:
                        status = "Used (Unknown)"
                    s.close()
                else:
                    s.close()
            except:
                pass
            
            display_list.append(f"{ip}   [{status}]")

        # Update UI in main thread
        self.root.after(0, lambda: self._update_combo(display_list))

    def _update_combo(self, values):
        self.ip_combo['values'] = values
        if values:
            self.ip_combo.current(0)
        self.btn_refresh.config(state=tk.NORMAL, text="↻ Scan IPs")
        self.log("Scan complete.")

    # --- Existing Logic ---
    def get_wifi_ssid(self):
        try:
            if self.os_type == "Windows":
                output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                match = re.search(r"^\s*SSID\s*:\s*(.*)$", output, re.MULTILINE)
                if match: return match.group(1).strip()
            elif self.os_type == "Linux":
                try:
                    output = subprocess.check_output("iwgetid -r", shell=True).decode('utf-8').strip()
                    if output: return output
                except: pass
                try:
                    output = subprocess.check_output("nmcli -t -f active,ssid dev wifi | grep '^yes'", shell=True).decode('utf-8')
                    return output.split(':')[1].strip()
                except: pass
            elif self.os_type == "Darwin":
                cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I"
                output = subprocess.check_output(cmd, shell=True).decode('utf-8')
                match = re.search(r" SSID:\s*(.*)", output)
                if match: return match.group(1).strip()
        except: pass
        return None

    def check_connection(self):
        ssid = self.get_wifi_ssid()
        self.current_connected_ssid = ssid
        
        if ssid:
            self.ssid_label.config(text=f"Current WiFi: {ssid}")
            if ssid in TARGET_SSIDS:
                self.status_label.config(text="Target Network Connected", fg="green")
                self.btn_national.config(state=tk.NORMAL, bg="#d1e7dd")
                self.btn_internet.config(state=tk.NORMAL, bg="#d1e7dd")
            else:
                self.status_label.config(text=f"Incorrect Network. Please connect to:\n{TARGET_SSIDS[0]} or {TARGET_SSIDS[1]}", fg="red")
                self.btn_national.config(state=tk.DISABLED, bg="#e1e1e1")
                self.btn_internet.config(state=tk.DISABLED, bg="#e1e1e1")
        else:
            self.ssid_label.config(text="WiFi: Not Connected")
            self.status_label.config(text="Please connect to WiFi", fg="red")
            self.btn_national.config(state=tk.DISABLED, bg="#e1e1e1")
            self.btn_internet.config(state=tk.DISABLED, bg="#e1e1e1")
        self.root.after(3000, self.check_connection)

    def set_national(self):
        selection = self.ip_combo.get()
        if not selection:
            messagebox.showerror("Error", "Please select an IP address.")
            return
        
        # Extract IP from string "192.168.80.5   [Available]"
        selected_ip = selection.split()[0]
        
        # Check if user selected a used IP
        if "Used by" in selection:
            if not messagebox.askyesno("Warning", f"This IP seems to be in use.\n{selection}\n\nDo you still want to force apply it?"):
                return

        config = CONFIG_NATIONAL_BASE.copy()
        config["ip"] = selected_ip
        self.apply_settings(config, f"National Net ({selected_ip})")

    def set_internet(self):
        self.apply_settings(CONFIG_INTERNET, "Normal Internet")

    def apply_settings(self, config, name):
        if not is_admin():
            messagebox.showerror("Error", "Lost admin privileges.")
            return

        self.log(f"Applying settings for {name}...")
        try:
            if self.os_type == "Windows":
                self.apply_windows(config)
            elif self.os_type == "Linux":
                self.apply_linux(config)
            elif self.os_type == "Darwin":
                self.apply_mac(config)
            
            self.log(f"Successfully applied {name} settings.")
            messagebox.showinfo("Success", f"Network configured for {name}.")
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed: {e}")
            messagebox.showerror("Error", f"Failed to apply settings.\n{e}")
        except Exception as e:
            self.log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def apply_windows(self, config):
        if_name = "Wi-Fi" 
        if config["dhcp"]:
            self.run_cmd(f'netsh interface ip set address "{if_name}" dhcp')
        else:
            self.run_cmd(f'netsh interface ip set address "{if_name}" static {config["ip"]} {config["subnet"]} {config["gateway"]}')
        
        if config.get("dns"):
            dns_list = config["dns"].split()
            self.run_cmd(f'netsh interface ip set dns "{if_name}" static {dns_list[0]}')
            for i, dns in enumerate(dns_list[1:], start=2):
                self.run_cmd(f'netsh interface ip add dns "{if_name}" {dns} index={i}')
        else:
            self.run_cmd(f'netsh interface ip set dns "{if_name}" dhcp')

    def apply_linux(self, config):
        # Use the current connected SSID as the connection name
        # This is more robust than hardcoding TARGET_SSID
        conn_name = self.current_connected_ssid if self.current_connected_ssid else TARGET_SSIDS[0]

        if config["dhcp"]:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.method auto')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.gateway ""')
        else:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.method manual ipv4.addresses {config["ip"]}/24 ipv4.gateway {config["gateway"]}')
        
        if config.get("dns"):
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.ignore-auto-dns yes')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.dns "{config["dns"]}"')
        else:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.ignore-auto-dns no')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.dns ""')
        self.run_cmd(f'nmcli con up "{conn_name}"')

    def apply_mac(self, config):
        service = "Wi-Fi"
        if config["dhcp"]:
            self.run_cmd(f'networksetup -setdhcp "{service}"')
        else:
            self.run_cmd(f'networksetup -setmanual "{service}" {config["ip"]} {config["subnet"]} {config["gateway"]}')

        if config.get("dns"):
            self.run_cmd(f'networksetup -setdnsservers "{service}" {config["dns"]}')
        else:
            self.run_cmd(f'networksetup -setdnsservers "{service}" "Empty"')

    def run_cmd(self, cmd):
        self.log(f"Exec: {cmd}")
        subprocess.check_call(cmd, shell=True)

if __name__ == "__main__":
    if not is_admin():
        try:
            elevate_privileges()
        except Exception as e:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Admin Required", f"This application requires Administrator privileges.\n\nError: {e}")
            sys.exit(1)
    else:
        root = tk.Tk()
        app = NetworkManagerApp(root)
        root.mainloop()
