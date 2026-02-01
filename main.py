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

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_SSID = "Group Lancing - Employe 5G"

# Configuration for "National Internet" (Net Melli)
CONFIG_NATIONAL_BASE = {
    "dhcp": False,
    "subnet": "255.255.255.0",
    "gateway": "192.168.80.2",
    "dns": "1.1.1.1 8.8.8.8"    # Cloudflare & Google DNS
}

# Range of IPs to check for National Internet
NATIONAL_IP_RANGE = [f"192.168.80.{i}" for i in range(5, 10)] # 5, 6, 7, 8, 9

# Configuration for "Normal Internet" (No Iranian Sites)
CONFIG_INTERNET = {
    "dhcp": True,               # Set to False if you need static IP
    "ip": "192.168.1.51",
    "subnet": "255.255.255.0",
    "gateway": "192.168.1.2",   # Gateway for Normal Internet
    "dns": "1.1.1.1 1.0.0.1"    # Cloudflare DNS (Primary & Secondary)
}

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        current_os = platform.system()
        if current_os == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Linux/macOS
            return os.geteuid() == 0
    except:
        return False

def elevate_privileges():
    """Attempt to re-run the script with administrative privileges."""
    current_os = platform.system()
    if current_os == "Windows":
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
        self.root.geometry("500x500")
        
        self.os_type = platform.system()
        
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
        self.btn_frame.pack(pady=10)

        # --- National Internet Section ---
        self.national_frame = tk.LabelFrame(self.btn_frame, text="National Internet (Net Melli)", padx=10, pady=10, font=("Segoe UI", 10, "bold"))
        self.national_frame.pack(pady=5, fill="x", padx=10)
        
        tk.Label(self.national_frame, text="Select IP Address:").pack(anchor="w")
        
        self.ip_combo = ttk.Combobox(self.national_frame, values=NATIONAL_IP_RANGE, state="readonly", font=("Consolas", 10))
        if NATIONAL_IP_RANGE:
            self.ip_combo.current(0)
        self.ip_combo.pack(fill="x", pady=5)

        self.btn_national = tk.Button(self.national_frame, text="Apply National IP", 
                                      command=self.set_national, state=tk.DISABLED, 
                                      bg="#e1e1e1", height=2)
        self.btn_national.pack(fill="x", pady=5)

        # --- Normal Internet Section ---
        self.internet_frame = tk.LabelFrame(self.btn_frame, text="Normal Internet", padx=10, pady=10, font=("Segoe UI", 10, "bold"))
        self.internet_frame.pack(pady=10, fill="x", padx=10)

        self.btn_internet = tk.Button(self.internet_frame, text="Connect to Normal Internet\n(No Iran Sites)", 
                                      command=self.set_internet, state=tk.DISABLED, 
                                      bg="#e1e1e1", height=2)
        self.btn_internet.pack(fill="x", pady=5)
        
        self.log_text = tk.Text(root, height=8, width=60, font=("Consolas", 9))
        self.log_text.pack(pady=10, padx=10)

        self.log(f"OS Detected: {self.os_type}")
        self.log("Running with Administrator Privileges.")
        
        # Start monitoring
        self.check_connection()

    def log(self, message):
        self.log_text.insert(tk.END, f"> {message}\n")
        self.log_text.see(tk.END)
        self.root.update()

    def get_wifi_ssid(self):
        try:
            if self.os_type == "Windows":
                output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode('utf-8', errors='ignore')
                match = re.search(r"^\s*SSID\s*:\s*(.*)$", output, re.MULTILINE)
                if match:
                    return match.group(1).strip()
                
            elif self.os_type == "Linux":
                try:
                    output = subprocess.check_output("iwgetid -r", shell=True).decode('utf-8').strip()
                    if output: return output
                except:
                    pass
                try:
                    output = subprocess.check_output("nmcli -t -f active,ssid dev wifi | grep '^yes'", shell=True).decode('utf-8')
                    return output.split(':')[1].strip()
                except:
                    pass

            elif self.os_type == "Darwin":
                cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I"
                output = subprocess.check_output(cmd, shell=True).decode('utf-8')
                match = re.search(r" SSID:\s*(.*)", output)
                if match:
                    return match.group(1).strip()
                    
        except Exception as e:
            pass
        return None

    def check_connection(self):
        ssid = self.get_wifi_ssid()
        
        if ssid:
            self.ssid_label.config(text=f"Current WiFi: {ssid}")
            if ssid == TARGET_SSID:
                self.status_label.config(text="Target Network Connected", fg="green")
                self.btn_national.config(state=tk.NORMAL, bg="#d1e7dd")
                self.btn_internet.config(state=tk.NORMAL, bg="#d1e7dd")
            else:
                self.status_label.config(text=f"Incorrect Network. Please connect to:\n{TARGET_SSID}", fg="red")
                self.btn_national.config(state=tk.DISABLED, bg="#e1e1e1")
                self.btn_internet.config(state=tk.DISABLED, bg="#e1e1e1")
        else:
            self.ssid_label.config(text="WiFi: Not Connected")
            self.status_label.config(text="Please connect to WiFi", fg="red")
            self.btn_national.config(state=tk.DISABLED, bg="#e1e1e1")
            self.btn_internet.config(state=tk.DISABLED, bg="#e1e1e1")
        
        self.root.after(3000, self.check_connection)

    def set_national(self):
        selected_ip = self.ip_combo.get()
        if not selected_ip:
            messagebox.showerror("Error", "Please select an IP address.")
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
        
        # IP Settings
        if config["dhcp"]:
            self.run_cmd(f'netsh interface ip set address "{if_name}" dhcp')
        else:
            self.run_cmd(f'netsh interface ip set address "{if_name}" static {config["ip"]} {config["subnet"]} {config["gateway"]}')
            
        # DNS Settings
        if config.get("dns"):
            dns_list = config["dns"].split()
            # Primary
            self.run_cmd(f'netsh interface ip set dns "{if_name}" static {dns_list[0]}')
            # Secondary
            for i, dns in enumerate(dns_list[1:], start=2):
                self.run_cmd(f'netsh interface ip add dns "{if_name}" {dns} index={i}')
        else:
            self.run_cmd(f'netsh interface ip set dns "{if_name}" dhcp')

    def apply_linux(self, config):
        conn_name = TARGET_SSID
        
        # IP Settings
        if config["dhcp"]:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.method auto')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.gateway ""')
        else:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.method manual ipv4.addresses {config["ip"]}/24 ipv4.gateway {config["gateway"]}')
            
        # DNS Settings
        if config.get("dns"):
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.ignore-auto-dns yes')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.dns "{config["dns"]}"')
        else:
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.ignore-auto-dns no')
            self.run_cmd(f'nmcli con mod "{conn_name}" ipv4.dns ""')
            
        self.run_cmd(f'nmcli con up "{conn_name}"')

    def apply_mac(self, config):
        service = "Wi-Fi"
        
        # IP Settings
        if config["dhcp"]:
            self.run_cmd(f'networksetup -setdhcp "{service}"')
        else:
            self.run_cmd(f'networksetup -setmanual "{service}" {config["ip"]} {config["subnet"]} {config["gateway"]}')
            
        # DNS Settings
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
