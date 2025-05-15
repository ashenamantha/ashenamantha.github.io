#!/usr/bin/env python3
# Port Scanner GUI Tool
# Compatible with Windows and Linux

import nmap
import ipaddress
import re
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import time
import datetime
import sys
import os

# Global variables
scan_running = False
port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Port Scanner Tool")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # Set user information
        self.username = "ashenamantha"
        self.timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        # Store scan results
        self.scan_results = []
        
        # Set color scheme
        self.primary_color = "#3f51b5"  # Indigo
        self.secondary_color = "#303f9f" # Darker Indigo
        self.accent_color = "#ff4081"    # Pink
        self.light_bg = "#f5f5f5"        # Almost white
        self.dark_text = "#212121"       # Almost black
        self.light_text = "#ffffff"      # White
        self.success_color = "#4caf50"   # Green
        self.warning_color = "#ff9800"   # Orange
        self.error_color = "#f44336"     # Red
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background=self.light_bg)
        self.style.configure('TLabel', background=self.light_bg, foreground=self.dark_text)
        self.style.configure('TButton', font=('Helvetica', 10, 'bold'))
        self.style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        self.style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))
        
        # Set application icon if available
        try:
            # For Windows
            self.root.iconbitmap('scanner_icon.ico')
        except:
            # Icon not found or not on Windows, ignore
            pass
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Header Frame
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # App Logo
        logo_label = ttk.Label(header_frame, text="🔎", font=("Arial", 24))
        logo_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # App Title
        title_label = ttk.Label(header_frame, text="Port Scanner Tool", style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        # User info frame
        user_frame = ttk.Frame(header_frame)
        user_frame.pack(side=tk.RIGHT)
        
        user_label = ttk.Label(user_frame, text=f"User: {self.username}")
        user_label.pack(anchor=tk.E)
        
        time_label = ttk.Label(user_frame, text=f"Session: {self.timestamp}")
        time_label.pack(anchor=tk.E)
        
        # Target Input Frame
        input_frame = ttk.LabelFrame(main_container, text="Target Configuration")
        input_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # IP Address input
        ip_frame = ttk.Frame(input_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").pack(side=tk.LEFT)
        
        self.ip_var = tk.StringVar()
        ip_entry = ttk.Entry(ip_frame, textvariable=self.ip_var, width=20)
        ip_entry.pack(side=tk.LEFT, padx=5)
        
        # Quick IP buttons
        quick_ip_frame = ttk.Frame(ip_frame)
        quick_ip_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(quick_ip_frame, text="Localhost", 
                  command=lambda: self.ip_var.set("127.0.0.1")).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_ip_frame, text="Validate IP", 
                  command=self.validate_ip).pack(side=tk.LEFT, padx=2)
        
        # Port Range input
        port_frame = ttk.Frame(input_frame)
        port_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(port_frame, text="Port Range:").pack(side=tk.LEFT)
        
        self.port_var = tk.StringVar(value="1-1024")
        port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=15)
        port_entry.pack(side=tk.LEFT, padx=5)
        
        # Quick port range buttons
        quick_port_frame = ttk.Frame(port_frame)
        quick_port_frame.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(quick_port_frame, text="Common (1-1024)", 
                  command=lambda: self.port_var.set("1-1024")).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_port_frame, text="All (1-65535)", 
                  command=lambda: self.port_var.set("1-65535")).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_port_frame, text="Custom", 
                  command=self.custom_port_range).pack(side=tk.LEFT, padx=2)
        
        # Scan options
        options_frame = ttk.Frame(input_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Scan type selection
        scan_type_frame = ttk.Frame(options_frame)
        scan_type_frame.pack(side=tk.LEFT)
        
        ttk.Label(scan_type_frame, text="Scan Type:").pack(side=tk.LEFT)
        
        self.scan_type = tk.StringVar(value="Basic")
        scan_type_combobox = ttk.Combobox(scan_type_frame, 
                                        textvariable=self.scan_type,
                                        values=["Basic", "Version Detection", "Service Info", "OS Detection"],
                                        width=15,
                                        state="readonly")
        scan_type_combobox.pack(side=tk.LEFT, padx=5)
        
        # Timeout setting
        timeout_frame = ttk.Frame(options_frame)
        timeout_frame.pack(side=tk.LEFT, padx=20)
        
        ttk.Label(timeout_frame, text="Timeout (sec):").pack(side=tk.LEFT)
        
        self.timeout_var = tk.IntVar(value=5)
        timeout_spinbox = ttk.Spinbox(timeout_frame, 
                                    from_=1, to=30, 
                                    textvariable=self.timeout_var,
                                    width=5)
        timeout_spinbox.pack(side=tk.LEFT, padx=5)
        
        # Controls Frame
        controls_frame = ttk.Frame(main_container)
        controls_frame.pack(fill=tk.X, padx=5, pady=10)
        
        # Scan button
        self.scan_button = ttk.Button(controls_frame, 
                                    text="Start Scan", 
                                    command=self.start_scan,
                                    style="TButton")
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Stop button
        self.stop_button = ttk.Button(controls_frame, 
                                    text="Stop Scan", 
                                    command=self.stop_scan,
                                    state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_button = ttk.Button(controls_frame, 
                                 text="Clear Results", 
                                 command=self.clear_results)
        clear_button.pack(side=tk.LEFT, padx=5)
        
        # Save button
        save_button = ttk.Button(controls_frame, 
                                text="Save Results", 
                                command=self.save_results)
        save_button.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = ttk.Frame(main_container)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                          variable=self.progress_var, 
                                          orient=tk.HORIZONTAL)
        self.progress_bar.pack(fill=tk.X, padx=5)
        
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        status_label.pack(fill=tk.X, padx=5, pady=2)
        
        # Results Frame
        results_frame = ttk.LabelFrame(main_container, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Results Treeview
        columns = ("port", "state", "service", "version")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Define headings
        self.results_tree.heading("port", text="Port")
        self.results_tree.heading("state", text="State")
        self.results_tree.heading("service", text="Service")
        self.results_tree.heading("version", text="Version")
        
        # Define columns
        self.results_tree.column("port", width=80)
        self.results_tree.column("state", width=80)
        self.results_tree.column("service", width=120)
        self.results_tree.column("version", width=400)
        
        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=tree_scroll_y.set)
        
        # Pack the Treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Summary Frame
        summary_frame = ttk.LabelFrame(main_container, text="Scan Summary")
        summary_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, height=4, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.X, expand=True, padx=5, pady=5)
        self.summary_text.insert(tk.END, "Port scan summary will appear here after scanning.")
        self.summary_text.config(state=tk.DISABLED)
        
        # Status bar
        self.statusbar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create menu bar
        self.create_menu()
    
    def create_menu(self):
        # Create the menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Create File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Create Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Utilities", command=self.show_network_utils)
        tools_menu.add_command(label="Host Lookup", command=self.host_lookup)
        
        # Create Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
    
    def validate_ip(self):
        """Validate the IP address and show a message"""
        ip = self.ip_var.get().strip()
        try:
            ipaddress.ip_address(ip)
            messagebox.showinfo("IP Validation", f"'{ip}' is a valid IP address.")
            return True
        except ValueError:
            messagebox.showerror("IP Validation", f"'{ip}' is not a valid IP address.")
            return False
    
    def custom_port_range(self):
        """Open a dialog to enter a custom port range"""
        custom_range = tk.simpledialog.askstring("Custom Port Range", 
                                             "Enter port range (e.g., 1-1024):",
                                             initialvalue=self.port_var.get())
        if custom_range:
            # Validate port range format
            if port_range_pattern.match(custom_range.replace(" ","")):
                self.port_var.set(custom_range)
            else:
                messagebox.showerror("Invalid Format", 
                                  "Port range must be in format: <int>-<int> (e.g., 1-1024)")
    
    def start_scan(self):
        """Start the port scanning process"""
        global scan_running
        
        # Validate IP first
        if not self.validate_ip():
            return
        
        # Get port range
        port_range = self.port_var.get().strip().replace(" ","")
        port_range_match = port_range_pattern.search(port_range)
        
        if not port_range_match:
            messagebox.showerror("Error", "Invalid port range format! Use format: <int>-<int> (e.g., 1-1024)")
            return
        
        # Extract port range
        port_min = int(port_range_match.group(1))
        port_max = int(port_range_match.group(2))
        
        # Validate port range values
        if port_min < 1 or port_max > 65535 or port_min > port_max:
            messagebox.showerror("Error", "Invalid port range! Ports must be between 1-65535 and min must be <= max.")
            return
        
        # Check if range is too large
        if port_max - port_min > 1000:
            if not messagebox.askyesno("Warning", 
                                    f"You are about to scan {port_max - port_min + 1} ports, which may take a long time. Continue?"):
                return
        
        # Clear previous results
        self.clear_results()
        
        # Update status
        self.status_var.set("Starting scan...")
        self.statusbar.config(text=f"Scanning {self.ip_var.get()}:{port_min}-{port_max}")
        
        # Update UI state
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Set flag that scan is running
        scan_running = True
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.run_scan_thread, 
                                    args=(self.ip_var.get(), port_min, port_max))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan_thread(self, ip_address, port_min, port_max):
        """Run the scan in a separate thread"""
        global scan_running
        
        # Initialize variables
        self.scan_results = []
        total_ports = port_max - port_min + 1
        scanned_ports = 0
        open_ports = 0
        start_time = time.time()
        
        # Create scanner
        nm = nmap.PortScanner()
        
        # Determine scan arguments based on scan type
        scan_args = '-T4'  # Default: T4 timing (faster than default)
        
        if self.scan_type.get() == "Version Detection":
            scan_args += ' -sV'
        elif self.scan_type.get() == "Service Info":
            scan_args += ' -sV --version-all'
        elif self.scan_type.get() == "OS Detection":
            scan_args += ' -sV -O'  # OS detection requires root/admin privileges
        
        try:
            # Loop over the ports
            for port in range(port_min, port_max + 1):
                if not scan_running:
                    # Scan was stopped
                    break
                
                try:
                    # Update status
                    self.status_var.set(f"Scanning port {port}/{port_max}...")
                    self.progress_var.set((scanned_ports / total_ports) * 100)
                    
                    # Scan the port
                    result = nm.scan(ip_address, str(port), arguments=scan_args, timeout=self.timeout_var.get())
                    
                    # Process the result if host was scanned
                    if ip_address in result['scan']:
                        if 'tcp' in result['scan'][ip_address] and port in result['scan'][ip_address]['tcp']:
                            port_data = result['scan'][ip_address]['tcp'][port]
                            port_state = port_data['state']
                            
                            # Get service and version
                            service = port_data.get('name', '')
                            version = port_data.get('product', '')
                            if 'version' in port_data:
                                version += f" {port_data['version']}"
                            if 'extrainfo' in port_data and port_data['extrainfo']:
                                version += f" ({port_data['extrainfo']})"
                            
                            # Add to results list
                            port_info = {
                                'port': port,
                                'state': port_state,
                                'service': service,
                                'version': version
                            }
                            self.scan_results.append(port_info)
                            
                            # Update UI with result
                            self.root.after(0, self.add_result_to_tree, port_info)
                            
                            if port_state == 'open':
                                open_ports += 1
                except Exception as e:
                    print(f"Error scanning port {port}: {str(e)}")
                
                scanned_ports += 1
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            
            # Update UI with summary
            summary = (
                f"Scan completed in {elapsed_time:.2f} seconds\n"
                f"Scanned {scanned_ports} ports on {ip_address}\n"
                f"Found {open_ports} open ports\n"
                f"Scan type: {self.scan_type.get()}"
            )
            self.root.after(0, self.update_summary, summary)
            
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            self.root.after(0, self.show_error, error_msg)
        
        # Reset UI state
        self.root.after(0, self.finish_scan)
    
    def add_result_to_tree(self, port_info):
        """Add a port result to the treeview"""
        # Insert into the treeview
        item_id = self.results_tree.insert('', 'end', values=(
            port_info['port'],
            port_info['state'],
            port_info['service'],
            port_info['version']
        ))
        
        # Color code based on state
        if port_info['state'] == 'open':
            self.results_tree.item(item_id, tags=('open',))
        elif port_info['state'] == 'closed':
            self.results_tree.item(item_id, tags=('closed',))
        else:
            self.results_tree.item(item_id, tags=('filtered',))
        
        # Configure tags
        self.results_tree.tag_configure('open', background='#c8e6c9')  # Light green
        self.results_tree.tag_configure('closed', background='#ffcdd2')  # Light red
        self.results_tree.tag_configure('filtered', background='#fff9c4')  # Light yellow
    
    def update_summary(self, summary):
        """Update the summary text widget"""
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)
    
    def show_error(self, message):
        """Show an error message"""
        messagebox.showerror("Error", message)
        self.statusbar.config(text=f"Error: {message}")
    
    def finish_scan(self):
        """Reset UI after scan completes"""
        global scan_running
        scan_running = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
        self.status_var.set("Scan completed")
        self.statusbar.config(text="Ready")
    
    def stop_scan(self):
        """Stop the running scan"""
        global scan_running
        scan_running = False
        self.status_var.set("Scan stopped by user")
        self.statusbar.config(text="Scan stopped by user")
    
    def clear_results(self):
        """Clear all scan results"""
        # Clear treeview
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Clear summary
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, "Port scan summary will appear here after scanning.")
        self.summary_text.config(state=tk.DISABLED)
        
        # Reset progress
        self.progress_var.set(0)
        self.status_var.set("Ready to scan")
        self.statusbar.config(text="Ready")
        
        # Clear scan results
        self.scan_results = []
    
    def save_results(self):
        """Save scan results to a file"""
        if not self.scan_results:
            messagebox.showinfo("Info", "No scan results to save.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w') as f:
                # Write header
                f.write(f"Port Scan Results\n")
                f.write(f"Target: {self.ip_var.get()}\n")
                f.write(f"Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"User: {self.username}\n")
                f.write("=" * 60 + "\n\n")
                
                # Write summary from summary text widget
                f.write("SUMMARY:\n")
                f.write(self.summary_text.get(1.0, tk.END))
                f.write("\n" + "=" * 60 + "\n\n")
                
                # Write table header
                f.write(f"{'PORT':<10}{'STATE':<15}{'SERVICE':<20}{'VERSION'}\n")
                f.write("-" * 80 + "\n")
                
                # Write results
                for result in self.scan_results:
                    f.write(f"{result['port']:<10}{result['state']:<15}{result['service']:<20}{result['version']}\n")
            
            messagebox.showinfo("Success", f"Results saved to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")
    
    def show_network_utils(self):
        """Show network utilities dialog"""
        utils_window = tk.Toplevel(self.root)
        utils_window.title("Network Utilities")
        utils_window.geometry("500x300")
        utils_window.resizable(False, False)
        
        # Network utilities content
        ttk.Label(utils_window, text="Network Utilities", font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Create a frame for the utilities
        utils_frame = ttk.Frame(utils_window)
        utils_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Ping utility
        ping_frame = ttk.LabelFrame(utils_frame, text="Ping Host")
        ping_frame.pack(fill=tk.X, pady=5)
        
        ping_host_var = tk.StringVar(value=self.ip_var.get())
        ttk.Entry(ping_frame, textvariable=ping_host_var, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(ping_frame, text="Ping", 
                  command=lambda: self.ping_host(ping_host_var.get())).pack(side=tk.LEFT, padx=5, pady=5)
        
        # DNS Lookup utility
        dns_frame = ttk.LabelFrame(utils_frame, text="DNS Lookup")
        dns_frame.pack(fill=tk.X, pady=5)
        
        dns_host_var = tk.StringVar()
        ttk.Entry(dns_frame, textvariable=dns_host_var, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(dns_frame, text="Lookup", 
                  command=lambda: self.dns_lookup(dns_host_var.get())).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Whois utility
        whois_frame = ttk.LabelFrame(utils_frame, text="Whois Lookup")
        whois_frame.pack(fill=tk.X, pady=5)
        
        whois_host_var = tk.StringVar()
        ttk.Entry(whois_frame, textvariable=whois_host_var, width=30).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(whois_frame, text="Whois", 
                  command=lambda: self.whois_lookup(whois_host_var.get())).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Close button
        ttk.Button(utils_window, text="Close", command=utils_window.destroy).pack(pady=10)
    
    def ping_host(self, host):
        """Ping a host and show results"""
        # This is a simplified version; in a real app, you'd use subprocess to run the ping command
        try:
            import platform
            import subprocess
            
            # Determine the ping command based on the OS
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "4", host]
            else:  # Linux/Mac
                command = ["ping", "-c", "4", host]
            
            # Run the ping command
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Show results in a new window
            result_window = tk.Toplevel(self.root)
            result_window.title(f"Ping Results: {host}")
            result_window.geometry("500x400")
            
            # Add a text area for the results
            result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
            result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Insert the results
            result_text.insert(tk.END, result.stdout if result.returncode == 0 else 
                            f"Error: {result.stderr}\n\n{result.stdout}")
            result_text.config(state=tk.DISABLED)
            
            # Close button
            ttk.Button(result_window, text="Close", 
                     command=result_window.destroy).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to ping host: {str(e)}")
    
    def dns_lookup(self, host):
        """Perform a DNS lookup"""
        try:
            import socket
            result = socket.gethostbyname_ex(host)
            
            messagebox.showinfo("DNS Lookup Result", 
                             f"Host: {result[0]}\nAliases: {', '.join(result[1]) or 'None'}\n"
                             f"IP Addresses: {', '.join(result[2])}")
            
        except Exception as e:
            messagebox.showerror("Error", f"DNS lookup failed: {str(e)}")
    
    def whois_lookup(self, host):
        """Perform a whois lookup (requires python-whois package)"""
        # In a real implementation, you would use the python-whois package
        # For this example, we'll just show a message
        messagebox.showinfo("Whois Lookup", 
                         f"Whois lookup for {host} would be displayed here.\n\n"
                         f"To implement this feature, install the 'python-whois' package:\n"
                         f"pip install python-whois")
    
    def host_lookup(self):
        """Show host lookup dialog"""
        host = tk.simpledialog.askstring("Host Lookup", 
                                      "Enter hostname or IP address:",
                                      initialvalue=self.ip_var.get())
        if not host:
            return
            
        try:
            import socket
            ip = socket.gethostbyname(host)
            if ip != host:  # If hostname was entered
                hostname = socket.getfqdn(ip)
                messagebox.showinfo("Host Lookup Result", 
                                 f"Hostname: {hostname}\nIP Address: {ip}")
            else:  # If IP was entered
                hostname = socket.getfqdn(ip)
                messagebox.showinfo("Host Lookup Result", 
                                 f"IP Address: {ip}\nHostname: {hostname}")
        except Exception as e:
            messagebox.showerror("Error", f"Host lookup failed: {str(e)}")
    
    def show_about(self):
        """Show about dialog with application information"""
        about_text = f"""Port Scanner Tool v1.0

A graphical user interface for port scanning using the Nmap library.

Created by: {self.username}
Session: {self.timestamp}

For educational and legitimate network testing purposes only.
Unauthorized port scanning may be illegal in some jurisdictions.
Always scan only networks you own or have explicit permission to scan.
"""
        messagebox.showinfo("About Port Scanner Tool", about_text)
    
    def show_docs(self):
        """Show documentation for the application"""
        docs_window = tk.Toplevel(self.root)
        docs_window.title("Port Scanner Documentation")
        docs_window.geometry("600x500")
        
        # Create a notebook for tabbed documentation
        notebook = ttk.Notebook(docs_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Usage tab
        usage_frame = ttk.Frame(notebook)
        notebook.add(usage_frame, text="Usage")
        
        usage_text = scrolledtext.ScrolledText(usage_frame, wrap=tk.WORD)
        usage_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        usage_content = """# Port Scanner Tool Usage Guide

1. **Basic Scanning**:
   - Enter an IP address in the "IP Address" field
   - Choose a port range (e.g., 1-1024 for common ports)
   - Click "Start Scan" to begin

2. **Scan Types**:
   - Basic: Fast scan that only checks if ports are open
   - Version Detection: Attempts to determine service versions
   - Service Info: More detailed service information
   - OS Detection: Attempts to detect operating system (requires admin/root)

3. **Viewing Results**:
   - Results appear in the table as they're discovered
   - Green rows indicate open ports
   - Red rows indicate closed ports
   - Yellow rows indicate filtered ports

4. **Saving Results**:
   - Click "Save Results" to save scan data to a text file
   - Results include summary and detailed port information
"""
        usage_text.insert(tk.END, usage_content)
        usage_text.config(state=tk.DISABLED)
        
        # Installation tab
        install_frame = ttk.Frame(notebook)
        notebook.add(install_frame, text="Installation")
        
        install_text = scrolledtext.ScrolledText(install_frame, wrap=tk.WORD)
        install_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        install_content = """# Installation Guide

## Windows Installation:

1. **Install Python**:
   - Download and install Python from python.org
   - Ensure you check "Add Python to PATH" during installation

2. **Install Nmap**:
   - Download and install Nmap from nmap.org
   - Add Nmap to your system PATH

3. **Install Python Requirements**:
   - Open Command Prompt as Administrator
   - Run: `pip install python-nmap`

4. **Run the Application**:
   - Double-click the port_scanner_gui.py file
   - Or run from command line: `python port_scanner_gui.py`

## Linux Installation:

1. **Install Python and Nmap**:
   - Run: `sudo apt install python3 python3-pip nmap`

2. **Install Python Requirements**:
   - Run: `pip3 install python-nmap`

3. **Run the Application**:
   - Run: `python3 port_scanner_gui.py`
"""
        install_text.insert(tk.END, install_content)
        install_text.config(state=tk.DISABLED)
        
        # Legal tab
        legal_frame = ttk.Frame(notebook)
        notebook.add(legal_frame, text="Legal")
        
        legal_text = scrolledtext.ScrolledText(legal_frame, wrap=tk.WORD)
        legal_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        legal_content = """# Legal and Ethical Considerations

## Important Notice:

Port scanning can be considered an intrusive activity and may be illegal in some jurisdictions if performed without explicit permission from the network owner.

## Legal Usage:

This tool should ONLY be used:
- On your own networks
- On networks you have explicit permission to test
- For educational purposes in controlled environments

## Prohibited Usage:

Do NOT use this tool to:
- Scan networks without permission
- Conduct unauthorized security assessments
- Attempt to gain unauthorized access
- Disrupt network services

## Disclaimer:

The creator of this tool accepts no liability for misuse or any damages resulting from the use of this software. Users bear full responsibility for ensuring their activities comply with all applicable laws and regulations.
"""
        legal_text.insert(tk.END, legal_content)
        legal_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(docs_window, text="Close", command=docs_window.destroy).pack(pady=10)

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()