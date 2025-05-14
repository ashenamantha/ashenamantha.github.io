import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu, filedialog
import threading
import time
import socket
import struct
import textwrap
from datetime import datetime
import ipaddress
import sys
import os
import json
import csv

class PacketAnalyzer:
    def __init__(self, root):
        # User info - updated with latest timestamp
        self.username = "ashenamantha"
        self.timestamp = "2025-05-14 09:41:00"
        
        # Application state
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)
        
        # Variables
        self.is_running = False
        self.captured_packets = []
        self.selected_interface = tk.StringVar()
        self.packet_filter = tk.StringVar(value="all")
        self.max_packets = tk.IntVar(value=100)
        self.show_payload = tk.BooleanVar(value=True)
        self.connections = {}
        self.packet_count = 0
        self.start_time = None
        
        # Define colors
        self.primary_color = "#3f51b5"  # Indigo
        self.secondary_color = "#303f9f"  # Dark Indigo
        self.accent_color = "#ff4081"    # Pink
        self.bg_color = "#f5f5f5"        # Light gray
        self.text_color = "#212121"      # Dark gray
        self.success_color = "#4caf50"   # Green
        self.warning_color = "#ff9800"   # Orange
        self.error_color = "#f44336"     # Red
        
        # Protocol color mapping for visual identification
        self.protocol_colors = {
            'TCP': '#2196F3',   # Blue
            'UDP': '#4CAF50',   # Green
            'ICMP': '#FFC107',  # Amber
            'HTTP': '#9C27B0',  # Purple
            'HTTPS': '#673AB7', # Deep Purple
            'DNS': '#FF9800',   # Orange
            'ARP': '#795548',   # Brown
            'DHCP': '#009688',  # Teal
            'OTHER': '#9E9E9E'  # Gray
        }
        
        # Create the interface
        self.create_ui()
        
        # Get available network interfaces
        self.get_available_interfaces()
        
        # Show ethical warning on startup
        self.show_ethical_warning()
    
    def create_ui(self):
        """Create the user interface"""
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TButton', background=self.primary_color, foreground='white', 
                        font=('Segoe UI', 9, 'bold'), borderwidth=1)
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.text_color,
                        font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('Status.TLabel', font=('Segoe UI', 9))
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header frame
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=10)
        
        title_label = ttk.Label(header_frame, text="Network Packet Analyzer", 
                               font=('Segoe UI', 18, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        # Control panel frame
        control_frame = ttk.LabelFrame(main_container, text="Capture Controls")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Network interface selection
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.selected_interface,
                                          state="readonly", width=30)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = ttk.Button(interface_frame, text="↻", width=3,
                               command=self.get_available_interfaces)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Filter and options
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Protocol filter
        protocols = ["all", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "ARP", "DHCP"]
        protocol_combo = ttk.Combobox(filter_frame, textvariable=self.packet_filter,
                                    values=protocols, state="readonly", width=10)
        protocol_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="Max Packets:").pack(side=tk.LEFT, padx=(15, 5))
        
        # Max packets entry
        max_packets_spin = ttk.Spinbox(filter_frame, from_=10, to=1000, increment=10,
                                     textvariable=self.max_packets, width=5)
        max_packets_spin.pack(side=tk.LEFT, padx=5)
        
        # Show payload checkbox
        payload_check = ttk.Checkbutton(filter_frame, text="Show Payload", 
                                      variable=self.show_payload)
        payload_check.pack(side=tk.LEFT, padx=(15, 5))
        
        # Start/Stop buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Capture", command=self.stop_capture,
                                 state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear_packets)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = ttk.Button(button_frame, text="Save Capture", command=self.save_capture)
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Packet list frame
        packet_list_frame = ttk.LabelFrame(main_container, text="Captured Packets")
        packet_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create treeview for packets
        columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(packet_list_frame, columns=columns, show='headings')
        
        # Set column headings and widths
        self.packet_tree.heading('No.', text='No.')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')
        self.packet_tree.heading('Info', text='Info')
        
        self.packet_tree.column('No.', width=50, anchor=tk.CENTER)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=150)
        self.packet_tree.column('Destination', width=150)
        self.packet_tree.column('Protocol', width=80, anchor=tk.CENTER)
        self.packet_tree.column('Length', width=80, anchor=tk.CENTER)
        self.packet_tree.column('Info', width=300)
        
        # Add scrollbars
        tree_scrolly = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, 
                                  command=self.packet_tree.yview)
        tree_scrollx = ttk.Scrollbar(packet_list_frame, orient=tk.HORIZONTAL, 
                                  command=self.packet_tree.xview)
        self.packet_tree.configure(yscroll=tree_scrolly.set, xscroll=tree_scrollx.set)
        
        # Pack the tree and scrollbars
        tree_scrolly.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scrollx.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind select event to show details
        self.packet_tree.bind('<<TreeviewSelect>>', self.show_packet_details)
        
        # Packet details frame
        details_frame = ttk.LabelFrame(main_container, text="Packet Details")
        details_frame.pack(fill=tk.X, pady=5)
        
        # Text widget for packet details
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10,
                                                   font=('Consolas', 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.details_text.config(state=tk.DISABLED)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create menu bar with Export/Import options
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Capture", command=self.save_capture)
        file_menu.add_command(label="Load Capture", command=self.load_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Export as CSV", command=self.export_as_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Ethical Guidelines", command=self.show_ethical_warning)
        
    def get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            if sys.platform == 'win32':
                # For Windows
                try:
                    import wmi
                    wmi_obj = wmi.WMI()
                    interfaces = [adapter.NetConnectionID for adapter in wmi_obj.Win32_NetworkAdapter() 
                                 if adapter.NetConnectionID]
                except:
                    # Fallback for Windows
                    from subprocess import check_output
                    interfaces_raw = check_output(['ipconfig']).decode('utf-8')
                    interfaces = [line.split(':')[0] for line in interfaces_raw.split('\n') 
                                 if 'Ethernet' in line or 'Wireless' in line]
            else:
                # For Linux/Mac
                import netifaces
                interfaces = netifaces.interfaces()
                
            # Update the dropdown
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.selected_interface.set(interfaces[0])
                self.status_bar.config(text=f"Found {len(interfaces)} network interfaces")
            else:
                self.status_bar.config(text="No network interfaces found")
                
        except Exception as e:
            self.status_bar.config(text=f"Error getting network interfaces: {str(e)}")
            messagebox.showerror("Error", f"Could not retrieve network interfaces: {str(e)}\n\n"
                               "This tool requires administrator/root privileges to access network interfaces.")
            self.interface_combo['values'] = ['lo', 'eth0', 'wlan0']  # Default fallback values
            self.selected_interface.set('lo')
    
    def start_capture(self):
        """Start packet capturing"""
        if not self.selected_interface.get():
            messagebox.showerror("Error", "Please select a network interface!")
            return
        
        # Check for privileges
        if os.name == 'posix' and os.geteuid() != 0:
            messagebox.showwarning("Warning", 
                               "This program may need root privileges to capture packets.\n"
                               "If no packets appear, please restart as root/administrator.")
        
        # Reset state
        self.clear_packets()
        
        # Update UI
        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_bar.config(text="Capturing packets...")
        self.start_time = time.time()
        
        # Start capture thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Start display update thread
        self.update_thread = threading.Thread(target=self.update_display)
        self.update_thread.daemon = True
        self.update_thread.start()
    
    def stop_capture(self):
        """Stop packet capturing"""
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_bar.config(text=f"Capture stopped. {len(self.captured_packets)} packets captured.")
    
    def clear_packets(self):
        """Clear all captured packets"""
        self.captured_packets = []
        self.packet_count = 0
        self.connections = {}
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete('1.0', tk.END)
        self.details_text.config(state=tk.DISABLED)
        self.status_bar.config(text="Packet list cleared")
    
    def capture_packets(self):
        """Capture packets in a separate thread"""
        try:
            # Create a raw socket
            if sys.platform == 'win32':  # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                interface = self.selected_interface.get()
                
                # Bind to the selected interface
                try:
                    # Try to get IP for the interface name
                    sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                except:
                    # Fallback to localhost if binding fails
                    sock.bind(('127.0.0.1', 0))
                
                # Enable promiscuous mode
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux/Mac
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                interface = self.selected_interface.get()
                try:
                    sock.bind((interface, 0))
                except:
                    # Fallback to any interface
                    sock.bind(('', 0))
            
            # Receive packets
            while self.is_running:
                if self.packet_count >= self.max_packets.get():
                    self.is_running = False
                    break
                
                # Set a timeout so we can check if capturing is still enabled
                sock.settimeout(1.0)
                
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    
                    # Process the packet
                    packet = self.process_packet(raw_data)
                    if packet:
                        self.captured_packets.append(packet)
                        self.packet_count += 1
                except socket.timeout:
                    pass
                except Exception as e:
                    print(f"Error capturing packet: {str(e)}")
            
            # Disable promiscuous mode when done
            if sys.platform == 'win32':
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
            sock.close()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error during packet capture: {str(e)}")
            self.is_running = False
            self.root.after(0, self.stop_capture)
    
    def process_packet(self, raw_data):
        """Process a captured packet and extract information"""
        try:
            # Get current time
            capture_time = time.time() - self.start_time
            
            # Start with basic info
            packet_info = {
                'time': f"{capture_time:.6f}",
                'length': len(raw_data),
                'raw_data': raw_data
            }
            
            # Process Ethernet header
            if sys.platform != 'win32':  # Linux/Mac
                dest_mac, src_mac, eth_proto, data = self.process_ethernet_header(raw_data)
                packet_info['eth_src_mac'] = src_mac
                packet_info['eth_dest_mac'] = dest_mac
                packet_info['eth_proto'] = eth_proto
            else:  # Windows (IP header directly)
                data = raw_data
                packet_info['eth_src_mac'] = 'N/A'
                packet_info['eth_dest_mac'] = 'N/A'
                packet_info['eth_proto'] = 'IP'
            
            # Process IP header
            version = (data[0] >> 4) & 0xF
            
            if version == 4:  # IPv4
                packet_info['version'] = 'IPv4'
                iph_length = (data[0] & 0xF) * 4
                ttl = data[8]
                protocol = data[9]
                src_ip = socket.inet_ntoa(data[12:16])
                dest_ip = socket.inet_ntoa(data[16:20])
                
                packet_info['src_ip'] = src_ip
                packet_info['dest_ip'] = dest_ip
                packet_info['protocol'] = protocol
                packet_info['ttl'] = ttl
                
                # Extract transport layer data
                transport_data = data[iph_length:]
                
                # Process based on protocol
                if protocol == 6:  # TCP
                    packet_info['protocol_name'] = 'TCP'
                    self.process_tcp_packet(transport_data, packet_info)
                elif protocol == 17:  # UDP
                    packet_info['protocol_name'] = 'UDP'
                    self.process_udp_packet(transport_data, packet_info)
                elif protocol == 1:  # ICMP
                    packet_info['protocol_name'] = 'ICMP'
                    self.process_icmp_packet(transport_data, packet_info)
                else:
                    packet_info['protocol_name'] = f'OTHER ({protocol})'
                    packet_info['info'] = f'Protocol: {protocol}'
                    packet_info['payload'] = transport_data.hex()
            
            elif packet_info.get('eth_proto') == 0x0806:  # ARP
                packet_info['protocol_name'] = 'ARP'
                self.process_arp_packet(data, packet_info)
            
            else:
                # Unknown or unsupported protocol
                packet_info['protocol_name'] = 'UNKNOWN'
                packet_info['src_ip'] = 'N/A'
                packet_info['dest_ip'] = 'N/A'
                packet_info['info'] = 'Unsupported protocol'
                packet_info['payload'] = data.hex()
            
            return packet_info
            
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            return None
    
    def format_mac(self, mac_bytes):
        """Format MAC address bytes into human-readable format"""
        return ':'.join('{:02x}'.format(b) for b in mac_bytes)
    
    def process_ethernet_header(self, data):
        """Process Ethernet header and return relevant info"""
        dest_mac = self.format_mac(data[0:6])
        src_mac = self.format_mac(data[6:12])
        eth_proto = (data[12] << 8) + data[13]
        return dest_mac, src_mac, eth_proto, data[14:]
    
    def process_tcp_packet(self, data, packet_info):
        """Process TCP packet and update packet_info"""
        src_port = (data[0] << 8) + data[1]
        dest_port = (data[2] << 8) + data[3]
        sequence = (data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7]
        ack = (data[8] << 24) + (data[9] << 16) + (data[10] << 8) + data[11]
        
        # Calculate header length
        offset = (data[12] >> 4) * 4
        
        # TCP flags
        flag_urg = (data[13] & 32) >> 5
        flag_ack = (data[13] & 16) >> 4
        flag_psh = (data[13] & 8) >> 3
        flag_rst = (data[13] & 4) >> 2
        flag_syn = (data[13] & 2) >> 1
        flag_fin = data[13] & 1
        
        # Update packet info
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        packet_info['sequence'] = sequence
        packet_info['ack'] = ack
        
        # Flag string
        flags = []
        if flag_syn: flags.append('SYN')
        if flag_ack: flags.append('ACK')
        if flag_fin: flags.append('FIN')
        if flag_rst: flags.append('RST')
        if flag_psh: flags.append('PSH')
        if flag_urg: flags.append('URG')
        
        # Determine if this is HTTP/HTTPS
        if dest_port == 80 or src_port == 80:
            packet_info['protocol_name'] = 'HTTP'
        elif dest_port == 443 or src_port == 443:
            packet_info['protocol_name'] = 'HTTPS'
        
        # Extract payload
        payload = data[offset:]
        packet_info['payload'] = payload.hex()
        
        # Generate info field
        connection_id = f"{packet_info['src_ip']}:{src_port} -> {packet_info['dest_ip']}:{dest_port}"
        flag_str = ' '.join(flags)
        
        if len(flags) > 0:
            info = f"{src_port} → {dest_port} [{flag_str}] Seq={sequence} Ack={ack} Win=?"
        else:
            info = f"{src_port} → {dest_port} Seq={sequence} Ack={ack} Len={len(payload)}"
            
        packet_info['info'] = info
        
        # Check for HTTP data
        if packet_info['protocol_name'] == 'HTTP' and len(payload) > 0:
            try:
                http_data = payload.decode('utf-8', errors='ignore')
                # Check if it's an HTTP request or response
                if http_data.startswith('GET ') or http_data.startswith('POST ') or http_data.startswith('HTTP/'):
                    first_line = http_data.split('\r\n')[0]
                    packet_info['info'] = f"{info} | {first_line}"
            except:
                pass
    
    def process_udp_packet(self, data, packet_info):
        """Process UDP packet and update packet_info"""
        src_port = (data[0] << 8) + data[1]
        dest_port = (data[2] << 8) + data[3]
        length = (data[4] << 8) + data[5]
        
        # Update packet info
        packet_info['src_port'] = src_port
        packet_info['dest_port'] = dest_port
        
        # Extract payload
        payload = data[8:]
        packet_info['payload'] = payload.hex()
        
        # Check for DNS (port 53)
        if src_port == 53 or dest_port == 53:
            packet_info['protocol_name'] = 'DNS'
            try:
                # Simplified DNS packet parsing
                if len(payload) > 12:  # DNS header is 12 bytes
                    transaction_id = (payload[0] << 8) + payload[1]
                    flags = (payload[2] << 8) + payload[3]
                    questions = (payload[4] << 8) + payload[5]
                    answers = (payload[6] << 8) + payload[7]
                    
                    is_response = (flags & 0x8000) != 0
                    
                    if is_response:
                        info = f"{src_port} → {dest_port} DNS Response ID={transaction_id} Answers={answers}"
                    else:
                        info = f"{src_port} → {dest_port} DNS Query ID={transaction_id} Questions={questions}"
                    
                    packet_info['info'] = info
                else:
                    packet_info['info'] = f"{src_port} → {dest_port} [DNS] Len={len(payload)}"
            except:
                packet_info['info'] = f"{src_port} → {dest_port} [DNS] Len={len(payload)}"
        elif src_port == 67 or dest_port == 67 or src_port == 68 or dest_port == 68:
            packet_info['protocol_name'] = 'DHCP'
            packet_info['info'] = f"{src_port} → {dest_port} [DHCP] Len={len(payload)}"
        else:
            packet_info['info'] = f"{src_port} → {dest_port} Len={len(payload)}"
    
    def process_icmp_packet(self, data, packet_info):
        """Process ICMP packet and update packet_info"""
        icmp_type = data[0]
        code = data[1]
        checksum = (data[2] << 8) + data[3]
        
        # Update packet info
        packet_info['icmp_type'] = icmp_type
        packet_info['icmp_code'] = code
        
        # Determine ICMP type
        icmp_type_str = "Unknown"
        if icmp_type == 0:
            icmp_type_str = "Echo Reply"
        elif icmp_type == 8:
            icmp_type_str = "Echo Request"
        elif icmp_type == 3:
            icmp_type_str = "Destination Unreachable"
        elif icmp_type == 11:
            icmp_type_str = "Time Exceeded"
        
        # Extract payload
        payload = data[4:]
        packet_info['payload'] = payload.hex()
        
        # Generate info field
        packet_info['info'] = f"Type={icmp_type} ({icmp_type_str}), Code={code}"
    
    def process_arp_packet(self, data, packet_info):
        """Process ARP packet and update packet_info"""
        # ARP header fields
        hardware_type = (data[0] << 8) + data[1]
        protocol_type = (data[2] << 8) + data[3]
        hardware_size = data[4]
        protocol_size = data[5]
        operation = (data[6] << 8) + data[7]
        
        # Extract addresses
        sender_mac = self.format_mac(data[8:14])
        sender_ip = '.'.join(str(b) for b in data[14:18])
        target_mac = self.format_mac(data[18:24])
        target_ip = '.'.join(str(b) for b in data[24:28])
        
        # Update packet info
        packet_info['src_ip'] = sender_ip
        packet_info['dest_ip'] = target_ip
        packet_info['arp_sender_mac'] = sender_mac
        packet_info['arp_target_mac'] = target_mac
        packet_info['arp_operation'] = operation
        
        # Generate info field
        op_str = "Request" if operation == 1 else "Reply" if operation == 2 else f"Operation {operation}"
        packet_info['info'] = f"ARP {op_str}: {sender_ip} asks/tells {target_ip}"
    
    def update_display(self):
        """Update the packet display in the UI"""
        last_count = 0
        
        while self.is_running:
            # Check if we have new packets to display
            current_count = len(self.captured_packets)
            
            if current_count > last_count:
                # We have new packets, update the UI
                self.root.after(0, self.add_packets_to_ui, last_count, current_count)
                last_count = current_count
                
                # Update status
                self.root.after(0, lambda: self.status_bar.config(
                    text=f"Capturing... {current_count} packets captured"))
            
            # Sleep briefly to avoid consuming too much CPU
            time.sleep(0.5)
    
    def add_packets_to_ui(self, start_idx, end_idx):
        """Add packets to the UI treeview"""
        # Get the filter
        current_filter = self.packet_filter.get()
        
        for i in range(start_idx, end_idx):
            packet = self.captured_packets[i]
            
            # Skip if it doesn't match the filter
            if current_filter != "all" and packet.get('protocol_name', '') != current_filter:
                continue
                
            # Format source and destination with ports if available
            src = packet.get('src_ip', 'N/A')
            dst = packet.get('dest_ip', 'N/A')
            
            if 'src_port' in packet:
                src = f"{src}:{packet['src_port']}"
            if 'dest_port' in packet:
                dst = f"{dst}:{packet['dest_port']}"
                
            # Protocol name
            protocol = packet.get('protocol_name', 'Unknown')
            
            # Insert into treeview
            item_id = self.packet_tree.insert('', 'end', values=(
                i + 1,  # No.
                packet['time'],  # Time
                src,  # Source
                dst,  # Destination
                protocol,  # Protocol
                packet['length'],  # Length
                packet.get('info', '')  # Info
            ))
            
            # Color-code by protocol
            color = self.protocol_colors.get(protocol, self.protocol_colors['OTHER'])
            self.packet_tree.tag_configure(f"protocol_{i}", background=color)
            self.packet_tree.item(item_id, tags=(f"protocol_{i}",))
            
            # Ensure the latest packet is visible
            if i == end_idx - 1:
                self.packet_tree.see(item_id)
    
    def show_packet_details(self, event):
        """Show detailed information for the selected packet"""
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
            
        # Get the selected packet's index
        item = selected_items[0]
        packet_no = int(self.packet_tree.item(item, 'values')[0]) - 1
        
        if packet_no < 0 or packet_no >= len(self.captured_packets):
            return
            
        # Get the packet
        packet = self.captured_packets[packet_no]
        
        # Create a formatted details string
        details = self.format_packet_details(packet)
        
        # Update the details text
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert('1.0', details)
        
        # Add syntax highlighting tags for readability
        self.highlight_details_text()
        
        self.details_text.config(state=tk.DISABLED)
    
    def format_packet_details(self, packet):
        """Format packet details for display"""
        details = []
        
        # Frame information
        details.append(f"Packet #{self.captured_packets.index(packet) + 1}")
        details.append(f"Capture time: {packet['time']} seconds")
        details.append(f"Total length: {packet['length']} bytes")
        details.append("")
        
        # Ethernet header (if available)
        if 'eth_src_mac' in packet and 'eth_dest_mac' in packet:
            details.append("=== ETHERNET HEADER ===")
            details.append(f"Source MAC: {packet['eth_src_mac']}")
            details.append(f"Destination MAC: {packet['eth_dest_mac']}")
            details.append(f"EtherType: 0x{packet.get('eth_proto', 0):04x}")
            details.append("")
        
        # IP header (if available)
        if 'src_ip' in packet and 'dest_ip' in packet:
            details.append("=== IP HEADER ===")
            details.append(f"Version: {packet.get('version', 'Unknown')}")
            details.append(f"Source IP: {packet['src_ip']}")
            details.append(f"Destination IP: {packet['dest_ip']}")
            if 'ttl' in packet:
                details.append(f"TTL: {packet['ttl']}")
            details.append(f"Protocol: {packet.get('protocol_name', 'Unknown')}")
            details.append("")
        
        # Transport layer (TCP/UDP) (if available)
        if 'src_port' in packet and 'dest_port' in packet:
            protocol = packet.get('protocol_name', '')
            if protocol in ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'DHCP']:
                details.append(f"=== {protocol} ===")
                details.append(f"Source Port: {packet['src_port']}")
                details.append(f"Destination Port: {packet['dest_port']}")
                
                if protocol == 'TCP':
                    if 'sequence' in packet:
                        details.append(f"Sequence Number: {packet['sequence']}")
                    if 'ack' in packet:
                        details.append(f"Acknowledgment Number: {packet['ack']}")
                
                details.append("")
        
        # ICMP details (if applicable)
        if 'icmp_type' in packet:
            details.append("=== ICMP ===")
            details.append(f"Type: {packet['icmp_type']}")
            details.append(f"Code: {packet['icmp_code']}")
            details.append("")
        
        # ARP details (if applicable)
        if 'arp_operation' in packet:
            details.append("=== ARP ===")
            details.append(f"Operation: {packet['arp_operation']} " + 
                         f"({'Request' if packet['arp_operation'] == 1 else 'Reply'})")
            details.append(f"Sender MAC: {packet['arp_sender_mac']}")
            details.append(f"Sender IP: {packet['src_ip']}")
            details.append(f"Target MAC: {packet['arp_target_mac']}")
            details.append(f"Target IP: {packet['dest_ip']}")
            details.append("")
        
        # Payload (if present and option enabled)
        if self.show_payload.get() and 'payload' in packet:
            payload_hex = packet['payload']
            if payload_hex:
                details.append("=== PAYLOAD (HEX) ===")
                # Format payload in chunks
                for i in range(0, len(payload_hex), 32):
                    chunk = payload_hex[i:i+32]
                    formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                    details.append(formatted)
                
                # Try to interpret as ASCII if it looks like text
                try:
                    # Convert hex string to bytes
                    payload_bytes = bytes.fromhex(payload_hex)
                    # Count printable characters
                    printable_count = sum(32 <= b <= 126 for b in payload_bytes)
                    # If more than 70% is printable, show as ASCII
                    if printable_count / len(payload_bytes) > 0.7:
                        details.append("\n=== PAYLOAD (ASCII) ===")
                        text = payload_bytes.decode('ascii', errors='replace')
                        details.append(text.replace('\r\n', '\n').replace('\r', '\n'))
                except:
                    pass
        
        return '\n'.join(details)
    
    def highlight_details_text(self):
        """Add color highlighting to the details text"""
        # Highlight section headers
        self.details_text.tag_configure("header", foreground="#3f51b5", font=("Consolas", 10, "bold"))
        
        text = self.details_text.get("1.0", tk.END)
        for line_num, line in enumerate(text.split('\n'), 1):
            if line.startswith("==="):
                start = f"{line_num}.0"
                end = f"{line_num}.{len(line)}"
                self.details_text.tag_add("header", start, end)
    
    def save_capture(self):
        """Save captured packets to a file"""
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to save!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[
                ("Packet capture files", "*.pcap"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w') as f:
                # Create a serializable version of the packets
                serializable_packets = []
                for packet in self.captured_packets:
                    serializable_packet = packet.copy()
                    # Convert raw_data and payload to hex strings
                    if 'raw_data' in serializable_packet:
                        serializable_packet['raw_data'] = serializable_packet['raw_data'].hex()
                    if 'payload' in serializable_packet and isinstance(serializable_packet['payload'], bytes):
                        serializable_packet['payload'] = serializable_packet['payload'].hex()
                    serializable_packets.append(serializable_packet)
                
                # Add metadata
                data = {
                    'metadata': {
                        'created_by': f"{self.username}",
                        'timestamp': f"{self.timestamp}",
                        'packet_count': len(self.captured_packets)
                    },
                    'packets': serializable_packets
                }
                
                json.dump(data, f, indent=2)
                
            self.status_bar.config(text=f"Capture saved to {file_path}")
            messagebox.showinfo("Success", f"Saved {len(self.captured_packets)} packets to {file_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save capture: {str(e)}")
    
    def load_capture(self):
        """Load captured packets from a file"""
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Packet capture files", "*.pcap"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if 'packets' not in data:
                messagebox.showerror("Error", "Invalid packet capture file format")
                return
                
            # Clear existing packets
            self.clear_packets()
            
            # Load the packets
            self.captured_packets = data['packets']
            
            # Convert hex strings back to bytes
            for packet in self.captured_packets:
                if 'raw_data' in packet:
                    packet['raw_data'] = bytes.fromhex(packet['raw_data'])
                if 'payload' in packet and isinstance(packet['payload'], str):
                    packet['payload'] = bytes.fromhex(packet['payload'])
            
            # Update UI
            self.packet_count = len(self.captured_packets)
            self.add_packets_to_ui(0, self.packet_count)
            
            # Show metadata if available
            if 'metadata' in data:
                meta = data['metadata']
                meta_str = f"Loaded {meta.get('packet_count', self.packet_count)} packets"
                if 'created_by' in meta:
                    meta_str += f" created by {meta['created_by']}"
                if 'timestamp' in meta:
                    meta_str += f" at {meta['timestamp']}"
                self.status_bar.config(text=meta_str)
            else:
                self.status_bar.config(text=f"Loaded {self.packet_count} packets from {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load capture: {str(e)}")
    
    def export_as_csv(self):
        """Export captured packets to a CSV file"""
        if not self.captured_packets:
            messagebox.showwarning("Warning", "No packets to export!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
                ])
                
                # Write data
                for i, packet in enumerate(self.captured_packets):
                    src = packet.get('src_ip', 'N/A')
                    dst = packet.get('dest_ip', 'N/A')
                    
                    if 'src_port' in packet:
                        src = f"{src}:{packet['src_port']}"
                    if 'dest_port' in packet:
                        dst = f"{dst}:{packet['dest_port']}"
                        
                    writer.writerow([
                        i + 1,
                        packet['time'],
                        src,
                        dst,
                        packet.get('protocol_name', 'Unknown'),
                        packet['length'],
                        packet.get('info', '')
                    ])
                    
            self.status_bar.config(text=f"Exported to CSV: {file_path}")
            messagebox.showinfo("Success", f"Exported {len(self.captured_packets)} packets to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export as CSV: {str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""Network Packet Analyzer v1.0

An educational tool for capturing and analyzing network packets.

User: {self.username}
Session: {self.timestamp}

This tool is for EDUCATIONAL PURPOSES ONLY.
Please use responsibly and respect network privacy laws.
"""
        messagebox.showinfo("About", about_text)
    
    def show_ethical_warning(self):
        """Show ethical usage warning"""
        warning_text = """⚠️ ETHICAL USAGE WARNING ⚠️

This packet analyzer tool is intended for EDUCATIONAL PURPOSES ONLY.

Unauthorized network monitoring or packet capturing may be illegal in many 
jurisdictions and violates privacy regulations. Only use this tool:

1. On networks you own or have explicit permission to monitor
2. For educational purposes to understand network protocols
3. For troubleshooting your own systems or networks you manage

Misuse of this tool may result in:
- Legal penalties under computer crime legislation
- Violation of privacy laws and regulations
- Ethics violations and potential academic discipline

By continuing to use this tool, you agree to use it responsibly
and in accordance with all applicable laws and regulations.

User: {username}
Timestamp: {timestamp}
""".format(username=self.username, timestamp=self.timestamp)

        result = messagebox.askokcancel("Ethical Usage Agreement", warning_text, icon=messagebox.WARNING)
        if not result:
            self.root.destroy()  # Exit if user doesn't agree

def main():
    """Main function to start the application"""
    root = tk.Tk()
    app = PacketAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()