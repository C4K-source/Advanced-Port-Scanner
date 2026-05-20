import socket 
import threading
import concurrent.futures
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urlparse
from fpdf import FPDF
import os

SCAN_TYPES = ["Normal Scan", "Service Scan", "All Scan"]
scanning = False

VULN_DATABASE = {
    "ftp": ["CVE-2011-2523 (Backdoor exploit available)"],
    "ssh": ["CVE-2018-15473 (Username Enumeration)"],
    "telnet": ["Insecure Cleartext Protocol (Sniffing Vulnerability)"],
    "smtp": ["CVE-2020-28018 (Exim Privilege Escalation)"],
    "http": ["Outdated Server Software Signature (Potential RCE Risk)"],
    "https": ["SSL/TLS Configuration Vulnerability Reference Mapping"],
    "mysql": ["CVE-2012-2122 (Authentication Bypass)"],
}

def clean_target_input(user_input):
    """Strips protocols, trailing slashes, and page routes to return a pure host name."""
    clean_str = user_input.strip()
    if not clean_str.startswith(('http://', 'https://')):
        if '/' in clean_str:
            clean_str = clean_str.split('/')[0]
        return clean_str
    try:
        parsed = urlparse(clean_str)
        host = parsed.netloc
        if ':' in host:
            host = host.split(':')[0]
        return host
    except:
        return user_input.strip()

def get_port_name(port):
    well_known_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
    }
    return well_known_ports.get(port, "Custom Service")

def map_vulnerabilities(port, port_name):
    p_name_lower = port_name.lower()
    for key in VULN_DATABASE:
        if key in p_name_lower:
            return ", ".join(VULN_DATABASE[key])
    return "No baseline CVE signature flagged locally."

def scan_port(target_ip, port, scan_type):
    """Core network socket loop providing visibly distinct outputs depending on scan configuration."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0) # Slightly increased timeout for deeper service evaluation
        res = sock.connect_ex((target_ip, port))
        
        if res == 0:
            # --- NORMAL SCAN: Strictly passive handshake verification ---
            if scan_type == "Normal Scan":
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    recv_data = sock.recv(64).decode(errors='ignore').strip()
                    if recv_data:
                        clean_data = recv_data.replace('\r', '').replace('\n', ' ')
                        banner = f"[Normal] {clean_data}"
                    else:
                        banner = "[Normal Scan] Connection Accepted (Passive)"
                except:
                    banner = "[Normal Scan] Connection Accepted (Passive)"
            
            # --- SERVICE SCAN / ALL SCAN: Active Protocol Aggressive Probing ---
            else:
                try:
                    # Stage 1: Send a targeted request based on common port configurations
                    if port in [80, 443]:
                        sock.send(b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Auditor\r\n\r\n")
                    elif port == 21:
                        sock.send(b"SYST\r\n")
                    elif port == 25:
                        sock.send(b"HELO target\r\n")
                    else:
                        # Fallback payload to wake up silent custom daemons
                        sock.send(b"\r\n\r\n")
                        
                    recv_data = sock.recv(256).decode(errors='ignore').strip()
                    
                    if recv_data:
                        lines = [l.strip() for l in recv_data.split('\n') if l.strip()]
                        # Look for explicit Web Server Headers
                        server_header = [l for l in lines if l.lower().startswith("server:")]
                        
                        if server_header:
                            banner = f"[Service Det.] {server_header[0]}"
                        else:
                            # Concat payload response fragments together cleanly
                            summary = " | ".join(lines[:2])
                            banner = f"[Service Det.] {summary[:60]}"
                    else:
                        banner = f"[Service Det.] Open Port (No response payload caught)"
                except Exception:
                    banner = f"[Service Det.] Active Handshake Exception"
                    
            sock.close()
            return port, True, banner
        sock.close()
        return port, False, None
    except:
        return port, False, None

def safe_insert_grid(target, port, p_name, state, svc, vuln_mapping):
    root_gui.after(0, lambda: result_tree.insert("", tk.END, values=(target, port, p_name, state, svc, vuln_mapping)))

def safe_update_progress(value, label_text, percent_text, color=None):
    def update():
        progress_bar['value'] = value
        status_lbl.config(text=label_text)
        pct_lbl.config(text=percent_text)
        if color:
            status_lbl.config(fg=color)
        else:
            status_lbl.config(fg='#95A5A6')
    root_gui.after(0, update)

def scan_ports(raw_target_input, start_port, end_port, scan_type):
    global scanning
    scanning = True
    
    root_gui.after(0, lambda: [result_tree.delete(item) for item in result_tree.get_children()])
    safe_update_progress(0, f"STATUS: Running optimization [{scan_type}] & parsing host...", "0%")
    
    target_host = clean_target_input(raw_target_input)
    
    try:
        target_ip = socket.gethostbyname(target_host)
        display_identity = f"{target_host} ({target_ip})"
    except Exception:
        safe_update_progress(0, f"ERROR: Could not resolve target address '{target_host}'!", "0%", '#E74C3C')
        scanning = False
        root_gui.after(0, lambda: messagebox.showerror("Resolution Error", f"Unable to resolve host: {target_host}\nPlease enter a valid IP address or domain name."))
        return

    total_ports = end_port - start_port + 1
    processed_count = 0
    open_ports_found = False
    
    safe_update_progress(0, f"STATUS: Scanning target profile: {display_identity}...", "0%", '#2ECC71')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = {executor.submit(scan_port, target_ip, port, scan_type): port for port in range(start_port, end_port + 1)}
        
        for future in concurrent.futures.as_completed(futures):
            if not scanning: 
                break
            
            port, is_open, banner_info = future.result()
            processed_count += 1
            
            percentage = int((processed_count / total_ports) * 100)
            safe_update_progress(percentage, f"STATUS: Analyzing port connector ID: {port}...", f"{percentage}%")
            
            if is_open:
                open_ports_found = True
                p_name = get_port_name(port)
                vuln_mapping = map_vulnerabilities(port, p_name)
                safe_insert_grid(display_identity, port, p_name, "OPEN", banner_info, vuln_mapping)
                
    scanning = False
    if not open_ports_found:
        safe_update_progress(100, "STATUS: Audit complete. No open ports captured in specified range.", "100%", '#E74C3C')
    else:
        safe_update_progress(100, f"STATUS: Diagnostic metrics [{scan_type}] complete! Open ports displayed above.", "100%", '#1ABC9C')

def stop_scan():
    global scanning
    scanning = False
    safe_update_progress(0, "STATUS: Scan execution aborted by operator request.", "0%", '#E74C3C')

def save_results_as_pdf():
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
    if file_path:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="NETWORK PORT LOG AUDIT REPORT", ln=1, align="C")
        pdf.cell(200, 10, txt="="*50, ln=2, align="C")
        for item in result_tree.get_children():
            row = result_tree.item(item)['values']
            pdf.multi_cell(0, 6, f"Target Node: {row[0]} | Port: {row[1]} | Prot: {row[2]} | State: {row[3]}\nBanner: {row[4]}\nThreat Signatures: {row[5]}\n" + "-"*60)
        pdf.output(file_path)
        messagebox.showinfo("Export Engine", "Audit summary successfully formatted to PDF.")

def switch_port_input_mode(event):
    if port_mode_var.get() == "Single":
        range_port_frame.pack_forget()
        single_port_frame.pack(anchor="w")
    else:
        single_port_frame.pack_forget()
        range_port_frame.pack(anchor="w")

def create_gui():
    global root_gui, target_entry, port_mode_var, single_port_frame, range_port_frame, single_port_entry, start_port_entry, end_port_entry, result_tree, status_lbl, progress_bar, pct_lbl
    
    root_gui = tk.Tk()
    root_gui.title("Advanced Port Scanner")
    root_gui.geometry("1150x750")
    root_gui.configure(bg='#0F171E')

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TCombobox", fieldbackground="#1C2630", background="#253241", foreground="#E4E7EB", arrowcolor="#1ABC9C")
    style.configure("Treeview", background="#0A0F14", foreground="#E4E7EB", fieldbackground="#0A0F14", rowheight=26, font=("Consolas", 10))
    style.configure("Treeview.Heading", background="#16222F", foreground="#1ABC9C", font=("Courier New", 10, "bold"), relief="flat")

    banner = tk.Frame(root_gui, bg='#111A24', height=65)
    banner.pack(fill="x")
    lbl_title = tk.Label(banner, text="⚡ ADVANCED PORT SCANNER", font=("Consolas", 13, "bold"), bg='#111A24', fg='#1ABC9C')
    lbl_title.pack(side="left", padx=25, pady=18)
    
    panel = tk.LabelFrame(root_gui, text=" AUDIT TARGET CONTROLS ", bg='#16222F', fg='#95A5A6', font=("Courier New", 9, "bold"), bd=1, padx=20, pady=15)
    panel.pack(fill="x", padx=25, pady=15)

    tk.Label(panel, text="TARGET HOST IP OR DOMAIN:", bg='#16222F', fg='#ECF0F1', font=("Courier New", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
    target_entry = tk.Entry(panel, width=40, font=("Consolas", 11), bg='#1F2D3D', fg='#2ECC71', insertbackground='white', bd=0, highlightthickness=1, highlightbackground='#2C3E50')
    target_entry.grid(row=0, column=1, columnspan=2, sticky="w", padx=10, pady=5)
    target_entry.insert(0, "")

    tk.Label(panel, text="SCAN CONFIG MESH:", bg='#16222F', fg='#ECF0F1', font=("Courier New", 10, "bold")).grid(row=1, column=0, sticky="w", pady=8)
    port_mode_var = tk.StringVar(value="Multiple")
    mode_box = ttk.Combobox(panel, textvariable=port_mode_var, values=["Single", "Multiple"], state="readonly", width=12)
    mode_box.grid(row=1, column=1, sticky="w", padx=10)

    tk.Label(panel, text="SCAN STRATEGY LEVEL:", bg='#16222F', fg='#ECF0F1', font=("Courier New", 10, "bold")).grid(row=1, column=2, sticky="w", padx=15)
    scan_type_var = tk.StringVar(value="All Scan")
    scan_box = ttk.Combobox(panel, textvariable=scan_type_var, values=SCAN_TYPES, state="readonly", width=16)
    scan_box.grid(row=1, column=3, sticky="w")

    global port_config_frame
    port_config_frame = tk.Frame(panel, bg='#16222F')
    port_config_frame.grid(row=2, columnspan=4, sticky="w", pady=10)

    single_port_frame = tk.Frame(port_config_frame, bg='#16222F')
    tk.Label(single_port_frame, text="TARGET SPECIFIC PORT ID:", bg='#16222F', fg='#95A5A6', font=("Courier New", 10, "bold")).pack(side="left")
    single_port_entry = tk.Entry(single_port_frame, width=8, font=("Consolas", 11), bg='#1F2D3D', fg='#E4E7EB', insertbackground='white', bd=0, highlightthickness=1, highlightbackground='#2C3E50')
    single_port_entry.pack(side="left", padx=15)
    single_port_entry.insert(0, "80")

    range_port_frame = tk.Frame(port_config_frame, bg='#16222F')
    tk.Label(range_port_frame, text="START PORT PORTFOLIO:", bg='#16222F', fg='#95A5A6', font=("Courier New", 10, "bold")).pack(side="left")
    start_port_entry = tk.Entry(range_port_frame, width=8, font=("Consolas", 11), bg='#1F2D3D', fg='#E4E7EB', insertbackground='white', bd=0, highlightthickness=1, highlightbackground='#2C3E50')
    start_port_entry.pack(side="left", padx=5)
    start_port_entry.insert(0, "1")
    tk.Label(range_port_frame, text="END PORT PORTFOLIO:", bg='#16222F', fg='#95A5A6', font=("Courier New", 10, "bold")).pack(side="left", padx=15)
    end_port_entry = tk.Entry(range_port_frame, width=8, font=("Consolas", 11), bg='#1F2D3D', fg='#E4E7EB', insertbackground='white', bd=0, highlightthickness=1, highlightbackground='#2C3E50')
    end_port_entry.pack(side="left", padx=5)
    end_port_entry.insert(0, "555")
    range_port_frame.pack(anchor="w")

    grid_container = tk.Frame(root_gui, bg='#0F171E')
    grid_container.pack(fill="both", expand=True, padx=25, pady=5)
    
    columns = ("target_ip", "port_num", "srv_name", "status_state", "banner_logs", "vuln_map")
    result_tree = ttk.Treeview(grid_container, columns=columns, show="headings", selectmode="browse")
    
    result_tree.heading("target_ip", text="RESOLVED NODE IDENTITY")
    result_tree.heading("port_num", text="PORT ID")
    result_tree.heading("srv_name", text="PROTOCOL")
    result_tree.heading("status_state", text="STATE")
    result_tree.heading("banner_logs", text="BANNER DATA LAYER")
    result_tree.heading("vuln_map", text="LOCAL IDENTIFIED CVE METRIC THREATS")

    result_tree.column("target_ip", width=180, anchor="center")
    result_tree.column("port_num", width=80, anchor="center")
    result_tree.column("srv_name", width=100, anchor="center")
    result_tree.column("status_state", width=100, anchor="center")
    result_tree.column("banner_logs", width=220, anchor="w")
    result_tree.column("vuln_map", width=380, anchor="w")
    
    scrollbar = ttk.Scrollbar(grid_container, orient="vertical", command=result_tree.yview)
    result_tree.configure(yscrollcommand=scrollbar.set)
    result_tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    progress_frame = tk.Frame(root_gui, bg='#111A24', padx=20, pady=8)
    progress_frame.pack(fill="x", padx=25, pady=5)
    
    status_lbl = tk.Label(progress_frame, text="STATUS: System online. Ready to accept target vector streams.", font=("Courier New", 9), bg='#111A24', fg='#95A5A6')
    status_lbl.pack(side="left")
    
    pct_lbl = tk.Label(progress_frame, text="0%", font=("Consolas", 10, "bold"), bg='#111A24', fg='#1ABC9C')
    pct_lbl.pack(side="right", padx=5)
    
    progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=220, mode='determinate')
    progress_bar.pack(side="right", padx=10)

    tray = tk.Frame(root_gui, bg='#0F171E')
    tray.pack(fill="x", padx=25, pady=15)

    tk.Button(tray, text="EXECUTE ENGINE", command=lambda: start_scan_wrapper(scan_type_var.get()), width=16, font=("Courier New", 10, "bold"), bg='#1ABC9C', fg='#0F171E', activebackground='#16A085', relief="flat").pack(side="left", padx=5)
    tk.Button(tray, text="ABORT SCANNER", command=stop_scan, width=16, font=("Courier New", 10, "bold"), bg='#E74C3C', fg='white', activebackground='#C0392B', relief="flat").pack(side="left", padx=5)
    tk.Button(tray, text="EXPORT LOG PDF", command=save_results_as_pdf, width=18, font=("Courier New", 10, "bold"), bg='#34495E', fg='white', activebackground='#2C3E50', relief="flat").pack(side="right", padx=5)

    mode_box.bind("<<ComboboxSelected>>", switch_port_input_mode)
    root_gui.mainloop()

def start_scan_wrapper(scan_type):
    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Target Empty", "Please type a valid URL or host IP destination.")
        return
    mode = port_mode_var.get()
    if mode == "Single":
        p = single_port_entry.get().strip()
        if not p.isdigit(): return
        sp = ep = int(p)
    else:
        sp, ep = start_port_entry.get().strip(), end_port_entry.get().strip()
        if not sp.isdigit() or not ep.isdigit(): return
        sp, ep = int(sp), int(ep)
    
    threading.Thread(target=scan_ports, args=(target, sp, ep, scan_type), daemon=True).start()

if __name__ == "__main__":
    create_gui()