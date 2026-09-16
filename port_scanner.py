import socket
import threading
import logging
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


# ==========================================================
# LOGGING
# ==========================================================

logging.basicConfig(
    filename="scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


# ==========================================================
# COMMON TCP SERVICES
# ==========================================================

SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "Microsoft SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Proxy"
}


# ==========================================================
# SECURITY INFORMATION
# ==========================================================

SECURITY_INFO = {
    20: (
        "FTP Data",
        "Used for FTP data transfer.",
        "Use secure alternatives such as SFTP/FTPS when possible."
    ),

    21: (
        "FTP",
        "Used for File Transfer Protocol.",
        "Avoid exposing FTP to untrusted networks; prefer SFTP/FTPS."
    ),

    22: (
        "SSH",
        "Used for secure remote administration.",
        "Restrict access to trusted users and networks."
    ),

    23: (
        "Telnet",
        "Used for remote administration without encryption.",
        "Avoid Telnet on untrusted networks; use SSH instead."
    ),

    25: (
        "SMTP",
        "Used for sending email between mail systems.",
        "Restrict unnecessary SMTP access and use proper mail-server security."
    ),

    53: (
        "DNS",
        "Used for domain-name resolution.",
        "Allow DNS only where required and secure the DNS service."
    ),

    80: (
        "HTTP",
        "Used for unencrypted web traffic.",
        "Prefer HTTPS for applications handling sensitive information."
    ),

    135: (
        "Microsoft RPC",
        "Used by Windows Remote Procedure Call services.",
        "Restrict access to trusted networks and use firewall rules."
    ),

    139: (
        "NetBIOS Session",
        "Used by older Windows networking services.",
        "Disable or restrict it if it is not required."
    ),

    443: (
        "HTTPS",
        "Used for encrypted web traffic.",
        "Keep the web service and TLS configuration updated."
    ),

    445: (
        "Microsoft SMB",
        "Used for Windows file and printer sharing.",
        "Do not expose SMB directly to untrusted networks."
    ),

    3306: (
        "MySQL",
        "Used by MySQL database servers.",
        "Restrict database access to trusted hosts."
    ),

    3389: (
        "RDP",
        "Used for Windows Remote Desktop.",
        "Restrict RDP access and use strong authentication."
    ),

    5432: (
        "PostgreSQL",
        "Used by PostgreSQL database servers.",
        "Restrict database access to trusted hosts."
    ),

    5900: (
        "VNC",
        "Used for remote graphical access.",
        "Restrict access and use strong authentication."
    ),

    8080: (
        "HTTP Proxy",
        "Commonly used for alternative web/proxy services.",
        "Verify the service and restrict unnecessary external access."
    )
}


# ==========================================================
# GLOBAL VARIABLES
# ==========================================================

host = ""
start_port = 1
end_port = 500

completed_ports = 0
total_ports = 0

open_ports = []

scan_lock = threading.Lock()


# ==========================================================
# GET SERVICE NAME
# ==========================================================

def get_service_name(port):

    if port in SERVICES:
        return SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")

    except OSError:
        return "Unknown Service"


# ==========================================================
# SCAN ONE PORT
# ==========================================================

def scan_port(port):

    global completed_ports

    sock = None

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        result = sock.connect_ex(
            (host, port)
        )

        if result == 0:

            service = get_service_name(port)

            message = (
                f"Port {port} OPEN - {service}"
            )

            with scan_lock:
                open_ports.append(
                    (port, service)
                )

            window.after(
                0,
                lambda msg=message:
                add_result(msg)
            )

            logging.info(message)

    except Exception as error:

        logging.error(
            f"Port {port}: {error}"
        )

    finally:

        if sock:
            sock.close()

        with scan_lock:
            completed_ports += 1

        window.after(
            0,
            update_progress
        )


# ==========================================================
# UPDATE PROGRESS
# ==========================================================

def update_progress():

    progress["value"] = completed_ports

    progress_label.config(
        text=f"Progress: {completed_ports}/{total_ports}"
    )

    if completed_ports >= total_ports:

        status_label.config(
            text="Scan completed."
        )

        add_result("")
        add_result("=" * 45)
        add_result("SCAN SUMMARY")
        add_result("=" * 45)

        add_result(
            f"Target: {host}"
        )

        add_result(
            f"Port Range: {start_port}-{end_port}"
        )

        add_result(
            f"Ports Scanned: {total_ports}"
        )

        add_result(
            f"Open Ports: {len(open_ports)}"
        )

        add_result(
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        add_result("=" * 45)

        if open_ports:

            add_result("")
            add_result("SECURITY ANALYSIS")
            add_result("=" * 45)

            for port, service in sorted(open_ports):

                if port in SECURITY_INFO:

                    name, purpose, recommendation = \
                        SECURITY_INFO[port]

                    add_result("")
                    add_result(
                        f"Port {port} - {name}"
                    )

                    add_result(
                        f"Purpose: {purpose}"
                    )

                    add_result(
                        f"Recommendation: {recommendation}"
                    )

                else:

                    add_result("")
                    add_result(
                        f"Port {port} - {service}"
                    )

                    add_result(
                        "Purpose: Service identified by the scanner."
                    )

                    add_result(
                        "Recommendation: Verify that this service "
                        "is required and restrict access where appropriate."
                    )

        else:

            add_result("")
            add_result(
                "No open TCP ports were detected."
            )

        add_result("")
        add_result(
            "Scan completed successfully."
        )

        logging.info(
            "Scan completed successfully."
        )


# ==========================================================
# ADD RESULT TO TEXT BOX
# ==========================================================

def add_result(message):

    results_text.insert(
        tk.END,
        message + "\n"
    )

    results_text.see(
        tk.END
    )


# ==========================================================
# START SCAN
# ==========================================================

def start_scan():

    global host
    global start_port
    global end_port
    global completed_ports
    global total_ports
    global open_ports

    host = host_entry.get().strip()

    if not host:

        messagebox.showerror(
            "Error",
            "Please enter a host or IP address."
        )

        return

    try:

        start_port = int(
            start_entry.get()
        )

        end_port = int(
            end_entry.get()
        )

    except ValueError:

        messagebox.showerror(
            "Error",
            "Ports must be numbers."
        )

        return

    if start_port < 1 or end_port > 65535:

        messagebox.showerror(
            "Error",
            "Ports must be between 1 and 65535."
        )

        return

    if start_port > end_port:

        messagebox.showerror(
            "Error",
            "Starting port cannot be greater than ending port."
        )

        return

    # Clear previous results

    results_text.delete(
        "1.0",
        tk.END
    )

    # Reset values

    completed_ports = 0
    open_ports = []

    total_ports = (
        end_port - start_port + 1
    )

    progress["maximum"] = total_ports
    progress["value"] = 0

    progress_label.config(
        text=f"Progress: 0/{total_ports}"
    )

    status_label.config(
        text="Scanning..."
    )

    logging.info(
        f"Starting scan of {host} "
        f"ports {start_port}-{end_port}"
    )

    add_result(
        f"Starting scan of {host}..."
    )

    add_result(
        f"Scanning ports {start_port}-{end_port}"
    )

    add_result("")

    start_button.config(
        state="disabled"
    )

    scan_thread = threading.Thread(
        target=run_scan,
        daemon=True
    )

    scan_thread.start()


# ==========================================================
# RUN SCAN
# ==========================================================

def run_scan():

    threads = []

    for port in range(
        start_port,
        end_port + 1
    ):

        thread = threading.Thread(
            target=scan_port,
            args=(port,),
            daemon=True
        )

        thread.start()

        threads.append(thread)

    for thread in threads:

        thread.join()

    window.after(
        0,
        lambda: start_button.config(
            state="normal"
        )
    )


# ==========================================================
# EXPORT RESULTS
# ==========================================================

def export_results():

    report = results_text.get(
        "1.0",
        tk.END
    ).strip()

    if not report:

        messagebox.showwarning(
            "No Results",
            "Please run a scan before exporting."
        )

        return

    filename = filedialog.asksaveasfilename(
        title="Save Scan Report",
        defaultextension=".txt",
        filetypes=[
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ],
        initialfile="scan_report.txt"
    )

    if not filename:
        return

    try:

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(report)

        messagebox.showinfo(
            "Export Successful",
            f"Report saved successfully:\n\n{filename}"
        )

        logging.info(
            f"Report exported to {filename}"
        )

    except Exception as error:

        messagebox.showerror(
            "Export Error",
            f"Could not save report:\n{error}"
        )


# ==========================================================
# OPEN REPORT
# ==========================================================

def open_report():

    report_file = "scan_report.txt"

    if os.path.exists(report_file):

        try:

            os.startfile(
                os.path.abspath(report_file)
            )

        except Exception as error:

            messagebox.showerror(
                "Error",
                f"Could not open report:\n{error}"
            )

    else:

        messagebox.showwarning(
            "Report Not Found",
            "scan_report.txt was not found.\n\n"
            "Use Export Results to create a report first."
        )


# ==========================================================
# CLEAR RESULTS
# ==========================================================

def clear_results():

    global completed_ports
    global total_ports
    global open_ports

    results_text.delete(
        "1.0",
        tk.END
    )

    completed_ports = 0
    total_ports = 0
    open_ports = []

    progress["value"] = 0

    progress_label.config(
        text="Progress: 0/0"
    )

    status_label.config(
        text="Ready"
    )


# ==========================================================
# GUI
# ==========================================================

window = tk.Tk()

window.title(
    "TCP Port Scanner"
)

window.geometry(
    "700x750"
)

window.resizable(
    False,
    False
)


# ==========================================================
# TITLE
# ==========================================================

title_label = ttk.Label(
    window,
    text="TCP PORT SCANNER",
    font=("Arial", 20, "bold")
)

title_label.pack(
    pady=15
)


# ==========================================================
# HOST
# ==========================================================

host_label = ttk.Label(
    window,
    text="Host / IP Address:"
)

host_label.pack(
    pady=3
)

host_entry = ttk.Entry(
    window,
    width=45
)

host_entry.pack(
    pady=3
)

host_entry.insert(
    0,
    "127.0.0.1"
)


# ==========================================================
# STARTING PORT
# ==========================================================

start_label = ttk.Label(
    window,
    text="Starting Port:"
)

start_label.pack(
    pady=3
)

start_entry = ttk.Entry(
    window,
    width=45
)

start_entry.pack(
    pady=3
)

start_entry.insert(
    0,
    "1"
)


# ==========================================================
# ENDING PORT
# ==========================================================

end_label = ttk.Label(
    window,
    text="Ending Port:"
)

end_label.pack(
    pady=3
)

end_entry = ttk.Entry(
    window,
    width=45
)

end_entry.pack(
    pady=3
)

end_entry.insert(
    0,
    "500"
)


# ==========================================================
# BUTTON FRAME
# ==========================================================

button_frame = ttk.Frame(
    window
)

button_frame.pack(
    pady=10
)


# START BUTTON

start_button = ttk.Button(
    button_frame,
    text="Start Scan",
    command=start_scan
)

start_button.grid(
    row=0,
    column=0,
    padx=5
)


# CLEAR BUTTON

clear_button = ttk.Button(
    button_frame,
    text="Clear Results",
    command=clear_results
)

clear_button.grid(
    row=0,
    column=1,
    padx=5
)


# EXPORT BUTTON

export_button = ttk.Button(
    button_frame,
    text="Export Results",
    command=export_results
)

export_button.grid(
    row=0,
    column=2,
    padx=5
)


# OPEN REPORT BUTTON

open_report_button = ttk.Button(
    button_frame,
    text="Open Report",
    command=open_report
)

open_report_button.grid(
    row=0,
    column=3,
    padx=5
)


# ==========================================================
# STATUS
# ==========================================================

status_label = ttk.Label(
    window,
    text="Ready"
)

status_label.pack(
    pady=5
)


# ==========================================================
# PROGRESS LABEL
# ==========================================================

progress_label = ttk.Label(
    window,
    text="Progress: 0/0"
)

progress_label.pack(
    pady=3
)


# ==========================================================
# PROGRESS BAR
# ==========================================================

progress = ttk.Progressbar(
    window,
    orient="horizontal",
    length=550,
    mode="determinate"
)

progress.pack(
    pady=5
)


# ==========================================================
# RESULTS LABEL
# ==========================================================

results_label = ttk.Label(
    window,
    text="Scan Results:",
    font=("Arial", 11, "bold")
)

results_label.pack(
    pady=5
)


# ==========================================================
# RESULTS TEXT BOX
# ==========================================================

results_frame = ttk.Frame(
    window
)

results_frame.pack(
    padx=20,
    pady=5
)

results_text = tk.Text(
    results_frame,
    height=25,
    width=80,
    wrap="word"
)

results_text.pack(
    side="left"
)


# SCROLLBAR

scrollbar = ttk.Scrollbar(
    results_frame,
    orient="vertical",
    command=results_text.yview
)

scrollbar.pack(
    side="right",
    fill="y"
)

results_text.config(
    yscrollcommand=scrollbar.set
)


# ==========================================================
# START GUI
# ==========================================================

window.mainloop()