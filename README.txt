TCP PORT SCANNER
================

Project Description:
This project is a Python-based TCP Port Scanner with a graphical
user interface (GUI).

Features:
- Host/IP address input
- Starting and ending port selection
- TCP port scanning
- Open-port detection
- Common service identification
- Progress bar
- Scan results display
- Export scan results to a text file
- Security analysis
- Scan summary

Technologies Used:
- Python
- Tkinter
- Socket
- Threading
- Logging

Test Target:
127.0.0.1

Test Result:
Ports 135 and 445 were detected as open during the test scan.

Output Files:
- scan_report.txt
- scan_results.log

Note:
The scanner should only be used against systems that you own
or have explicit permission to test.
Limitations:
- This scanner performs TCP connect scans.
- It does not perform vulnerability exploitation.
- Results depend on firewall and network configuration.
- Only scan systems that you own or have permission to test.