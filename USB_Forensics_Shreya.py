#USB Forensics Tool

import winreg
import win32evtlog
import win32evtlogutil
import win32event
import win32con
import win32security
import winerror
import os
import string
import re
from datetime import datetime

# Function to get USB device activity logs from the system
def get_usb_activity_logs():
    # Open the System log on the local machine
    server = None  # None means the local machine
    log_type = "System"  # Windows Event Log type (System log)
    
    # Create handle for event log
    hand = win32evtlog.OpenEventLog(server, log_type)
    
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    
    event_id_list = [2003, 2101]  # Event IDs for USB plug/unplug
    records = []
    
    # Read events from the log
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    while events:
        for event in events:
            # Filter USB-related events
            if event.EventID in event_id_list:
                records.append({
                    'EventID': event.EventID,
                    'Source': event.SourceName,
                    'TimeGenerated': event.TimeGenerated,
                    'EventType': event.EventType,
                    'EventCategory': event.EventCategory,
                    'ComputerName': event.ComputerName,
                    'Message': win32evtlogutil.SafeFormatMessage(event, log_type)
                })
        events = win32evtlog.ReadEventLog(hand, flags, 0)
    
    win32evtlog.CloseEventLog(hand)
    return records

# Function to get USB device details from the Registry
def get_usb_registry_info():
    usb_registry_key = r"SYSTEM\CurrentControlSet\Enum\USB"
    usb_info = []

    try:
        with win32reg.OpenKey(win32reg.HKEY_LOCAL_MACHINE, usb_registry_key) as key:
            for i in range(0, win32reg.QueryInfoKey(key)[0]):
                subkey_name = win32reg.EnumKey(key, i)
                with win32reg.OpenKey(key, subkey_name) as subkey:
                    device_desc = win32reg.QueryValueEx(subkey, "DeviceDesc")[0]
                    serial_number = win32reg.QueryValueEx(subkey, "SerialNumber")[0] if "SerialNumber" in win32reg.QueryValueEx(subkey, "") else "Unknown"
                    usb_info.append({
                        'DeviceDesc': device_desc,
                        'SerialNumber': serial_number
                    })
    except Exception as e:
        print(f"Error accessing USB registry information: {e}")

    return usb_info

# Function to detect unauthorized or malicious usage
def analyze_usb_activity(logs):
    unauthorized_devices = []
    
    # Add logic to define "unauthorized" based on your organization rules
    # Example: Checking if specific USB device names or serials are unauthorized
    unauthorized_keywords = ["Unknown", "Unauthorized Device", "Malware"]
    
    for log in logs:
        # Check if message contains unauthorized keywords
        if any(keyword in log['Message'] for keyword in unauthorized_keywords):
            unauthorized_devices.append(log)
    
    return unauthorized_devices

# Function to list all removable drives
def list_removable_drives():
    drives = [f"{drive}:" for drive in string.ascii_uppercase if os.path.exists(f"{drive}:")]
    removable_drives = []
    
    for drive in drives:
        if os.path.ismount(drive) and os.path.isdir(drive):
            try:
                volume_info = os.popen(f"wmic logicaldisk where DeviceID='{drive}' get DriveType").read()
                if "2" in volume_info:  # DriveType 2 corresponds to removable storage
                    removable_drives.append(drive)
            except Exception as e:
                print(f"Error checking drive {drive}: {e}")

    return removable_drives

# Function to scan and analyze files on the USB drive
def scan_usb_drive(drive_path):
    if not os.path.exists(drive_path):
        print(f"Drive {drive_path} does not exist.")
        return

    file_patterns = [r"\bmalware\b", r"\bunauthorized\b"]  # Add more patterns as needed
    found_files = []

    for root, dirs, files in os.walk(drive_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    for pattern in file_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            found_files.append(file_path)
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

    return found_files



# Display the logs
def display_logs(logs):
    for log in logs:
        print(f"EventID: {log['EventID']}, Source: {log['Source']}")
        print(f"Time: {log['TimeGenerated']}")
        print(f"Message: {log['Message']}")
        print("=" * 50)

# Function to cross-reference logs and registry information
def cross_reference_logs_and_registry(logs, registry_info):
    known_threats = ["Unauthorized Device", "Malware"]
    threats_detected = []

    for log in logs:
        if any(threat in log['Message'] for threat in known_threats):
            threats_detected.append(log)

    for info in registry_info:
        if any(threat in info['DeviceDesc'] for threat in known_threats):
            threats_detected.append(info)

    return threats_detected


# Function to generate a report
def generate_report(threats, files):
    with open("usb_forensics_report.txt", "w") as report_file:
        report_file.write("Detected Threats:\n")
        for threat in threats:
            report_file.write(f"Device Description: {threat.get('DeviceDesc', 'N/A')}\n")
            report_file.write(f"Serial Number: {threat.get('SerialNumber', 'N/A')}\n")
            report_file.write(f"Message: {threat.get('Message', 'N/A')}\n")
            report_file.write("=" * 50 + "\n")
        
        report_file.write("\nFiles Matching Patterns:\n")
        for file in files:
            report_file.write(f"File: {file}\n")
            report_file.write("=" * 50 + "\n")

if __name__ == "__main__":
    print("Fetching USB Activity Logs...\n")
    logs = get_usb_activity_logs()

    print("Fetching USB Registry Information...\n")
    registry_info = get_usb_registry_info()
    
    print("Analyzing Logs for Unauthorized USB Activity...\n")
    unauthorized_logs = analyze_usb_activity(logs)

    print("Listing Removable Drives...\n")
    removable_drives = list_removable_drives()
    
    print("Scanning USB Drives...\n")
    all_files = []
    for drive in removable_drives:
        print(f"Scanning drive {drive}...")
        files = scan_usb_drive(drive)
        all_files.extend(files)
    print("Cross-Referencing Logs and Registry Information...\n")
    threats = cross_reference_logs_and_registry(unauthorized_logs, registry_info)
    
    if unauthorized_logs:
        print("Unauthorized or Malicious USB Device Activity Detected:\n")
        display_logs(unauthorized_logs)
    else:
        print("No unauthorized USB device activity found.")
    
    if threats or all_files:
        print("Generating Report...\n")
        generate_report(threats, all_files)
        print("Report generated: usb_forensics_report.txt")
    else:
        print("No threats detected.")
        
