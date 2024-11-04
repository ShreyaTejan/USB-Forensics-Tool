import logging
import winreg
import win32evtlog
import win32evtlogutil
import os
import string
import re

# Configure logging
logging.basicConfig(
    filename='usb_forensics.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Function to get USB device activity logs from the system
def get_usb_activity_logs():
    logging.info("Fetching USB device activity logs.")
    server = None
    log_type = "System"
    
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        event_id_list = [2003, 2101]
        records = []
        
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        while events:
            for event in events:
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
        logging.info("Successfully fetched USB activity logs.")
    except Exception as e:
        logging.error(f"Error fetching USB activity logs: {e}")
        records = []
    
    return records

# Function to get USB device details from the Registry
def get_usb_registry_info():
    logging.info("Fetching USB registry information.")
    usb_registry_key = r"SYSTEM\CurrentControlSet\Enum\USB"
    usb_info = []

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_registry_key) as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey_name) as subkey:
                    try:
                        device_desc = winreg.QueryValueEx(subkey, "DeviceDesc")[0]
                    except FileNotFoundError:
                        device_desc = "Unknown"
                    
                    try:
                        serial_number = winreg.QueryValueEx(subkey, "SerialNumber")[0]
                    except FileNotFoundError:
                        serial_number = "Unknown"
                    
                    usb_info.append({
                        'DeviceDesc': device_desc,
                        'SerialNumber': serial_number
                    })
        logging.info("USB registry information successfully fetched.")
    except Exception as e:
        logging.error(f"Error accessing USB registry information: {e}")

    return usb_info

# Function to detect unauthorized or malicious usage
def analyze_usb_activity(logs):
    logging.info("Analyzing USB activity logs for unauthorized usage.")
    unauthorized_devices = []
    unauthorized_keywords = ["Unknown", "Unauthorized Device", "Malware"]
    
    for log in logs:
        if any(keyword in log['Message'] for keyword in unauthorized_keywords):
            unauthorized_devices.append(log)
    
    if unauthorized_devices:
        logging.warning(f"Unauthorized USB activity detected: {unauthorized_devices}")
    else:
        logging.info("No unauthorized USB activity found.")
    
    return unauthorized_devices

# Function to list all removable drives
def list_removable_drives():
    logging.info("Listing removable drives.")
    drives = [f"{drive}:" for drive in string.ascii_uppercase if os.path.exists(f"{drive}:")]
    removable_drives = []
    
    for drive in drives:
        if os.path.ismount(drive) and os.path.isdir(drive):
            try:
                volume_info = os.popen(f"wmic logicaldisk where DeviceID='{drive}' get DriveType").read()
                if "2" in volume_info:
                    removable_drives.append(drive)
                    logging.info(f"Removable drive detected: {drive}")
            except Exception as e:
                logging.error(f"Error checking drive {drive}: {e}")

    return removable_drives

# Function to scan and analyze files on the USB drive
def scan_usb_drive(drive_path):
    logging.info(f"Scanning files on USB drive: {drive_path}")
    if not os.path.exists(drive_path):
        logging.warning(f"Drive {drive_path} does not exist.")
        return []

    file_patterns = [r"\bmalware\b", r"\bunauthorized\b"]
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
                            logging.info(f"Pattern found in file: {file_path}")
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")

    if not found_files:
        logging.info(f"No matching patterns found on drive {drive_path}.")
    return found_files

# Main function to execute USB analysis
if __name__ == "__main__":
    logging.info("USB Forensics Tool started.")
    
    logs = get_usb_activity_logs()
    registry_info = get_usb_registry_info()
    unauthorized_logs = analyze_usb_activity(logs)
    removable_drives = list_removable_drives()
    
    all_files = []
    for drive in removable_drives:
        files = scan_usb_drive(drive)
        all_files.extend(files)

    if unauthorized_logs or all_files:
        logging.info("Threats detected. Generating report.")
        generate_report(unauthorized_logs, all_files)
    else:
        logging.info("No threats detected.")
    
    logging.info("USB Forensics Tool execution completed.")
