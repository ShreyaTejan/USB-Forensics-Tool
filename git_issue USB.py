import logging

# logging initialize 
logging.basicConfig(
    filename='usb_forensics.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Modified scan_usb_drive function
def scan_usb_drive(drive_path):
    if not os.path.exists(drive_path):
        logging.warning(f"Drive {drive_path} does not exist.")
        print(f"Drive {drive_path} does not exist.")
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
                print(f"Error reading file {file_path}: {e}")

    if not found_files:
        logging.info(f"No matching patterns found in files on {drive_path}.")
    return found_files



#end of orgfile
if __name__ == "__main__":
    print("Fetching USB Activity Logs...\n")
    logs = get_usb_activity_logs()
    logging.info("USB activity logs fetched.")

    print("Fetching USB Registry Information...\n")
    registry_info = get_usb_registry_info()
    logging.info("USB registry information fetched.")

    print("Analyzing Logs for Unauthorized USB Activity...\n")
    unauthorized_logs = analyze_usb_activity(logs)
    logging.info("Unauthorized USB activity analysis completed.")

    print("Listing Removable Drives...\n")
    removable_drives = list_removable_drives()
    logging.info(f"Removable drives found: {removable_drives}")

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
        logging.warning("Unauthorized USB device activity detected.")
    else:
        print("No unauthorized USB device activity found.")
    
    if threats or all_files:
        print("Generating Report...\n")
        generate_report(threats, all_files)
        logging.info("Report generated: usb_forensics_report.txt")
    else:
        print("No threats detected.")
