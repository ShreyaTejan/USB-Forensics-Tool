# USB-Forensics-Tool

## Introduction

- This project is entirely a **Windows-based USB Forensics Tool**.
- It is focused on monitoring and analyzing USB device activity on a Windows system.
- It logs USB device insertions/removals and helps detect potential unauthorized or malicious usage.

## **Features**

- **USB Activity Log Retrieval**: Retrieves and filters relevant USB device connection events from the Windows Event Log.
- **Registry Information Fetching**: Extracts detailed USB device information (e.g., device description, serial numbers) from the Windows registry.
- **Unauthorized Device Detection**: Analyzes event logs and USB device information for signs of unauthorized or malicious devices.
- **Removable Drive Detection**: Identifies all connected USB drives (removable storage) on the system.
- **File Scanning**: Scans USB drives for potentially malicious or unauthorized files based on regular expressions.
- **Cross-Referencing Logs and Registry**: Detects threats by comparing activity logs with registry data.
- **Forensic Report Generation**: Outputs a detailed report containing suspicious device activities and detected files.

---

## Prerequisites
- **Windows OS**: This tool is designed to run on Windows because it uses the `pywin32` library to access Windows Event Logs.
- **Python 3.10 or higher**: Make sure Python is installed on your system. You can download it from [here](https://www.python.org/downloads/).
- **`pywin32` Library**: This is required to access and manage Windows Event Logs.
  Install it using:
  ```bash
  pip install pywin32

- Install dependencies:
  ```bash
  pip install pywin32

- Run the script with admin privileges:
  ```bash
  python usb_forensics_tool.py

  ## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/usb-forensics-tool.git
   cd usb-forensics-tool


This **Markdown** code provides a full breakdown of the project, covering **features**, **installation**, **usage**, and a **script breakdown**. You can copy and paste this directly into your README file.




   

## Code Overview

### `get_usb_activity_logs()`
This function retrieves logs related to USB activity from the Windows Event Logs. It filters events based on specific Event IDs corresponding to USB plug/unplug events.

### `analyze_usb_activity(logs)`
This function analyzes the logs retrieved by `get_usb_activity_logs()` and checks for suspicious activity. You can customize it by adding unauthorized device patterns.

### `display_logs(logs)`
Displays the logs in a readable format, providing information such as event ID, source, timestamp, and messages for each USB event.

## Customization

- **Event IDs**: You can modify the `event_id_list` in `get_usb_activity_logs()` to track different events. Event IDs 2003 and 2101 typically correspond to USB device activity.
  
- **Unauthorized Device Detection**: Customize the `unauthorized_keywords` in `analyze_usb_activity()` to match specific device names, serial numbers, or any suspicious behavior you want to flag.


## Future Scope of the Project
- **Cross-platform support**: Extend compatibility to non-Windows systems like Linux using libraries such as `usbrip`.
- **Automated Reports**: Add functionality to generate periodic reports of USB device activity.
- **Device Whitelisting**: Implement a feature to maintain a list of trusted USB devices to improve the detection of unauthorized devices.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Feel free to contribute by submitting issues or pull requests. Please follow the contributing guidelines in `CONTRIBUTING.md`.

---

### Additional Resources:
- [pywin32 Documentation](https://github.com/mhammond/pywin32)
- [Understanding Windows Event Logs](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging)

