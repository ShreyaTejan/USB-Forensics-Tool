# USB-Forensics-Tool

## Introduction
- This project is entirely a **Windows-based USB Forensics Tool**.
- It is focused on monitoring and analyzing USB device activity on a Windows system.
- It logs USB device insertions/removals and helps detect potential unauthorized or malicious usage.

## Features
- **Retrieve USB Activity Logs**: Extracts logs from Windows Event Logs that capture USB device activity, such as plug/unplug events.
- **Identify Unauthorized Devices**: Analyzes logs to detect unauthorized or suspicious USB devices based on predefined keywords or patterns.
- **Event Filtering**: Filters relevant USB-related Event IDs to avoid unnecessary log clutter.
- **Cross-referencing for Anomalies**: Cross-references device IDs against a list of known trusted devices.

## Prerequisites
- **Windows OS**: This tool is designed to run on Windows because it uses the `pywin32` library to access Windows Event Logs.
- **Python 3.x**: Make sure Python is installed on your system. You can download it from [here](https://www.python.org/downloads/).
- **`pywin32` Library**: This is required to access and manage Windows Event Logs. Install it using:
  ```bash
  pip install pywin32

## Prerequisites
- **Windows OS**: This tool is designed to run on Windows because it uses the `pywin32` library to access Windows Event Logs.
- **Python 3.10 or higher**: Make sure Python is installed on your system. You can download it from [here](https://www.python.org/downloads/).
- **`pywin32` Library**: This is required to access and manage Windows Event Logs. Install it using:
  ```bash
  pip install pywin32

- Install dependencies:
  ```bash
  pip install pywin32

- Run the script with admin privileges:
  ```bash
  python usb_forensics_tool.py

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

## Example Output

