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
