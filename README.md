# USB Forensics Tool by Shreya

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


## Prerequisites
- **Windows OS**: This tool is designed to run on Windows because it uses the `pywin32` library to access Windows Event Logs.
- **Python 3.10 or higher**: Make sure Python is installed on your system. You can download it from [here](https://www.python.org/downloads/).
- **`pywin32` Library**: This is required to access and manage Windows Event Logs.
  Install it using:
  
  ```bash
  pip install pywin32

## Installation

-  **Clone the repository**
    ```bash
    git clone https://github.com/username/usb-forensics-tool.gitcd usb-forensics-tool
   
- **Install Dependencies:**
  Ensure you have the necessary Python modules:

  ```bash
  pip install pywin32

- **Execute** the Python script using the command prompt with admin privileges:
  ```bash
  python usb_forensics_tool.py
 
## Usage
1.  Open a command prompt with administrator privileges (necessary to access Windows Event Logs and registry).
    
-  ```bash 
    cd "C:\Path\To\USB_Forensics_Tool"
-  ```bash
    python "USB_Forensics_ShreyaFinal.py"
2.  The script will:
    
    *   Fetch USB activity logs.
        
    *   Fetch USB registry information.
        
    *   Analyze logs for unauthorized activity.
        
    *   List removable drives and scan them for suspicious files.
        
    *   Cross-reference log data with registry information.
        
    *   Generate a forensic report (usb\_forensics\_report.txt).
        

**Script Breakdown**
--------------------

### **Key Functions**:

*   **get\_usb\_activity\_logs()**: Fetches USB-related events from the Windows Event Log.
    
*   **get\_usb\_registry\_info()**: Retrieves information about connected USB devices from the Windows registry.
    
*   **analyze\_usb\_activity()**: Analyzes the event logs for unauthorized or malicious USB devices.
    
*   **list\_removable\_drives()**: Lists all removable USB drives connected to the system.
    
*   **scan\_usb\_drive(drive\_path)**: Scans a USB drive for suspicious files based on defined patterns.
    
*   **cross\_reference\_logs\_and\_registry()**: Cross-references event logs and registry information to detect known threats.
    
*   **generate\_report()**: Creates a forensic report detailing detected threats and suspicious files.
    

## Code Overview

### `get_usb_activity_logs()`
This function retrieves logs related to USB activity from the Windows Event Logs. It filters events based on specific Event IDs corresponding to USB plug/unplug events.

### `analyze_usb_activity(logs)`
This function analyzes the logs retrieved by `get_usb_activity_logs()` and checks for suspicious activity. You can customize it by adding unauthorized device patterns.

### `display_logs(logs)`
Displays the logs in a readable format, providing information such as event ID, source, timestamp, and messages for each USB event.

**Customization**
-----------------

- **Event IDs**: You can modify the `event_id_list` in `get_usb_activity_logs()` to track different events. Event IDs 2003 and 2101 typically correspond to USB device activity.
  
- **Unauthorized Device Detection**: Customize the `unauthorized_keywords` in `analyze_usb_activity()` to match specific device names, serial numbers, or any suspicious behavior you want to flag.

*   **File Patterns**: You can modify the file\_patterns list in the scan\_usb\_drive function to add more patterns or keywords for detecting suspicious files.
    
*   **Unauthorized Device Detection**: You can modify the unauthorized\_keywords and known\_threats lists to include your organization’s specific keywords or device names for more precise detection
  


------------


## Future Scope of the Project

- **Cross-platform support**: Extend compatibility to non-Windows systems like Linux using libraries such as `usbrip`.
  
- **Automated Reports**: Add functionality to generate periodic reports of USB device activity.
  
- **Device Whitelisting**: Implement a feature to maintain a list of trusted USB devices to improve the detection of unauthorized devices.

  

## Forensic Report


The tool generates a text report (usb\_forensics\_report.txt) that contains:

*   **Detected Threats**: USB devices flagged as unauthorized or malicious based on the event logs and registry data.
    
*   **Suspicious Files**: Files on removable drives that match predefined patterns (e.g., malware indicators).
    
The report is stored in the directory where the script is executed.



## Potential Use Cases


*   **Corporate Security**: Monitor and log all USB activity in a corporate environment, detect unauthorized devices, and prevent data exfiltration.
    
*   **Forensics**: Help forensic teams analyze historical USB connections to a system and detect potential unauthorized access via removable storage.
    
*   **Malware Detection**: Identify USB drives that might have been used to transport malware by scanning for suspicious file contents.
    


## Limitations


*   The tool currently only works on Windows** systems due to its reliance on Windows-specific APIs.
    
*   It may need administrative privileges to access system logs and registry information.
    
*   Pattern matching for suspicious files is basic and can be enhanced with more complex regex or integration with a malware scanning engine.





-----------


**License**
-----------

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Contributions**
-----------------

Feel free to contribute to this project by submitting a pull request or opening an issue. Please follow the contributing guidelines in `CONTRIBUTING.md`.
All suggestions for improving detection capabilities or adding new features are welcome!

### Additional Resources
- [pywin32 Documentation](https://github.com/mhammond/pywin32)
- [Understanding Windows Event Logs](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging)

-------------

# About Me

**Contact Me**
-----------

For any questions or issues, please contact:

*   **GitHub** - \[ https://github.com/ShreyaTejan ]
*   **LinkedIn** - \[ www.linkedin.com/in/shreya-tejan ]
    
