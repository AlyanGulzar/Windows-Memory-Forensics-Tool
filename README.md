# Windows Memory Forensics Tool

This is a GUI-based memory forensics tool built with Python and Tkinter. It provides real-time insights into active processes, network connections, and loaded drivers on a Windows system. The tool is useful for digital forensics analysts, incident responders, and security researchers who need a quick way to inspect system activity.

---

## Features

- View all running processes with:
  - PID
  - Process name
  - Start time
  - Memory usage (MB)
  - CPU usage (%)

- View active network connections:
  - PID
  - Process name
  - Connection status
  - Local and remote IP:Port pairs

- Display all loaded drivers with:
  - Driver name
  - Description

- Save all collected information into a `.txt` file
- Refresh button to update all views in real-time

---

## Requirements

- Python 3.x
- Windows OS
- Administrator privileges (for some system-level access)

### Python Libraries:

Install required libraries using pip:

```bash
pip install psutil pymem
tkinter is included by default in most Python installations.
```
---
## How to Use

1. **Clone the repository or download the script.**

2. **Run the script:**

   ```bash
   python mem_forensics_windows.py
   ```

3. **Explore the Interface:**

   - Navigate through the tabs: `Processes`, `Network Connections`, and `Loaded Drivers`.
   - Use the `Refresh` button to update data.
   - Click `Save as File` to export a snapshot of the current view to a text file.

## Use Cases

- Quick triage during incident response
- Investigation of suspicious processes or drivers
- Network connection auditing during malware analysis
- Memory usage profiling

## Limitations

- Memory usage reporting via `pymem` may fail for some processes due to permission restrictions.
- Some fields may display `N/A` for system-protected or inaccessible processes.

  
