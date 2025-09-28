# PIDtective
<img width="653" height="126" alt="image" src="https://github.com/user-attachments/assets/ca3788a7-89ed-4206-b82c-225d74c318e7" />

-A tool that reconstructs process parent-child relationships by reading `/proc` and parsing system logs.-

## What it does

- Reads `/proc/<pid>/` files to build process ancestry chains
- Searches systemd journal and syslog for process-related events
- Correlates log entries with running processes based on PID, command name, and timing
- Displays process hierarchies with start times and confidence scores

## Installation

```bash
git clone https://github.com/blu3OceanWaves/PIDtective.git
cd PIDtective
chmod +x pidtective.py
```

Requires Python 3.6+. Uses only standard library modules.

## Usage

```bash
# Basic usage
sudo python3 pidtective.py <PID>

# Search logs from last 48 hours
sudo python3 pidtective.py <PID> --hours-back 48

# Verbose output
sudo python3 pidtective.py <PID> -v
```

## Example output

```
sudo python3 pidtective.py -v 2657
                                                                                                                                                                                                     ─╯
Found 1196 systemd events
Collected 339 running processes.
Collected 1196 log events from the last 24 hours.

=== PIDtective Analysis for PID 2657 ===

Analysis Notes:
  • Log evidence sourced from: systemd-journal
  • Correlation time window set to 300 seconds (defined by LOG_TIME_WINDOW_SEC).

Process Ancestry (from /proc):
  ├── PID 1 (PPID: 0) - systemd
      Command Line: /sbin/init splash
      Started: 2025-09-27 15:55:19
  └── PID 2657 (PPID: 1) - udisksd
      Command Line: /usr/libexec/udisks2/udisksd
      Started: 2025-09-27 15:56:12

Related Processes (Children/Siblings):
  • Sibling: PID 522 (systemd-journal)
    Command Line: /usr/lib/systemd/systemd-journald
    Started: 2025-09-27 15:55:29
[...]

Potentially Related Log Entries (Top 10):
  [2025-09-27 15:56:12] (systemd-journal) PID: 1402
    Message: dbus-daemon[1402]: [session uid=125 pid=1402 pidfd=5] Successfully activated service 'org.freedeskto...
    Correlations: Within 300s of ancestor start
[...]


=== End Analysis ===

DISCLAIMER: This tool correlates available evidence but cannot
guarantee accuracy.
Always verify findings through additional investigation methods.

...
```

## How it works

1. **Process scanning**: Reads `/proc/<pid>/status`, `/proc/<pid>/cmdline`, and `/proc/<pid>/stat` for all running processes
2. **Log parsing**: Searches systemd journal (if available) and syslog files for process creation events
3. **Correlation**: Matches log entries to processes using PID, command name, user ID, and timing within a 10-minute window
4. **Confidence scoring**: Assigns reliability scores based on strength of evidence correlation

## Data sources

- `/proc` filesystem (running processes only)
- systemd journal (`journalctl` output)
- `/var/log/syslog` or `/var/log/messages`
- `/var/log/auth.log` (limited support)

## Limitations

- Historical analysis depends on log retention policies
- Terminated processes only visible in logs if they generated logged events
- Some `/proc` information requires root access
- Log parsing uses basic pattern matching - may miss events in non-standard formats
- Confidence scores are heuristic-based, not statistically validated

## Notes

- Run with `sudo` for complete system access
- Works best on processes created within the log retention window
- Does not require pre-installation or running daemons
- Output accuracy depends on system logging configuration
---
## Contact
For bugs, feedback, or questions, connect with me on LinkedIn:<br>
<br>
<a href="https://www.linkedin.com/in/yassin-el-wardioui-34016b332" target="_blank">
  <img src="https://img.shields.io/badge/LinkedIn-Connect%20with%20me-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=0077B5&color=004182" />
</a>
