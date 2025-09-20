# Process Ancestry Tracer

A tool that reconstructs process parent-child relationships by reading `/proc` and parsing system logs.

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
--- Process Ancestry Report for PID 1337 ---

Evidence Summary:
  - Running Processes Scanned: 342
  - Historical Events Collected: 23
  - Analysis Confidence: 1.0

Ancestry Chain:
├── PID 1 (PPID: 0)
    Command: /sbin/init
    Start Time: 2024-01-15 09:23:14
└── PID 1337 (PPID: 1)
    Command: /bin/bash script.sh
    Start Time: 2024-01-15 10:15:33
    Confidence: 1.0

Related Processes:
  - Child: PID 1338 (grep)
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
## Connect with me

<a href="https://www.linkedin.com/in/yassin-el-wardioui-34016b332" target="_blank">
  <img src="https://img.shields.io/badge/LinkedIn-Connect%20with%20me-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&labelColor=0077B5&color=004182" />
</a>
