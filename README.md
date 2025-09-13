# PIDtective
## Overview

PIDtective is a powerful Linux forensic tool designed to reconstruct the ancestry and historical context of a process. By combining real-time data from running processes with historical log evidence, it provides a comprehensive view of process activity, related processes, and system events. The tool is especially useful for incident response, malware analysis, and forensic investigations.

## Features

- Live Process Analysis: Extracts detailed information from /proc, including PID, PPID, command, arguments, UID, GID, start time, and status.

- Historical Log Correlation: Parses systemd journal, syslog, and authentication logs to find past events related to processes.

- Ancestry Reconstruction: Builds parent-child process chains and fills gaps using historical events.

- Related Processes Detection: Identifies child processes, siblings, and other related processes for context.

- Chronological Timeline: Generates a timeline of process starts, historical events, and related processes.

- Confidence Scoring: Assigns confidence levels to ancestry and event correlations for reliability assessment.

- User-Friendly Output: Color-coded, structured terminal reports for readability.

- Extensible Architecture: Modular design allows easy integration of additional log sources or correlation methods.

## Requirements

- Python 3.8 or higher

- inux system with access to /proc and log files (/var/log/syslog, /var/log/messages, /var/log/auth.log, or systemd journal)

- Root privileges recommended for full access

## Usage

Run the tool with the target PID as the main argument:
```bash
sudo python3 process_ancestry_analyzer.py <PID>
```
### Optional arguments:
```bash
-H, --hours-back : Number of hours to search historical logs (default: 24)

-v, --verbose : Enable verbose output for debugging
```
- Example:
```bash
sudo python3 PIDtective.py 1234 -H 48 -v
```
## Output

The tool produces a detailed console report including:

Evidence Summary: Number of processes scanned and historical events collected.

Ancestry Chain: Parent-child relationships, command details, start times, and confidence scores.

Related Processes: Children and siblings of the target process.

Chronological Timeline: Ordered list of all relevant events for situational context.

## Use Cases

1. Incident response and forensic investigations

2. Malware or rootkit analysis

3. Process activity reconstruction for security audits

4. System behavior analysis and debugging

## Notes

- Running as root is recommended to access all processes and logs.

- Recently ended or short-duration processes may not appear in the running process chain but may be captured in historical events.

- Confidence scores help prioritize reliable correlations, but manual verification is recommended for critical investigations.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Consider adding support for additional log sources or enhancing correlation algorithms.
