# PIDtective

*Retrospective process analysis without requiring pre-installed monitoring*

## What PIDtective Actually Does

PIDtective correlates running process data from `/proc` with system logs to provide context about how processes came to be. It presents available evidence clearly without making reliability claims about correlations.

**Core functionality:**
- Reads `/proc` filesystem to build process ancestry chains
- Searches systemd journal and syslog for process-related events  
- Shows correlations based on PID matches, command names, and timing proximity
- Displays evidence with clear reasoning for why entries might be related

**What it doesn't do:**
- Generate automated reports or IOC extraction
- Provide confidence scores or reliability metrics
- Monitor processes in real-time
- Replace comprehensive forensic tools

## Installation

```bash
git clone https://github.com/blu3OceanWaves/PIDtective.git
cd PIDtective
chmod +x pidtective.py
```

**Requirements:**
- Python 3.6+
- Linux system with `/proc` filesystem
- Root access recommended for complete log access

Uses only standard library modules - no external dependencies.

## Usage

```bash
# Basic analysis
sudo python3 pidtective.py <PID>

# Search further back in logs
sudo python3 pidtective.py <PID> --hours-back 48

# Verbose output showing collection details
sudo python3 pidtective.py <PID> -v
```

## Example Output

```
sudo python3 pidtective.py 2657

=== PIDtective Analysis for PID 2657 ===

Analysis Notes:
  • Log evidence sourced from: systemd-journal
  • Correlation time window set to 300 seconds

Process Ancestry (from /proc):
  ├── PID 1 (PPID: 0) - systemd
      Command Line: /sbin/init splash
      Started: 2025-09-27 15:55:19
  └── PID 2657 (PPID: 1) - udisksd
      Command Line: /usr/libexec/udisks2/udisksd
      Started: 2025-09-27 15:56:12

Potentially Related Log Entries (Top 10):
  [2025-09-27 15:56:12] (systemd-journal) PID: 1402
    Message: dbus-daemon[1402]: Successfully activated service...
    Correlations: Within 300s of ancestor start

DISCLAIMER: This tool correlates available evidence but cannot
guarantee accuracy. Always verify findings through additional
investigation methods.
```

## How Correlation Works

1. **Process Collection**: Scans `/proc` for all running processes and their metadata
2. **Log Parsing**: Searches systemd journal and syslog files for process-related events
3. **Evidence Correlation**: Matches log entries using:
   - Direct PID matches
   - Command name matches  
   - Events within 5 minutes of process start times
4. **Evidence Presentation**: Shows correlation reasoning without reliability scores

## Data Sources

**Live process data:**
- `/proc/<pid>/status` - Process metadata
- `/proc/<pid>/cmdline` - Command line arguments
- `/proc/<pid>/stat` - Process statistics and start time

**Historical log data:**
- `journalctl` output (systemd journal)
- `/var/log/syslog` (Debian/Ubuntu)
- `/var/log/messages` (RHEL/CentOS)

## Realistic Limitations

**Time sensitivity:**
- Most effective within 24-48 hours of process generation
- Depends entirely on system log retention configuration
- Older processes may have no discoverable log traces

**Log dependency:**
- Only finds processes that generated logged events
- Transient processes may leave minimal evidence
- Non-interactive system processes often generate few logs

**Access requirements:**
- Some `/proc` information requires root privileges
- Log files typically need elevated access
- May miss information without proper permissions

**Analysis scope:**
- Shows correlations, not definitive relationships
- Basic pattern matching may miss non-standard log formats
- Cannot verify if correlations represent actual causation

## When PIDtective is Useful

**Good scenarios:**
- Investigating suspicious processes discovered during incident response
- Understanding how system services started during boot
- Quick triage when comprehensive monitoring wasn't already running
- Learning process relationships on unfamiliar systems

**Not suitable for:**
- Real-time process monitoring
- Automated malware analysis pipelines
- High-volume forensic processing

## Comparison with Other Tools

| Tool | Strengths | Use Case |
|------|-----------|----------|
| **PIDtective** | No setup required, works retroactively | Ad-hoc investigation of discovered processes |
| **pstree** | Fast, reliable for current state | Quick process hierarchy visualization |
| **osquery** | Comprehensive, historical data | Enterprise monitoring and investigation |
| **ps aux** | Universal, accessible | Basic process listing and filtering |

PIDtective fills the gap between simple process listing tools and comprehensive monitoring solutions.

## Contact

For questions or feedback:

<a href="https://www.linkedin.com/in/yassin-el-wardioui-34016b332" target="_blank">
  <img src="https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" />
</a>
