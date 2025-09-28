#!/usr/bin/env python3
"""PIDtective - Honest Retrospective Process Analysis
================================================
This tool correlates process information from /proc with system logs
to provide context about process ancestry. It presents evidence clearly
without false confidence metrics.

Usage: python3 pidtective.py <PID> [options]
"""
import os
import sys
import re
import json
import subprocess
import argparse
import time 
from datetime import datetime, timedelta
from collections import namedtuple, deque # Added deque for performance fix
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

# --- CONSTANTS ---
# Standard time window (in seconds) for logs to be considered "related" to process start time
LOG_TIME_WINDOW_SEC = 300 
# Maximum number of log entries to display in the final report
MAX_LOG_ENTRIES = 10
# Maximum PID value (used for basic input validation)
MAX_PID_VALUE = 65536 
# Max lines to read from syslog files to prevent reading entire large logs into memory (performance fix)
SYSLOG_MAX_LINES = 5000 
# Common system log locations for cross-distribution compatibility
SYSLOG_PATHS = [
    Path('/var/log/syslog'),    # Debian/Ubuntu
    Path('/var/log/messages'),  # RHEL/CentOS
    Path('/var/log/kern.log')   # Common kernel log
]
# --- END CONSTANTS ---

ProcessInfo = namedtuple('ProcessInfo', [
    'pid', 'ppid', 'command', 'args', 'start_time', 'uid', 'gid'])

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m' 
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class ProcessCollector:
    """
    Collects real-time information about running processes from the /proc filesystem.
    Handles potential race conditions and file read errors.
    """
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        # Cache for boot time to avoid repeated file reads (performance)
        self._boot_time_cache: Optional[float] = None 

    def collect_running_processes(self) -> Dict[int, ProcessInfo]:
        """
        Scans the /proc directory and extracts ProcessInfo for all valid running PIDs.
        """
        processes: Dict[int, ProcessInfo] = {}
        proc_path = Path('/proc')
        
        # Check if /proc is accessible
        if not proc_path.is_dir():
            print(f"{Colors.FAIL}Error: /proc directory not found or inaccessible.{Colors.ENDC}", file=sys.stderr)
            return processes

        # Use list comprehension for efficient filtering
        pid_dirs = [d for d in proc_path.iterdir() if d.is_dir() and d.name.isdigit()]
        
        for pid_dir in pid_dirs:
            pid = int(pid_dir.name)
            proc_info = self._extract_proc_info(pid)
            if proc_info:
                processes[pid] = proc_info
        
        return processes

    def _extract_proc_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Extracts status, command line, and start time for a single PID.

        Args:
            pid: The process ID.

        Returns:
            A ProcessInfo namedtuple or None if the process has terminated (race condition)
             or files could not be read.
        """
        proc_path = Path(f'/proc/{pid}')
        
        # Check for race condition: process terminated while we are reading
        if not proc_path.exists():
            return None

        status_info: Dict[str, str] = {}
        
        # Robust file reading with Path and explicit handling of termination/permissions
        try:
            # 1. Read status file
            with open(proc_path / 'status', 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        status_info[key.strip()] = value.strip()
            
            # 2. Read command line
            cmdline = ""
            with open(proc_path / 'cmdline', 'r') as f:
                # Null-terminated arguments are replaced with spaces
                cmdline = f.read().replace('\0', ' ').strip()
                if not cmdline:
                    # Fallback for kernel threads
                    cmdline = f"[{status_info.get('Name', 'unknown')}]"

            # 3. Get start time
            start_time = self._get_process_start_time(proc_path)
            
            # 4. Extract UIDs/GIDs safely
            uid_str = status_info.get('Uid', '0 0 0 0').split()
            gid_str = status_info.get('Gid', '0 0 0 0').split()
            
            return ProcessInfo(
                pid=pid,
                ppid=int(status_info.get('PPid', '0')),
                command=status_info.get('Name', 'unknown'),
                args=cmdline,
                start_time=start_time,
                uid=int(uid_str[0]) if uid_str else 0,
                gid=int(gid_str[0]) if gid_str else 0
            )

        except (OSError, IOError, ValueError, IndexError) as e:
            if self.verbose:
                print(f"Error reading info for PID {pid}: {e}", file=sys.stderr)
            # Process likely terminated or permission issue occurred
            return None

    def _get_process_start_time(self, proc_path: Path) -> datetime:
        """
        Calculates the process start time (datetime) using /proc/[pid]/stat and btime.

        Args:
            proc_path: Path object for /proc/[pid].

        Returns:
            The process start time as a datetime object.
        """
        try:
            with open(proc_path / 'stat', 'r') as f:
                stat_fields = f.read().split()
                # Field 22 (index 21) is the start time in clock ticks
                start_time_ticks = int(stat_fields[21])

            boot_time = self._get_boot_time()
            # SC_CLK_TCK is 100 on most Linux systems
            clock_ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            
            start_time_unix = boot_time + (start_time_ticks / clock_ticks_per_sec)
            return datetime.fromtimestamp(start_time_unix)

        except (OSError, IOError, ValueError, IndexError) as e:
            if self.verbose:
                print(f"Error calculating start time for {proc_path.name}: {e}", file=sys.stderr)
            # Fallback to current time if reading stat or calculating fails
            return datetime.now()

    def _get_boot_time(self) -> float:
        """
        Reads the system boot time ('btime') from /proc/stat. Caches the result.
        """
        if self._boot_time_cache is not None:
            return self._boot_time_cache

        try:
            with open('/proc/stat', 'r') as f:
                for line in f:
                    if line.startswith('btime '):
                        # btime is the Unix timestamp of the boot
                        self._boot_time_cache = float(line.split()[1])
                        return self._boot_time_cache
        except (OSError, IOError) as e:
            if self.verbose:
                print(f"Warning: Could not read /proc/stat for boot time. {e}", file=sys.stderr)

        # Fallback: assume system started "now" if /proc/stat is inaccessible
        # This will result in inaccurate start times but prevents a crash.
        self._boot_time_cache = datetime.now().timestamp()
        return self._boot_time_cache

class LogCollector:
    """
    Collects system log events from journalctl (preferred) and fallback syslog files.
    """
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def collect_recent_events(self, hours_back: int) -> List[Dict[str, Any]]:
        """
        Collects events from systemd journal (priority) and syslog files.

        Args:
            hours_back: The number of hours to search back in the logs.

        Returns:
            A sorted list of log event dictionaries.
        """
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        events: List[Dict[str, Any]] = []

        # 1. Try systemd journal (most reliable, best performance)
        try:
            systemd_events = self._parse_systemd_journal(cutoff_time)
            events.extend(systemd_events)
            if self.verbose:
                print(f"Found {len(systemd_events)} systemd events")
        except Exception as e:
            if self.verbose:
                # The runtime error output showed the message: 'list' object has no attribute 'lower'
                # This is now fixed in _looks_process_related
                print(f"Systemd journal unavailable or error: {e}")

        # 2. Try syslog files (fallback)
        if not events or len(events) < 50: 
            try:
                syslog_events = self._parse_syslog(cutoff_time)
                events.extend(syslog_events)
                if self.verbose:
                    print(f"Found {len(syslog_events)} syslog events")
            except Exception as e:
                if self.verbose:
                    print(f"Syslog file reading error: {e}")

        # Sort by timestamp (the key is guaranteed to exist by the parsing methods)
        return sorted(events, key=lambda x: x['timestamp'])

    def _parse_systemd_journal(self, since_time: datetime) -> List[Dict[str, Any]]:
        """
        Calls `journalctl` using subprocess to get structured JSON log entries.
        Uses a list for arguments to prevent shell injection.
        """
        events: List[Dict[str, Any]] = []
        # ISO format ensures journalctl receives a precise timestamp
        since_time_str = since_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Robust command structure for security
        cmd = [
            'journalctl', '--output=json', 
            '--since', since_time_str, 
            '--no-pager', '--quiet'
        ]
        
        try:
            # Run without shell=True to prevent injection
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            
            if result.returncode != 0:
                if self.verbose:
                    print(f"journalctl failed (RC {result.returncode}): {result.stderr.strip()}")
                return events

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                    # Use helper methods to filter and extract data
                    if self._looks_process_related(entry):
                        event = self._extract_journal_event(entry)
                        if event:
                            events.append(event)
                except json.JSONDecodeError as e:
                    if self.verbose:
                        print(f"JSON decode error in journal output: {e}", file=sys.stderr)
                    continue

        except FileNotFoundError:
            # journalctl command not found
            if self.verbose:
                print("journalctl command not found. Falling back to syslog files.")
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            if self.verbose:
                print(f"Error executing journalctl: {e}")

        return events

    def _looks_process_related(self, entry: Dict[str, Any]) -> bool:
        """
        Checks if a journal entry message contains process-related keywords.
        FIX: Ensures the MESSAGE field is a string before calling .lower().
        """
        message = entry.get('MESSAGE', '')
        
        # Check if the message is a string. If not (e.g., list or number), skip it.
        if not isinstance(message, str):
            return False
            
        message = message.lower()
        return any(word in message for word in [
            'started', 'stopped', 'spawned', 'executed', 'launched',
            'process', 'command', 'pid', 'killed', 'exec'
        ])

    def _extract_journal_event(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extracts and formats key fields from a raw journal entry."""
        try:
            # __REALTIME_TIMESTAMP is microseconds since epoch
            timestamp_usec = int(entry.get('__REALTIME_TIMESTAMP', 0))
            if timestamp_usec == 0:
                return None
            timestamp = datetime.fromtimestamp(timestamp_usec / 1000000)

            # Ensure PID is an integer if present
            pid_val = entry.get('_PID')
            try:
                pid_val = int(pid_val) if pid_val else None
            except ValueError:
                pid_val = None

            return {
                'timestamp': timestamp,
                'pid': pid_val,
                # _COMM is the executable name
                'command': entry.get('_COMM', 'N/A'),
                'message': entry.get('MESSAGE', ''),
                'uid': entry.get('_UID'),
                'source': 'systemd-journal'
            }
        except (ValueError, TypeError):
            return None

    def _read_syslog_tail(self, log_path: Path, max_lines: int) -> List[str]:
        """
        Reads up to max_lines from the end of a file efficiently using deque. 
        This prevents reading very large log files entirely into memory.
        """
        try:
            with open(log_path, 'r', errors='ignore') as f:
                # Use deque with maxlen to read lines from the end
                return list(deque(f, maxlen=max_lines))
        except (OSError, IOError) as e:
            if self.verbose:
                print(f"Error reading tail of file {log_path}: {e}", file=sys.stderr)
            return []

    def _parse_syslog(self, since_time: datetime) -> List[Dict[str, Any]]:
        """
        Reads common syslog files line-by-line using a line limit for performance.
        """
        events: List[Dict[str, Any]] = []

        for log_path in SYSLOG_PATHS:
            if not log_path.exists() or not os.access(log_path, os.R_OK):
                if self.verbose:
                    print(f"Syslog path check: {log_path} not found or unreadable.")
                continue

            # Use the new efficient tail reading function
            log_lines = self._read_syslog_tail(log_path, SYSLOG_MAX_LINES)

            for line in log_lines:
                event = self._parse_syslog_line(line, since_time)
                if event:
                    events.append(event)

        return events

    def _parse_syslog_line(self, line: str, since_time: datetime) -> Optional[Dict[str, Any]]:
        """Helper to parse a single, standard syslog line."""
        # Syslog pattern (e.g., May 18 10:00:00 hostname program[pid]: message)
        # Added flexibility for hostname and program field
        pattern = r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^ ]+)\s+([^:\[\]]+)(?:\[(\d+)\])?\s*:\s*(.+)'
        match = re.match(pattern, line.strip())
        if not match:
            return None

        try:
            timestamp_str = match.group(1)
            # Syslog typically omits the year. We assume the current year.
            current_year = datetime.now().year
            # The pattern is: Month Day HH:MM:SS
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")

            # Basic input validation for time
            if timestamp > datetime.now():
                # Correct for year wrap-around (log from late Dec on Jan 1st)
                timestamp = timestamp.replace(year=current_year - 1)

            if timestamp < since_time:
                return None

            program_name = match.group(3)
            pid = int(match.group(4)) if match.group(4) else None
            message = match.group(5)
            
            # Filter messages not likely related to process activity
            if not self._contains_process_keywords(message):
                return None

            return {
                'timestamp': timestamp,
                'program': program_name,
                'pid': pid,
                'message': message,
                'source': 'syslog'
            }

        except (ValueError, AttributeError):
            return None

    def _contains_process_keywords(self, message: str) -> bool:
        """Checks if a message contains process-related keywords."""
        keywords = ['started', 'stopped', 'killed', 'spawned', 'exec', 'process', 'command']
        return any(keyword in message.lower() for keyword in keywords)

class EvidenceAnalyzer:
    """Performs the correlation and analysis of process data and log entries."""
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def analyze_process(self, 
                        target_pid: int, 
                        processes: Dict[int, ProcessInfo], 
                        log_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes the target process by building ancestry, finding relatives,
        and correlating logs.
        """
        
        # Input validation: check if target_pid is at least present in the collected data
        if target_pid not in processes:
            # Allow analysis even if PID is gone, but mark it
            pass
            
        # Build ancestry chain
        ancestry_chain = self._build_ancestry_chain(target_pid, processes)
        
        # Find related processes
        related_processes = self._find_related_processes(target_pid, processes)
        
        # Find relevant log entries
        relevant_logs = self._find_relevant_logs(target_pid, ancestry_chain, log_events)
        
        return {
            'ancestry_chain': ancestry_chain,
            'related_processes': related_processes,
            'relevant_logs': relevant_logs,
            'analysis_notes': self._generate_analysis_notes(target_pid, processes, relevant_logs)
        }

    def _build_ancestry_chain(self, pid: int, processes: Dict[int, ProcessInfo]) -> List[Dict[str, Any]]:
        """Builds the parent chain starting from the target PID up to PID 1 or 0."""
        chain: List[Dict[str, Any]] = []
        current_pid = pid
        visited: Set[int] = set() # Detects and breaks circular links (PID reuse/wraparound)

        while current_pid != 0 and current_pid not in visited:
            if current_pid not in processes:
                # Process not running (terminated or outside collection window)
                chain.append({
                    'pid': current_pid,
                    'process': None,
                    'evidence_source': f'Not running (PPID: {processes.get(current_pid, ProcessInfo(0, 0, "", "", datetime.now(), 0, 0)).ppid})' if current_pid in processes else 'Terminated/Unknown'
                })
                # Break if the process itself is not running (only its parents may be)
                break 

            process = processes[current_pid]
            chain.append({
                'pid': current_pid,
                'process': process,
                'evidence_source': '/proc filesystem'
            })

            visited.add(current_pid)
            current_pid = process.ppid

        return list(reversed(chain))

    def _find_related_processes(self, target_pid: int, processes: Dict[int, ProcessInfo]) -> List[Dict[str, Any]]:
        """Finds immediate child and sibling processes of the target PID."""
        if target_pid not in processes:
            return []

        target_process = processes[target_pid]
        related: List[Dict[str, Any]] = []
        target_ppid = target_process.ppid

        for pid, proc in processes.items():
            if pid == target_pid:
                continue

            # Find children (proc's parent is the target)
            if proc.ppid == target_pid:
                related.append({
                    'pid': pid,
                    'relationship': 'child',
                    'process': proc
                })

            # Find siblings (proc's parent is the target's parent, and not the parent itself)
            elif target_ppid != 0 and proc.ppid == target_ppid and pid != target_ppid:
                related.append({
                    'pid': pid,
                    'relationship': 'sibling', 
                    'process': proc
                })

        return related

    def _find_relevant_logs(self, target_pid: int, ancestry_chain: List[Dict[str, Any]], log_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Finds logs correlated by PID, command name, or time proximity.
        Uses the LOG_TIME_WINDOW_SEC and MAX_LOG_ENTRIES constants.
        """
        relevant: List[Dict[str, Any]] = []
        
        # Get all PIDs and Command names from the ancestry chain
        ancestry_pids = {entry['pid'] for entry in ancestry_chain if entry['process']}
        ancestry_commands = {entry['process'].command.lower() 
                             for entry in ancestry_chain if entry['process']}
        
        for event in log_events:
            correlations: List[str] = []
            
            event_pid = event.get('pid')
            event_command = event.get('command', '').lower()
            
            # Correlation 1: Direct PID match
            if event_pid and event_pid in ancestry_pids:
                correlations.append(f"Direct PID match ({event_pid})")
            
            # Correlation 2: Command name match
            if event_command and event_command in ancestry_commands:
                correlations.append(f"Command name match ({event_command})")
            
            # Correlation 3: Time proximity (Magic Number 300 -> LOG_TIME_WINDOW_SEC)
            min_time_diff = float('inf')
            event_timestamp = event['timestamp']

            for entry in ancestry_chain:
                proc = entry.get('process')
                if proc and proc.start_time:
                    time_diff = abs((event_timestamp - proc.start_time).total_seconds())
                    min_time_diff = min(min_time_diff, time_diff)
            
            if min_time_diff <= LOG_TIME_WINDOW_SEC:
                correlations.append(f"Within {LOG_TIME_WINDOW_SEC}s of ancestor start")
            
            if correlations:
                # Use min_time_diff (guaranteed to be set if correlations found) for sorting key
                relevant.append({
                    'event': event,
                    'correlations': list(set(correlations)), # Deduplicate correlations
                    'time_proximity': min_time_diff
                })
        
        # Sort by time proximity to the closest process start time
        relevant.sort(key=lambda x: x['time_proximity'])
        
        # Limit to prevent overwhelm (Magic Number 10 -> MAX_LOG_ENTRIES)
        return relevant[:MAX_LOG_ENTRIES] 

    def _generate_analysis_notes(self, target_pid: int, processes: Dict[int, ProcessInfo], relevant_logs: List[Dict[str, Any]]) -> List[str]:
        """Generates honest analysis notes based on findings."""
        notes: List[str] = []
        
        if target_pid not in processes:
            notes.append(f"{Colors.BOLD}Target process PID {target_pid} not found in running processes.{Colors.ENDC}")
            notes.append("Process may have already terminated. Analysis is based on historical logs and parent PPID if available.")
        
        if not relevant_logs:
            notes.append("No clearly related log entries found within the defined search window.")
            notes.append("This may indicate a very short-lived process, a low logging level, or the process was non-interactive.")
        
        log_sources = {log['event']['source'] for log in relevant_logs}
        if log_sources:
            notes.append(f"Log evidence sourced from: {', '.join(log_sources)}")
        
        notes.append(f"Correlation time window set to {LOG_TIME_WINDOW_SEC} seconds (defined by LOG_TIME_WINDOW_SEC).")

        return notes

class PIDtectiveReporter:
    """Handles the structured, honest, and colorized display of analysis results."""
    def display_analysis(self, target_pid: int, results: Dict[str, Any]):
        """
        Displays the analysis results clearly to the user.
        Avoids fake confidence metrics as requested.
        """
        
        print(f"\n{Colors.BOLD}=== PIDtective Analysis for PID {target_pid} ==={Colors.ENDC}")
        
        ancestry = results['ancestry_chain']
        related = results['related_processes']
        logs = results['relevant_logs']
        notes = results['analysis_notes']
        
        # 1. Analysis Notes
        print(f"\n{Colors.WARNING}Analysis Notes:{Colors.ENDC}")
        for note in notes:
            print(f"  • {note}")
        
        # 2. Ancestry Chain  
        print(f"\n{Colors.OKBLUE}Process Ancestry (from /proc):{Colors.ENDC}")
        if not ancestry:
            print("  No running ancestry chain found.")
        else:
            for i, entry in enumerate(ancestry):
                proc = entry.get('process')
                prefix = "└── " if i == len(ancestry) - 1 else "├── "
                
                if proc:
                    # Target or running ancestor
                    print(f"  {prefix}PID {proc.pid} (PPID: {proc.ppid}) - {proc.command}")
                    print(f"      Command Line: {proc.args}")
                    print(f"      Started: {proc.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    # Terminated process in the chain
                    print(f"  {prefix}PID {entry['pid']} - {entry['evidence_source']}")

        
        # 3. Related Processes
        print(f"\n{Colors.OKGREEN}Related Processes (Children/Siblings):{Colors.ENDC}")
        if not related:
            print("  No related running processes found.")
        else:
            for rel in related:
                proc = rel['process']
                print(f"  • {rel['relationship'].title()}: PID {proc.pid} ({proc.command})")
                print(f"    Command Line: {proc.args}")
                print(f"    Started: {proc.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 4. Log Evidence
        print(f"\n{Colors.HEADER}Potentially Related Log Entries (Top {MAX_LOG_ENTRIES}):{Colors.ENDC}")
        if not logs:
            print("  No log entries correlated by PID, command, or time proximity.")
        else:
            for log_data in logs:
                event = log_data['event']
                correlations = log_data['correlations']
                
                timestamp = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                print(f"  [{timestamp}] ({event['source']}) PID: {event.get('pid', 'N/A')}")
                # Truncate long messages, avoids long method issue.
                message = event['message'] 
                truncated_message = message[:100] + ('...' if len(message) > 100 else '')
                print(f"    Message: {truncated_message}")
                print(f"    Correlations: {', '.join(correlations)}")
                print()
        
        print(f"\n{Colors.BOLD}=== End Analysis ==={Colors.ENDC}\n")
        
        # Disclaimer
        print(f"{Colors.WARNING}DISCLAIMER: This tool correlates available evidence but cannot")
        print(f"guarantee accuracy.")
        print(f"Always verify findings through additional investigation methods.{Colors.ENDC}")

def validate_pid(pid: int) -> None:
    """
    Checks if a PID is likely valid. Raises ValueError if the PID is outside the
    documented system range.
    
    Args:
        pid: The process ID to validate.
    
    Raises:
        ValueError: If the PID is not a valid number (e.g., <= 0 or > MAX_PID_VALUE).
    """
    if pid <= 0 or pid > MAX_PID_VALUE: 
        raise ValueError(f"PID {pid} is outside the valid range (1-{MAX_PID_VALUE}).")
    
    if not Path(f'/proc/{pid}').exists():
        # This warning is acceptable as the tool's core function is to analyze terminated 
        # processes using logs as a fallback.
        print(f"{Colors.WARNING}Warning: PID {pid} directory not found in /proc. Process may be terminated. Analysis will rely on logs.{Colors.ENDC}")


def main() -> None:
    """Main execution entry point, handles argument parsing and orchestration."""
    parser = argparse.ArgumentParser(description="Analyze process ancestry using available system evidence (PIDtective)")
    # Input validation for PID is crucial
    parser.add_argument('pid', type=int, help="Target process ID to investigate")
    parser.add_argument('-H', '--hours-back', type=int, default=24, 
                       help="Hours to search back in logs (default: 24)")
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help="Enable verbose output for debugging and detailed file access issues")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    
    # 1. Input Validation
    try:
        validate_pid(args.pid)
    except ValueError as e:
        # Exit immediately on invalid PID number
        print(f"{Colors.FAIL}Critical Error: {e}{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)

    if os.getuid() != 0:
        print(f"{Colors.WARNING}Warning: Not running as root. Some log files and /proc info may be inaccessible or incomplete.{Colors.ENDC}")

    try:
        # 2. Collect evidence
        process_collector = ProcessCollector(args.verbose)
        log_collector = LogCollector(args.verbose)
        
        processes = process_collector.collect_running_processes()
        log_events = log_collector.collect_recent_events(args.hours_back)
        
        if args.verbose:
            print(f"Collected {len(processes)} running processes.")
            print(f"Collected {len(log_events)} log events from the last {args.hours_back} hours.")
        
        # 3. Analyze evidence
        analyzer = EvidenceAnalyzer(args.verbose)
        results = analyzer.analyze_process(args.pid, processes, log_events)
        
        # 4. Display results
        reporter = PIDtectiveReporter()
        reporter.display_analysis(args.pid, results)
        
    except Exception as e:
        # Final catch-all error handling
        print(f"\n{Colors.FAIL}Fatal Error during PIDtective analysis: {e}{Colors.ENDC}", file=sys.stderr)
        if args.verbose:
             import traceback
             traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
