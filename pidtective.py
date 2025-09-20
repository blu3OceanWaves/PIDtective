#!/usr/bin/env python3
"""Process Ancestry Tracer - A Retrospective Process Analysis Tool
==============================================================
This tool analyzes process ancestry chains without requiring pre-installed monitoring.
It works by intelligently correlating information from various system sources that
naturally exist on Linux systems: /proc filesystem, system logs, and other artifacts.

Usage: python3 ancestry_tracer.py <PID> [options]

The tool follows a forensic detective approach - starting with what can be observed
and working backwards through available evidence to reconstruct the story of how
processes came to exist.
"""
import os
import sys
import re
import time
import json
import subprocess
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, namedtuple
from pathlib import Path

# Define our data structures to hold process information
ProcessInfo = namedtuple('ProcessInfo', [
    'pid', 'ppid', 'command', 'args', 'start_time',
    'uid', 'gid', 'status', 'source'])

class Colors:
    """ANSI color codes for better terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class EvidenceCollector:
    """
    Collects evidence about processes from various system sources.
    This class knows where Linux systems store process-related information
    and how to extract it reliably.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        # Track what evidence sources are available on this system
        self.available_sources = self._detect_available_sources()
        # Cache for boot time to avoid repeated calculations
        self._boot_time_cache = None

    def _detect_available_sources(self):
        """
        Detect what evidence sources exist on this system.
        Different Linux distributions have different logging setups,
        so we need to adapt to what's available.
        """
        sources = []

        # /proc filesystem - should be available on all Linux systems
        if os.path.exists('/proc'):
            sources.append('proc')

        # systemd journal - modern systems
        if (os.path.exists('/var/log/journal') or
            os.path.exists('/run/log/journal')):
            sources.append('systemd')

        # Traditional syslog
        if (os.path.exists('/var/log/syslog') or
            os.path.exists('/var/log/messages')):
            sources.append('syslog')

        # Authentication logs
        if (os.path.exists('/var/log/auth.log') or
            os.path.exists('/var/log/secure')):
            sources.append('auth')

        if self.verbose:
            print(f"Available evidence sources: {', '.join(sources)}")

        return sources

    def collect_running_processes(self):
        """
        Extract information about currently running processes.
        This gives us the current state that we'll work backwards from.
        """
        processes = {}
        proc_count = 0

        try:
            # Iterate through all process directories in /proc
            for pid_dir in os.listdir('/proc'):
                if not pid_dir.isdigit():
                    continue

                pid = int(pid_dir)
                proc_info = self._extract_proc_info(pid)
                if proc_info:
                    processes[pid] = proc_info
                    proc_count += 1

            if self.verbose:
                print(f"Collected information for {proc_count} running processes")

        except (OSError, IOError) as e:
            print(f"{Colors.WARNING}Warning: Error reading /proc: {e}{Colors.ENDC}")

        return processes

    def _extract_proc_info(self, pid):
        """
        Extract detailed information about a specific process from /proc.
        This function handles the various files in /proc/<pid>/ and deals
        gracefully with processes that might disappear during analysis.
        """
        try:
            proc_path = f'/proc/{pid}'

            # Read the status file for basic process information
            # This file contains structured information about the process
            status_info = {}
            try:
                with open(f'{proc_path}/status', 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            status_info[key.strip()] = value.strip()
            except (OSError, IOError):
                return None

            # Read the command line arguments
            # These are stored null-separated, so we need to clean them up
            cmdline = ""
            try:
                with open(f'{proc_path}/cmdline', 'r') as f:
                    cmdline = f.read().replace('\0', ' ').strip()
                    if not cmdline:
                        # Some processes (like kernel threads) have no cmdline
                        cmdline = f"[{status_info.get('Name', 'unknown')}]"
            except (OSError, IOError):
                cmdline = f"[{status_info.get('Name', 'unknown')}]"

            # Get process start time from stat file
            # This requires some calculation based on system boot time
            start_time = self._get_process_start_time(proc_path)

            return ProcessInfo(
                pid=pid,
                ppid=int(status_info.get('PPid', '0')),
                command=status_info.get('Name', 'unknown'),
                args=cmdline,
                start_time=start_time,
                uid=int(status_info.get('Uid', '0').split()[0]),
                gid=int(status_info.get('Gid', '0').split()[0]),
                status=status_info.get('State', 'unknown'),
                source='proc'
            )

        except (OSError, IOError, ValueError, IndexError):
            # Process might have disappeared while we were reading it
            # This is normal and happens frequently
            return None

    def _get_process_start_time(self, proc_path):
        """
        Calculate the actual start time of a process.
        Linux stores this as clock ticks since boot, so we need to convert it.
        """
        try:
            with open(f'{proc_path}/stat', 'r') as f:
                stat_fields = f.read().split()
                # Field 21 (index 21) is start time in clock ticks since boot
                start_time_ticks = int(stat_fields[21])

            # Get system boot time and calculate actual start time
            boot_time = self._get_boot_time()
            clock_ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
            start_time = boot_time + (start_time_ticks / clock_ticks_per_sec)

            return datetime.fromtimestamp(start_time)

        except (OSError, IOError, ValueError, IndexError):
            # If we can't get the start time, use current time as fallback
            return datetime.now()

    def _get_boot_time(self):
        """
        Get system boot time for calculating process start times.
        We cache this since it doesn't change during program execution.
        """
        if self._boot_time_cache is not None:
            return self._boot_time_cache

        try:
            with open('/proc/stat', 'r') as f:
                for line in f:
                    if line.startswith('btime '):
                        self._boot_time_cache = float(line.split()[1])
                        return self._boot_time_cache
        except (OSError, IOError):
            pass

        # Fallback to current time if we can't read boot time
        self._boot_time_cache = time.time()
        return self._boot_time_cache

class HistoricalEvidenceCollector:
    """
    Collects historical evidence about processes from log files and other sources.
    This is where the tool becomes powerful - finding traces of processes that
    are no longer running by intelligently searching through system logs.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        # Different log parsers for different types of log files
        self.log_parsers = {
            'systemd': self._parse_systemd_journal,
            'syslog': self._parse_syslog,
            'auth': self._parse_auth_logs
        }

    def collect_recent_process_events(self, hours_back=24):
        """
        Collect process-related events from the last N hours.
        This gives us the historical context needed to understand
        how current processes came to exist.
        """
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        all_events = []

        if self.verbose:
            print(f"Collecting historical events from last {hours_back} hours...")

        # Try systemd journal first (modern systems prefer this)
        if self._has_systemd():
            try:
                events = self._parse_systemd_journal(cutoff_time)
                all_events.extend(events)
                if self.verbose:
                    print(f"Found {len(events)} events in systemd journal")
            except Exception as e:
                if self.verbose:
                    print(f"Error reading systemd journal: {e}")
        
        # Parse traditional log files as backup/supplement
        try:
            syslog_events = self._parse_syslog(cutoff_time)
            all_events.extend(syslog_events)
            if self.verbose:
                print(f"Found {len(syslog_events)} events in syslog")
        except Exception as e:
            if self.verbose:
                print(f"Error reading syslog: {e}")

        # Sort all events by timestamp for timeline analysis
        return sorted(all_events, key=lambda x: x.get('timestamp', cutoff_time))

    def _has_systemd(self):
        """Check if systemd is available on this system"""
        try:
            result = subprocess.run(['systemctl', '--version'],
                                   capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _parse_systemd_journal(self, since_time):
        """
        Extract process events from systemd journal.
        systemd's structured logging makes this relatively straightforward
        since it captures process metadata automatically.
        """
        events = []

        try:
            # Use journalctl to get structured log data in JSON format
            cmd = [
                'journalctl',
                '--output=json',
                '--since', since_time.isoformat(),
                '--no-pager',
                '--quiet'  # Reduce noise
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return events

            # Parse each JSON line from journalctl output
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)

                    # Look for process-related entries
                    if self._is_process_event(entry):
                        event = self._extract_process_event_info(entry)
                        if event:
                            events.append(event)

                except json.JSONDecodeError:
                    continue

        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return events

    def _is_process_event(self, journal_entry):
        """
        Determine if a journal entry relates to process activity.
        We look for various indicators that suggest process creation,
        execution, or termination events.
        """
        message = journal_entry.get('MESSAGE', '').lower()
        unit = journal_entry.get('_SYSTEMD_UNIT', '').lower()

        # Look for process-related keywords in the message
        process_indicators = [
            'started', 'stopped', 'spawned', 'executed', 'launched',
            'fork', 'exec', 'exit', 'killed', 'terminated',
            'process', 'command', 'binary'
        ]

        # Check if message contains process-related terms
        message_match = any(indicator in message for indicator in process_indicators)

        # Some systemd units are inherently process-related
        service_match = any(svc in unit for svc in ['service', 'timer', 'target'])

        return message_match or service_match

    def _extract_process_event_info(self, journal_entry):
        """
        Extract structured information from a process-related journal entry.
        systemd provides rich metadata that we can use for correlation.
        """
        try:
            # Convert systemd's microsecond timestamp to datetime
            timestamp_usec = int(journal_entry.get('__REALTIME_TIMESTAMP', 0))
            timestamp = datetime.fromtimestamp(timestamp_usec / 1000000)

            return {
                'timestamp': timestamp,
                'pid': journal_entry.get('_PID'),
                'command': journal_entry.get('_COMM'),
                'message': journal_entry.get('MESSAGE', ''),
                'uid': journal_entry.get('_UID'),
                'systemd_unit': journal_entry.get('_SYSTEMD_UNIT', ''),
                'source': 'systemd-journal'
            }
        except (ValueError, TypeError):
            return None

    def _parse_syslog(self, since_time):
        """
        Parse traditional syslog files for process-related events.
        This is more challenging than systemd since syslog is unstructured,
        but it provides compatibility with older systems.
        """
        events = []

        # Common syslog locations
        syslog_paths = ['/var/log/syslog', '/var/log/messages']

        for log_path in syslog_paths:
            if not os.path.exists(log_path):
                continue

            try:
                with open(log_path, 'r') as f:
                    for line in f:
                        event = self._parse_syslog_line(line, since_time)
                        if event:
                            events.append(event)
            except (OSError, IOError):
                continue

        return events

    def _parse_syslog_line(self, line, since_time):
        """
        Parse a single syslog line looking for process-related information.
        Syslog format varies, but we can extract useful information using patterns.
        """
        # Basic syslog pattern: timestamp hostname program[pid]: message
        syslog_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[\]]+)(\[(\d+)\])?\s*:\s*(.+)'

        match = re.match(syslog_pattern, line.strip())
        if not match:
            return None

        try:
            # Parse timestamp (syslog doesn't include year, so assume current year)
            timestamp_str = match.group(1)
            current_year = datetime.now().year
            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")

            # Skip events outside our time window
            if timestamp < since_time:
                return None

            hostname = match.group(2)
            program = match.group(3)
            pid = match.group(5)  # May be None
            message = match.group(6)

            # Look for process-related keywords in the message
            if not self._contains_process_keywords(message):
                return None

            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'program': program,
                'pid': int(pid) if pid else None,
                'message': message,
                'source': 'syslog'
            }

        except (ValueError, AttributeError):
            return None

    def _contains_process_keywords(self, message):
        """Check if a message contains process-related keywords"""
        keywords = [
            'started', 'stopped', 'killed', 'terminated', 'spawned',
            'exec', 'fork', 'exit', 'process', 'command'
        ]
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in keywords)

    def _parse_auth_logs(self, since_time):
        """Parse authentication logs for process-related security events"""
        # This could be extended to parse auth logs for sudo, su, etc.
        # For now, we'll keep it simple
        return []

class ProcessCorrelationEngine:
    """
    The core of our tool - correlates evidence from multiple sources to
    reconstruct process ancestry chains. This is where raw data becomes
    actionable intelligence.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.process_cache = {}
        self.timeline_events = []
        # Threshold for considering evidence reliable enough to include
        self.correlation_confidence_threshold = 0.6

    def analyze_process_ancestry(self, target_pid, evidence_sources):
        """
        Main entry point for analyzing process ancestry.
        This coordinates all the analysis steps and returns comprehensive results.
        """
        if self.verbose:
            print(f"{Colors.HEADER}Starting correlation analysis for PID {target_pid}{Colors.ENDC}")

        current_processes = evidence_sources.get('running_processes', {})
        historical_events = evidence_sources.get('historical_events', [])

        # Start with the target process and work backwards through parents
        ancestry_chain = []
        if target_pid in current_processes:
            ancestry_chain = self._build_running_ancestry(target_pid, current_processes)
            if self.verbose:
                print(f"Built ancestry chain with {len(ancestry_chain)} processes")
        else:
            if self.verbose:
                print(f"Target PID {target_pid} not found in running processes. "
                      f"Attempting to find historical evidence.")

        # Enhance ancestry chain with historical information
        enhanced_chain = self._enhance_with_historical_data(ancestry_chain, historical_events)

        # Look for related processes (siblings, children, etc.)
        related_processes = self._find_related_processes(target_pid, evidence_sources)

        # Build a timeline of relevant events
        timeline = self._build_timeline(enhanced_chain, related_processes, historical_events)

        # Calculate overall confidence in our analysis
        confidence = self._calculate_analysis_confidence(enhanced_chain, historical_events)

        return {
            'ancestry_chain': enhanced_chain,
            'related_processes': related_processes,
            'timeline': timeline,
            'analysis_confidence': confidence,
            'evidence_summary': self._generate_evidence_summary(evidence_sources)
        }

    def _build_running_ancestry(self, pid, processes):
        """
        Build ancestry chain from currently running processes.
        This gives us the backbone of our analysis - the direct parent-child chain.
        """
        chain = []
        current_pid = pid
        visited_pids = set()  # Prevent infinite loops in case of corrupted data

        while current_pid != 0 and current_pid not in visited_pids:
            if current_pid not in processes:
                # Parent process is no longer running
                break

            process_info = processes[current_pid]
            chain.append({
                'pid': current_pid,
                'process_info': process_info,
                'confidence': 1.0,  # High confidence for running processes
                'evidence_sources': ['proc'],
                'relationship': 'parent' if len(chain) > 0 else 'target'
            })

            visited_pids.add(current_pid)
            current_pid = process_info.ppid

        # Reverse so the chain goes from root ancestor to target
        return list(reversed(chain))

    def _enhance_with_historical_data(self, ancestry_chain, historical_events):
        """
        Enhance ancestry chain with historical log data.
        This adds context and fills in gaps for processes that may have terminated.
        """
        enhanced_chain = []

        # If the ancestry chain is empty (target not running), try to find it historically
        if not ancestry_chain:
            # We'll just look for the most relevant historical events for the target PID
            # The correlation engine will find these based on pid, command etc.
            return []

        for chain_entry in ancestry_chain:
            enhanced_entry = dict(chain_entry)
            pid = chain_entry['pid']
            process_info = chain_entry['process_info']

            # Look for historical events that correlate with this process
            related_events = self._find_related_historical_events(
                pid, process_info, historical_events
            )

            if related_events:
                enhanced_entry['historical_events'] = related_events
                enhanced_entry['evidence_sources'] = list(enhanced_entry['evidence_sources'])
                if 'historical_logs' not in enhanced_entry['evidence_sources']:
                    enhanced_entry['evidence_sources'].append('historical_logs')

                # Try to get more accurate start time from logs
                log_start_time = self._extract_start_time_from_events(related_events)
                if log_start_time:
                    enhanced_entry['log_start_time'] = log_start_time
                    # Adjust confidence if log time differs significantly from proc time
                    time_diff = abs((log_start_time - process_info.start_time).total_seconds())
                    if time_diff > 60:  # More than 1 minute difference
                        enhanced_entry['confidence'] *= 0.9

            enhanced_chain.append(enhanced_entry)

        return enhanced_chain

    def _find_related_historical_events(self, pid, process_info, events):
        """
        Find historical events that likely relate to a specific process.
        This uses multiple correlation techniques to build confidence.
        """
        related_events = []

        # Create a time window around the process start time
        process_start = process_info.start_time
        time_window = timedelta(minutes=10)  # 10 minute window for correlation

        for event in events:
            event_time = event.get('timestamp')
            if not event_time:
                continue

            # Skip events outside our time window
            time_diff = abs((event_time - process_start).total_seconds())
            if time_diff > time_window.total_seconds():
                continue

            # Calculate how confident we are that this event relates to our process
            confidence = self._calculate_event_correlation_confidence(
                pid, process_info, event
            )

            if confidence > self.correlation_confidence_threshold:
                related_events.append({
                    'event': event,
                    'correlation_confidence': confidence,
                    'time_difference_seconds': time_diff
                })

        # Sort by confidence, then by time proximity
        related_events.sort(key=lambda x: (x['correlation_confidence'],
                                          -x['time_difference_seconds']),
                            reverse=True)

        return related_events[:5]  # Keep top 5 most relevant events

    def _calculate_event_correlation_confidence(self, pid, process_info, event):
        """
        Calculate confidence that an event relates to a specific process.
        This uses multiple signals to build a composite confidence score.
        """
        confidence = 0.0

        # Direct PID match gives highest confidence
        event_pid = event.get('pid')
        if event_pid == pid:
            confidence += 0.7

        # Command name matching
        event_command = event.get('command', '').lower()
        process_command = process_info.command.lower()

        if event_command and event_command == process_command:
            confidence += 0.3
        elif event_command and process_command in event_command:
            confidence += 0.2
        elif event_command and event_command in process_command:
            confidence += 0.1

        # User ID matching
        event_uid = event.get('uid')
        if event_uid is not None and event_uid == process_info.uid:
            confidence += 0.1

        # Message content analysis - look for process-related terms
        message = event.get('message', '').lower()
        if any(term in message for term in ['started', 'launched', 'executed']):
            confidence += 0.1

        # Command line argument matching in message
        if process_info.args and len(process_info.args) > 10:
            # Extract key parts of command line for matching
            args_parts = process_info.args.split()
            if len(args_parts) > 1:
                # Look for script names, file paths, etc. in the message
                for arg in args_parts[1:3]:  # Check first couple of arguments
                    if len(arg) > 3 and arg in message:
                        confidence += 0.05

        return min(confidence, 1.0)  # Cap at 1.0

    def _extract_start_time_from_events(self, related_events):
        """Extract the most likely start time from related events"""
        if not related_events:
            return None

        # Look for events that specifically mention process start
        start_events = []
        for event_data in related_events:
            event = event_data['event']
            message = event.get('message', '').lower()
            if any(term in message for term in ['started', 'launched', 'began']):
                start_events.append(event)

        if start_events:
            # Return the timestamp of the most confident start event
            return start_events[0].get('timestamp')

        return None

    def _find_related_processes(self, target_pid, evidence_sources):
        """
        Find processes related to the target (children, siblings, etc.).
        This helps understand the broader context of process activity.
        """
        related = []
        current_processes = evidence_sources.get('running_processes', {})

        if target_pid not in current_processes:
            return related

        target_process = current_processes[target_pid]

        # Find child processes
        for pid, proc_info in current_processes.items():
            if proc_info.ppid == target_pid:
                related.append({
                    'pid': pid,
                    'command': proc_info.command,
                    'args': proc_info.args,
                    'relationship': 'child',
                    'start_time': proc_info.start_time
                })

        # Find sibling processes (same parent)
        if target_process.ppid != 0:
            for pid, proc_info in current_processes.items():
                if (proc_info.ppid == target_process.ppid and
                    pid != target_pid and
                    pid != target_process.ppid):
                    related.append({
                        'pid': pid,
                        'command': proc_info.command,
                        'args': proc_info.args,
                        'relationship': 'sibling',
                        'start_time': proc_info.start_time
                    })

        return related

    def _build_timeline(self, ancestry_chain, related_processes, historical_events):
        """Build a chronological timeline of relevant events"""
        timeline_events = []

        # Add process start events from ancestry chain
        for entry in ancestry_chain:
            proc_info = entry['process_info']
            timeline_events.append({
                'timestamp': proc_info.start_time,
                'type': 'process_start',
                'description': f"Process {proc_info.pid} ({proc_info.command}) started",
                'pid': proc_info.pid,
                'confidence': entry['confidence']
            })

        # Add related process events
        for related in related_processes:
            timeline_events.append({
                'timestamp': related['start_time'],
                'type': 'related_process',
                'description': f"{related['relationship'].title()} process {related['pid']} ({related['command']}) started",
                'pid': related['pid'],
                'confidence': 0.8
            })

        # Add relevant historical events
        for event in historical_events[:20]:  # Limit to prevent overwhelm
            timeline_events.append({
                'timestamp': event.get('timestamp'),
                'type': 'historical_event',
                'description': event.get('message', 'Unknown event'),
                'source': event.get('source', 'unknown'),
                'confidence': 0.6
            })

        # Sort chronologically
        timeline_events.sort(key=lambda x: x.get('timestamp', datetime.min))

        return timeline_events

    def _calculate_analysis_confidence(self, ancestry_chain, historical_events):
        """Calculate overall confidence in our analysis"""
        if not ancestry_chain:
            return 0.0

        # Base confidence on the confidence of individual chain elements
        total_confidence = sum(entry['confidence'] for entry in ancestry_chain)
        avg_confidence = total_confidence / len(ancestry_chain)

        # Boost confidence if we have supporting historical evidence
        historical_support = len([entry for entry in ancestry_chain
                                 if 'historical_events' in entry and entry['historical_events']])

        if historical_support > 0:
            boost = min(0.2, historical_support * 0.05)
            avg_confidence += boost

        return min(avg_confidence, 1.0)

    def _generate_evidence_summary(self, evidence_sources):
        """Generate a summary of available evidence"""
        summary = {}

        running_procs = evidence_sources.get('running_processes', {})
        summary['running_processes_count'] = len(running_procs)

        historical = evidence_sources.get('historical_events', [])
        summary['historical_events_count'] = len(historical)

        # Categorize historical events by source
        source_counts = defaultdict(int)
        for event in historical:
            source = event.get('source', 'unknown')
            source_counts[source] += 1

        summary['historical_sources'] = dict(source_counts)

        return summary

class ProcessAncestryAnalyzer:
    """
    Main analyzer class that coordinates all components and produces the final report.
    This is the user-facing interface that brings everything together.
    """

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.evidence_collector = EvidenceCollector(verbose)
        self.historical_collector = HistoricalEvidenceCollector(verbose)
        self.correlation_engine = ProcessCorrelationEngine(verbose)

    def analyze_process(self, target_pid, hours_back=24):
        """
        Main analysis pipeline. This method orchestrates the entire process
        from data collection to correlation and report generation.
        """
        if self.verbose:
            print(f"{Colors.HEADER}Starting analysis for PID {target_pid}{Colors.ENDC}")

        # Step 1: Collect evidence from various sources
        running_processes = self.evidence_collector.collect_running_processes()
        historical_events = self.historical_collector.collect_recent_process_events(hours_back)

        evidence_sources = {
            'running_processes': running_processes,
            'historical_events': historical_events
        }

        # Step 2: Correlate evidence and build the analysis
        analysis_results = self.correlation_engine.analyze_process_ancestry(
            target_pid, evidence_sources
        )

        # Step 3: Display the results to the user
        self._display_results(target_pid, analysis_results)

    def _display_results(self, target_pid, results):
        """
        Formats and prints the final analysis report to the console.
        """
        print(f"\n{Colors.BOLD}--- Process Ancestry Report for PID {target_pid} ---{Colors.ENDC}")

        ancestry_chain = results.get('ancestry_chain', [])
        related_processes = results.get('related_processes', [])
        timeline = results.get('timeline', [])
        confidence = results.get('analysis_confidence', 0.0)
        summary = results.get('evidence_summary', {})

        # Display Summary
        print(f"\n{Colors.UNDERLINE}Evidence Summary:{Colors.ENDC}")
        print(f"  - Running Processes Scanned: {summary.get('running_processes_count', 'N/A')}")
        print(f"  - Historical Events Collected: {summary.get('historical_events_count', 'N/A')}")
        for source, count in summary.get('historical_sources', {}).items():
            print(f"    - {source.title()} Logs: {count} events")
        print(f"  - Analysis Confidence: {confidence:.2f} (1.00 = High Confidence)")

        # Display Ancestry Chain
        print(f"\n{Colors.UNDERLINE}Ancestry Chain:{Colors.ENDC}")
        if not ancestry_chain:
            print(f"{Colors.WARNING}  No running ancestry chain found for PID {target_pid}.{Colors.ENDC}")
            print("  This may indicate the process is a transient one or has already terminated.")
            print("  Check the historical events section for possible clues.")
        else:
            for i, entry in enumerate(ancestry_chain):
                proc_info = entry['process_info']
                prefix = "└── " if i == len(ancestry_chain) - 1 else "├── "
                print(f"  {prefix}{Colors.OKBLUE}PID {proc_info.pid}{Colors.ENDC} (PPID: {proc_info.ppid})")
                print(f"      {Colors.OKGREEN}Command:{Colors.ENDC} {proc_info.args}")
                print(f"      {Colors.OKCYAN}Start Time:{Colors.ENDC} {proc_info.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"      {Colors.WARNING}Confidence:{Colors.ENDC} {entry['confidence']:.2f}")

                if entry.get('historical_events'):
                    print(f"      {Colors.OKBLUE}Historical Correlates:{Colors.ENDC}")
                    for event_data in entry['historical_events']:
                        event = event_data['event']
                        print(f"        - {event['source']}: '{event['message']}' (Confidence: {event_data['correlation_confidence']:.2f})")

        # Display Related Processes
        print(f"\n{Colors.UNDERLINE}Related Processes:{Colors.ENDC}")
        if not related_processes:
            print("  No related processes (children or siblings) found.")
        else:
            for proc in related_processes:
                print(f"  - {proc['relationship'].title()}: PID {proc['pid']} ({proc['command']})")
                print(f"    {Colors.OKCYAN}Start Time:{Colors.ENDC} {proc['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")

        # Display Timeline
        print(f"\n{Colors.UNDERLINE}Chronological Timeline:{Colors.ENDC}")
        for event in timeline:
            timestamp = event.get('timestamp', datetime.min).strftime('%Y-%m-%d %H:%M:%S')
            source = event.get('source', '')
            description = event.get('description', '')
            pid = event.get('pid', 'N/A')
            
            # Highlight the PID if it's the target PID
            pid_str = f"{Colors.OKGREEN}PID {pid}{Colors.ENDC}" if pid == target_pid else f"PID {pid}"
            
            print(f"  - [{timestamp}] {pid_str} ({event['type']}): {description}")

        print(f"\n{Colors.BOLD}--- End of Report ---{Colors.ENDC}\n")


def main():
    """
    Main function to parse arguments and run the analysis.
    """
    banner = f"""
    ___    ___     ___     _                       _        _                    
   │ _ ╲  │_ _│   │   ╲   │ │_     ___     __     │ │_     (_)    __ __    ___   
   │  _╱   │ │    │ │) │  │  _│   ╱ ─_)   ╱ _│    │  _│    │ │    ╲ V ╱   ╱ ─_)  
  _│_│_   │___│   │___╱   _╲__│   ╲___│   ╲__│_   _╲__│   _│_│_   _╲_╱_   ╲___│  
_│     │_│     │_│     │_│     │_│     │_│     │_│     │_│     │_│     │_│     │ 
"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─'"`─0─0─' 
    """
    print(banner)
    parser = argparse.ArgumentParser(
        description="Analyze a process's ancestry and historical context.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        'pid',
        type=int,
        help="The Process ID (PID) of the target process to analyze."
    )
    parser.add_argument(
        '-H', '--hours-back',
        type=int,
        default=24,
        help="Number of hours to search back in historical logs (default: 24)."
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Enable verbose output for debugging."
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Check if we are running as root, as /proc/ and logs may not be readable otherwise
    if os.getuid() != 0:
        print(f"{Colors.WARNING}Warning: Not running as root. Some information may be inaccessible. "
              f"For best results, run with 'sudo'.{Colors.ENDC}")

    try:
        analyzer = ProcessAncestryAnalyzer(verbose=args.verbose)
        analyzer.analyze_process(args.pid, hours_back=args.hours_back)
    except Exception as e:
        print(f"{Colors.FAIL}An error occurred during analysis: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
