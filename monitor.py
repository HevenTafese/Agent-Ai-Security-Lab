import yaml
import json
import logging
import os
from datetime import datetime

# Setup structured logging to file for Splunk ingestion
os.makedirs(os.path.expanduser("~/agent-security-lab/logs"), exist_ok=True)

log_handler = logging.FileHandler(
    os.path.expanduser("~/agent-security-lab/logs/agent_monitor.log")
)
log_handler.setFormatter(logging.Formatter('%(message)s'))

monitor_logger = logging.getLogger("agent_monitor")
monitor_logger.setLevel(logging.INFO)
monitor_logger.addHandler(log_handler)

class BehavioralMonitor:
    def __init__(self, policy_path):
        with open(os.path.expanduser(policy_path), 'r') as f:
            self.policy = yaml.safe_load(f)
        self.call_chain = []
        print(f"[MONITOR] Policy loaded from {policy_path}")

    def _log(self, tool_name, tool_input, verdict, reason, severity="INFO"):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "input": str(tool_input)[:300],
            "verdict": verdict,
            "reason": reason,
            "severity": severity,
            "chain_depth": len(self.call_chain)
        }
        monitor_logger.info(json.dumps(entry))
        status = "BLOCKED" if verdict == "BLOCKED" else "ALLOWED"
        print(f"[MONITOR] {status} | {tool_name} | {reason}")

    def _check_chain_limit(self, tool_name):
        self.call_chain.append(tool_name)
        limit = self.policy.get("chain", {}).get("max_sequential_calls", 5)
        if len(self.call_chain) > limit:
            return False, f"Tool chain exceeded limit of {limit} sequential calls"
        return True, "Chain depth within limit"

    def check_file_tool(self, filepath):
        policy = self.policy.get("file_tool", {})
        allowed_path = policy.get("allowed_base_path", "")
        
        # Check chain limit first
        allowed, reason = self._check_chain_limit("file_tool")
        if not allowed:
            self._log("file_tool", filepath, "BLOCKED", reason, "HIGH")
            return "BLOCKED", reason

        # Check for blocked keywords in filepath
        for keyword in policy.get("blocked_keywords", []):
            if keyword.lower() in filepath.lower():
                reason = f"Blocked keyword in filepath: '{keyword}'"
                self._log("file_tool", filepath, "BLOCKED", reason, "CRITICAL")
                return "BLOCKED", reason

        # Check for blocked path patterns
        for pattern in policy.get("blocked_path_patterns", []):
            if pattern in filepath:
                reason = f"Blocked path pattern detected: '{pattern}'"
                self._log("file_tool", filepath, "BLOCKED", reason, "HIGH")
                return "BLOCKED", reason

        self._log("file_tool", filepath, "ALLOWED", "Passed all policy checks", "INFO")
        return "ALLOWED", "Passed all policy checks"

    def check_web_tool(self, url):
        policy = self.policy.get("web_tool", {})

        allowed, reason = self._check_chain_limit("web_tool")
        if not allowed:
            self._log("web_tool", url, "BLOCKED", reason, "HIGH")
            return "BLOCKED", reason

        for pattern in policy.get("blocked_url_patterns", []):
            if pattern in url:
                reason = f"Blocked URL pattern: '{pattern}'"
                self._log("web_tool", url, "BLOCKED", reason, "HIGH")
                return "BLOCKED", reason

        self._log("web_tool", url, "ALLOWED", "Passed all policy checks", "INFO")
        return "ALLOWED", "Passed all policy checks"

    def check_code_tool(self, code):
        policy = self.policy.get("code_tool", {})

        allowed, reason = self._check_chain_limit("code_tool")
        if not allowed:
            self._log("code_tool", code[:100], "BLOCKED", reason, "HIGH")
            return "BLOCKED", reason

        for pattern in policy.get("blocked_patterns", []):
            if pattern in code:
                reason = f"Blocked code pattern: '{pattern}'"
                self._log("code_tool", code[:100], "BLOCKED", reason, "CRITICAL")
                return "BLOCKED", reason

        self._log("code_tool", code[:100], "ALLOWED", "Passed all policy checks", "INFO")
        return "ALLOWED", "Passed all policy checks"

    def reset_chain(self):
        self.call_chain = []

monitor = BehavioralMonitor("~/agent-security-lab/policy/agent_policy.yaml")
