import os
import requests
import subprocess
from bs4 import BeautifulSoup
from langchain.tools import tool
from monitor import monitor

WORKSPACE = os.path.expanduser("~/agent-security-lab/workspace")

@tool
def file_read(filepath: str) -> str:
    """Read a file from the workspace. Input must be a filename only, not a full path."""
    verdict, reason = monitor.check_file_tool(filepath)
    if verdict == "BLOCKED":
        return f"Security policy blocked this action: {reason}"
    
    safe_path = os.path.join(WORKSPACE, os.path.basename(filepath))
    try:
        with open(safe_path, "r") as f:
            content = f.read()
        return f"FILE CONTENTS of {filepath}:\n{content}"
    except FileNotFoundError:
        return f"Error: File '{filepath}' not found in workspace."
    except Exception as e:
        return f"Error reading file: {str(e)}"

@tool
def file_write(filepath: str, content: str) -> str:
    """Write content to a file in the workspace. Input must be a filename only."""
    verdict, reason = monitor.check_file_tool(filepath)
    if verdict == "BLOCKED":
        return f"Security policy blocked this action: {reason}"
    
    safe_path = os.path.join(WORKSPACE, os.path.basename(filepath))
    try:
        with open(safe_path, "w") as f:
            f.write(content)
        return f"Successfully wrote to {filepath}"
    except Exception as e:
        return f"Error writing file: {str(e)}"

@tool
def web_fetch(url: str) -> str:
    """Fetch and return the text content of a webpage."""
    verdict, reason = monitor.check_web_tool(url)
    if verdict == "BLOCKED":
        return f"Security policy blocked this action: {reason}"
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text(separator="\n", strip=True)
        return f"WEB CONTENT from {url}:\n{text[:3000]}"
    except Exception as e:
        return f"Error fetching URL: {str(e)}"

@tool
def code_execute(code: str) -> str:
    """Execute a Python code snippet and return the output."""
    verdict, reason = monitor.check_code_tool(code)
    if verdict == "BLOCKED":
        return f"Security policy blocked this action: {reason}"
    
    try:
        result = subprocess.run(
            ["python3", "-c", code],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout if result.stdout else result.stderr
        return f"CODE OUTPUT:\n{output}"
    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out."
    except Exception as e:
        return f"Error executing code: {str(e)}"

tools = [file_read, file_write, web_fetch, code_execute]
