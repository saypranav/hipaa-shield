import subprocess
import threading
import queue
import time
import os

class ScannerRunner:
    def __init__(self):
        self.processes = {}
        self.logs = {}
        self.status = {}

    def run_scan(self, scanner_id, command):
        if scanner_id in self.status and self.status[scanner_id] == "running":
            return False
        
        self.status[scanner_id] = "running"
        self.logs[scanner_id] = []
        
        def target():
            try:
                # Use shell=True for complex commands if needed, 
                # but careful with untrusted input.
                # Here we control the commands.
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                self.processes[scanner_id] = process
                
                for line in process.stdout:
                    self.logs[scanner_id].append(line)
                    # Keep only last 1000 lines to save memory
                    if len(self.logs[scanner_id]) > 1000:
                        self.logs[scanner_id].pop(0)
                
                process.wait()
                self.status[scanner_id] = "completed" if process.returncode == 0 else "failed"
            except Exception as e:
                self.logs[scanner_id].append(f"Error: {str(e)}")
                self.status[scanner_id] = "error"

        thread = threading.Thread(target=target)
        thread.start()
        return True

    def get_status(self, scanner_id):
        return {
            "status": self.status.get(scanner_id, "idle"),
            "logs": self.logs.get(scanner_id, [])
        }

scanner_runner = ScannerRunner()
