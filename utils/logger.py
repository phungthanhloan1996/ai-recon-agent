import os
from datetime import datetime

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        self.ensure_dir()
        
    def ensure_dir(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {message}\n"
        
        # Write to file
        with open(self.log_file, 'a') as f:
            f.write(log_line)
        
        # Also print if needed
        if level == "ERROR":
            print(f"   └─ ❌ {message}")
        elif level == "WARNING":
            print(f"   └─ ⚠️ {message}")
