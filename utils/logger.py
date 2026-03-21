import os
import sys
from datetime import datetime

class Logger:
    """Logger with colored terminal output and file logging support"""
    
    # ANSI color codes
    COLORS = {
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
    }
    
    # Log level colors
    LEVEL_COLORS = {
        'DEBUG': 'CYAN',
        'INFO': 'GREEN',
        'WARNING': 'YELLOW',
        'ERROR': 'RED',
        'CRITICAL': 'RED',
        'SUCCESS': 'GREEN',
    }
    
    def __init__(self, log_file, use_colors=True):
        self.log_file = log_file
        self.use_colors = use_colors and sys.stdout.isatty()
        self.ensure_dir()
        
    def ensure_dir(self):
        if self.log_file:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    def _colorize(self, message, level):
        """Add color to message based on level"""
        if not self.use_colors:
            return message
        
        color_name = self.LEVEL_COLORS.get(level, 'WHITE')
        color = self.COLORS.get(color_name, '')
        reset = self.COLORS['RESET']
        return f"{color}{message}{reset}"
        
    def log(self, message, level="INFO"):
        """Log message to file and print to terminal with colors"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] [{level}] {message}"
        
        # Write to file (always without colors)
        if self.log_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(log_line + "\n")
            except:
                pass
        
        # Print to terminal with colors
        if level == "ERROR":
            colored = self._colorize(f"   └─ ❌ {message}", level)
            print(colored, file=sys.stderr)
        elif level == "WARNING":
            colored = self._colorize(f"   └─ ⚠️  {message}", level)
            print(colored, file=sys.stderr)
        elif level == "SUCCESS":
            colored = self._colorize(f"   └─ ✅ {message}", level)
            print(colored, file=sys.stdout)
        elif level in ("INFO", "DEBUG"):
            colored = self._colorize(f"   └─ ℹ️  {message}", level)
            print(colored, file=sys.stdout)
    
    def debug(self, message):
        """Log debug message"""
        self.log(message, "DEBUG")
    
    def info(self, message):
        """Log info message"""
        self.log(message, "INFO")
    
    def warning(self, message):
        """Log warning message"""
        self.log(message, "WARNING")
    
    def error(self, message):
        """Log error message"""
        self.log(message, "ERROR")
    
    def success(self, message):
        """Log success message"""
        self.log(message, "SUCCESS")
