import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import string
import random
import hashlib
from datetime import datetime

class PasswordComplexityChecker:
    def __init__(self, root):
        # Application metadata - updated with latest timestamp
        self.username = "ashenamantha"
        self.timestamp = "2025-05-14 08:48:30"
        
        # Initialize window
        self.root = root
        self.root.title("Password Complexity Checker")
        self.root.geometry("700x680")  # Made taller for feedback section
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(True, True)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Define colors
        self.primary_color = "#3f51b5"  # Indigo
        self.secondary_color = "#303f9f" # Dark Indigo
        self.accent_color = "#ff4081"    # Pink
        self.warning_color = "#ff9800"   # Orange
        self.success_color = "#4caf50"   # Green
        self.danger_color = "#f44336"    # Red
        self.neutral_color = "#9e9e9e"   # Gray
        
        self.style.configure("TButton", background=self.primary_color, foreground="white", 
                             font=("Segoe UI", 10, "bold"), borderwidth=0)
        self.style.map("TButton", background=[("active", self.secondary_color)])
        
        self.style.configure("Accent.TButton", background=self.accent_color)
        self.style.map("Accent.TButton", background=[("active", "#e91e63")])
        
        self.style.configure("Success.TButton", background=self.success_color)
        self.style.map("Success.TButton", background=[("active", "#388e3c")])
        
        self.style.configure("Danger.TButton", background=self.danger_color)
        self.style.map("Danger.TButton", background=[("active", "#d32f2f")])
        
        # Variables for password analysis
        self.password_var = tk.StringVar()
        self.password_var.trace("w", self.check_password_strength)
        self.strength_var = tk.StringVar(value="Password Strength: None")
        self.score_var = tk.IntVar(value=0)
        
        self.show_password = tk.BooleanVar(value=False)
        self.show_password.trace("w", self.toggle_password_visibility)
        
        # Common passwords data
        self.common_passwords = self.load_common_passwords()
        
        # Create and place widgets
        self.create_widgets()
        
        # History of password checks
        self.password_history = []
        
        # Initial update of the UI
        self.root.after(100, self.initial_update)
        
    def load_common_passwords(self):
        # This would normally load from a file, but for simplicity we'll include a sample
        return [
            "password", "123456", "qwerty", "admin", "welcome", 
            "123456789", "12345678", "abc123", "password123", "admin123",
            "letmein", "monkey", "1234567890", "000000", "qwerty123"
        ]
        
    def initial_update(self):
        """Initial UI update to ensure everything is displayed correctly"""
        self.check_password_strength()
        
    def create_widgets(self):
        # Header frame
        header_frame = tk.Frame(self.root, bg=self.primary_color, pady=15)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(header_frame, text="Password Complexity Checker", 
                            font=("Segoe UI", 22, "bold"), fg="white", bg=self.primary_color)
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, text="Evaluate and improve your password security", 
                               font=("Segoe UI", 12), fg="white", bg=self.primary_color)
        subtitle_label.pack()
        
        # Content frame (main area)
        content_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=10)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Password input section
        input_frame = tk.LabelFrame(content_frame, text="Enter Password", font=("Segoe UI", 11, "bold"),
                                 bg="#f0f0f0", padx=15, pady=15)
        input_frame.pack(fill=tk.X, pady=10)
        
        password_entry_frame = tk.Frame(input_frame, bg="#f0f0f0")
        password_entry_frame.pack(fill=tk.X)
        
        self.password_entry = ttk.Entry(password_entry_frame, textvariable=self.password_var, 
                                     font=("Segoe UI", 12), width=30, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        show_pwd_check = ttk.Checkbutton(password_entry_frame, text="Show Password", 
                                       variable=self.show_password)
        show_pwd_check.pack(side=tk.LEFT)
        
        action_frame = tk.Frame(input_frame, bg="#f0f0f0", pady=10)
        action_frame.pack(fill=tk.X)
        
        generate_btn = ttk.Button(action_frame, text="Generate Strong Password", 
                               style="Accent.TButton", command=self.generate_password)
        generate_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = ttk.Button(action_frame, text="Clear", command=self.clear_password)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        copy_btn = ttk.Button(action_frame, text="Copy to Clipboard", 
                           command=self.copy_to_clipboard)
        copy_btn.pack(side=tk.LEFT, padx=5)
        
        # Strength meter section
        meter_frame = tk.Frame(content_frame, bg="#f0f0f0", pady=5)
        meter_frame.pack(fill=tk.X)
        
        self.strength_label = tk.Label(meter_frame, textvariable=self.strength_var,
                                    font=("Segoe UI", 14, "bold"), bg="#f0f0f0")
        self.strength_label.pack(anchor=tk.W)
        
        self.meter_canvas = tk.Canvas(meter_frame, height=30, bg="#e0e0e0", 
                                   highlightthickness=0)
        self.meter_canvas.pack(fill=tk.X, pady=5)
        
        # Analysis section
        analysis_frame = tk.LabelFrame(content_frame, text="Password Analysis", 
                                    font=("Segoe UI", 11, "bold"), bg="#f0f0f0",
                                    padx=15, pady=15)
        analysis_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create criteria labels with checkmarks/Xs
        criteria_frame = tk.Frame(analysis_frame, bg="#f0f0f0")
        criteria_frame.pack(fill=tk.X, pady=5)
        
        # Grid for criteria
        self.criteria_labels = {}
        self.criteria_status = {}
        
        criteria = [
            "length", "uppercase", "lowercase", "numbers", "special", 
            "not_common", "no_sequences", "no_repetitions"
        ]
        
        criteria_descriptions = [
            "Length (8+ chars, 12+ recommended)",
            "Contains uppercase letters (A-Z)",
            "Contains lowercase letters (a-z)",
            "Contains numbers (0-9)",
            "Contains special characters (!@#$...)",
            "Not a commonly used password",
            "No obvious sequences (abc, 123, qwerty)",
            "No excessive character repetition"
        ]
        
        for idx, (criterion, description) in enumerate(zip(criteria, criteria_descriptions)):
            row = idx // 2
            col = idx % 2
            
            criterion_frame = tk.Frame(criteria_frame, bg="#f0f0f0", pady=5)
            criterion_frame.grid(row=row, column=col, sticky=tk.W, padx=10, pady=2)
            
            self.criteria_status[criterion] = tk.Label(criterion_frame, text="✘", 
                                                    font=("Segoe UI", 12), 
                                                    fg=self.danger_color, bg="#f0f0f0")
            self.criteria_status[criterion].pack(side=tk.LEFT)
            
            self.criteria_labels[criterion] = tk.Label(criterion_frame, text=description,
                                                   font=("Segoe UI", 11), bg="#f0f0f0")
            self.criteria_labels[criterion].pack(side=tk.LEFT, padx=5)
        
        # Time to crack estimate
        time_frame = tk.Frame(analysis_frame, bg="#f0f0f0", pady=10)
        time_frame.pack(fill=tk.X)
        
        time_label = tk.Label(time_frame, text="Estimated time to crack:",
                           font=("Segoe UI", 11, "bold"), bg="#f0f0f0")
        time_label.pack(anchor=tk.W)
        
        self.time_text = tk.Label(time_frame, text="N/A", font=("Segoe UI", 10),
                               bg="#f0f0f0")
        self.time_text.pack(anchor=tk.W)
        
        # FIXED: Detailed feedback section
        feedback_frame = tk.LabelFrame(content_frame, text="Detailed Feedback", 
                                    font=("Segoe UI", 11, "bold"), bg="#f0f0f0",
                                    padx=15, pady=15)
        feedback_frame.pack(fill=tk.X, pady=10, expand=False)
        
        # Using ScrolledText instead of Text for better visibility
        self.feedback_text = scrolledtext.ScrolledText(
            feedback_frame, 
            height=6,  # Increased height for better visibility
            wrap=tk.WORD, 
            font=("Segoe UI", 10),
            bg="#f5f5f5", 
            fg="#212121"
        )
        self.feedback_text.pack(fill=tk.X, expand=True)
        
        # Footer with session info
        footer_frame = tk.Frame(self.root, bg=self.primary_color, pady=5)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        session_info = f"User: {self.username} | Session: {self.timestamp}"
        session_label = tk.Label(footer_frame, text=session_info,
                              font=("Segoe UI", 8), fg="white", bg=self.primary_color)
        session_label.pack()
    
    def toggle_password_visibility(self, *args):
        """Toggle password visibility between clear text and hidden"""
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def clear_password(self):
        """Clear the password field"""
        self.password_var.set("")
        self.password_entry.focus()
    
    def copy_to_clipboard(self):
        """Copy the password to clipboard"""
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showinfo("Info", "No password to copy!")
            
    def generate_password(self):
        """Generate a secure random password"""
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?`~"
        
        # Ensure at least one of each type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(symbols)
        ]
        
        # Add more random characters to reach desired length
        length = random.randint(14, 18)  # Random length between 14-18 chars
        all_chars = lowercase + uppercase + digits + symbols
        password.extend(random.choices(all_chars, k=length-4))
        
        # Shuffle to avoid predictable patterns
        random.shuffle(password)
        generated_password = ''.join(password)
        
        # Set the generated password
        self.password_var.set(generated_password)
    
    def check_password_strength(self, *args):
        """Analyze password strength and update UI"""
        password = self.password_var.get()
        
        # Reset UI
        self.meter_canvas.delete("all")
        
        # FIXED: Clear feedback text first
        self.feedback_text.delete('1.0', tk.END)
        
        if not password:
            self.strength_var.set("Password Strength: None")
            self.score_var.set(0)
            self.update_criteria_indicators({})
            self.feedback_text.insert(tk.END, "Enter a password to analyze its strength.")
            self.time_text.config(text="N/A")
            return
        
        # Calculate strength score and get feedback
        score, issues, passed = self.analyze_password(password)
        self.score_var.set(score)
        
        # Update strength label
        strength_labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        strength_colors = [self.danger_color, self.warning_color, self.warning_color, 
                           self.success_color, self.success_color]
        
        index = min(score // 20, 4)  # Map score (0-100) to index (0-4)
        strength_text = strength_labels[index]
        strength_color = strength_colors[index]
        
        self.strength_var.set(f"Password Strength: {strength_text}")
        self.strength_label.config(fg=strength_color)
        
        # Update meter
        self.update_strength_meter(score, strength_color)
        
        # Update criteria indicators
        self.update_criteria_indicators(passed)
        
        # FIXED: Update feedback text with better formatting and visibility
        if score >= 80:
            self.feedback_text.insert(tk.END, "✓ Great password! It meets all security criteria.\n\n", "good")
            self.feedback_text.tag_configure("good", foreground=self.success_color, font=("Segoe UI", 10, "bold"))
        elif score >= 60:
            self.feedback_text.insert(tk.END, "⚠ Good password, but could be improved.\n\n", "medium")
            self.feedback_text.tag_configure("medium", foreground=self.warning_color, font=("Segoe UI", 10, "bold"))
        else:
            self.feedback_text.insert(tk.END, "✗ This password needs improvement.\n\n", "bad")
            self.feedback_text.tag_configure("bad", foreground=self.danger_color, font=("Segoe UI", 10, "bold"))
        
        # Add recommendations if there are any issues
        if issues:
            self.feedback_text.insert(tk.END, "Recommendations:\n", "header")
            self.feedback_text.tag_configure("header", font=("Segoe UI", 10, "bold"))
            
            for issue in issues:
                self.feedback_text.insert(tk.END, f"• {issue}\n", "bullet")
            self.feedback_text.tag_configure("bullet", font=("Segoe UI", 10))
        else:
            self.feedback_text.insert(tk.END, "No specific recommendations. Your password meets all criteria.", "info")
            self.feedback_text.tag_configure("info", font=("Segoe UI", 10, "italic"))
                
        # Add to history (don't store actual passwords, just a hash)
        self.add_to_history(password)
        
        # Update time to crack estimate
        self.time_text.config(text=self.estimate_crack_time(password, score))
    
    def analyze_password(self, password):
        """Analyze the password and return score, issues, and passed criteria"""
        score = 0
        issues = []
        passed = {}
        
        # Check length
        length = len(password)
        if length >= 12:
            score += 25
            passed["length"] = True
        elif length >= 8:
            score += 15
            passed["length"] = True
            issues.append("Consider using a longer password (12+ characters recommended).")
        else:
            passed["length"] = False
            issues.append("Password is too short. Use at least 8 characters, preferably 12+.")
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 10
            passed["uppercase"] = True
        else:
            passed["uppercase"] = False
            issues.append("Add uppercase letters (A-Z) to strengthen your password.")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 10
            passed["lowercase"] = True
        else:
            passed["lowercase"] = False
            issues.append("Add lowercase letters (a-z) to strengthen your password.")
        
        # Check for numbers
        if re.search(r'[0-9]', password):
            score += 10
            passed["numbers"] = True
        else:
            passed["numbers"] = False
            issues.append("Add numbers (0-9) to strengthen your password.")
        
        # Check for special characters
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 15
            passed["special"] = True
        else:
            passed["special"] = False
            issues.append("Add special characters (!@#$%^&*...) to strengthen your password.")
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            score = max(score - 30, 0)
            passed["not_common"] = False
            issues.append("This is a commonly used password. It's highly vulnerable to attacks.")
        else:
            passed["not_common"] = True
        
        # Check for sequences
        sequences = ['123', '234', '345', '456', '567', '678', '789', '987', '876', '765', 
                    '654', '543', '432', '321', 'abc', 'bcd', 'cde', 'def', 'efg',
                    'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop',
                    'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy',
                    'xyz', 'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop']
                    
        has_sequence = False
        for seq in sequences:
            if seq in password.lower():
                has_sequence = True
                break
                
        if has_sequence:
            score = max(score - 10, 0)
            passed["no_sequences"] = False
            issues.append("Your password contains common sequences. Avoid patterns like '123', 'abc', 'qwerty'.")
        else:
            passed["no_sequences"] = True
        
        # Check for repetitions
        if re.search(r'(.)\1{2,}', password):  # Same character repeated 3+ times
            score = max(score - 10, 0)
            passed["no_repetitions"] = False
            issues.append("Your password contains repeated characters. Avoid patterns like 'aaa', '111'.")
        else:
            passed["no_repetitions"] = True
        
        # Bonus for password complexity (mixture of character types)
        char_types = 0
        if re.search(r'[A-Z]', password): char_types += 1
        if re.search(r'[a-z]', password): char_types += 1
        if re.search(r'[0-9]', password): char_types += 1
        if re.search(r'[^a-zA-Z0-9]', password): char_types += 1
        
        if char_types >= 3:
            score += 10
            if char_types == 4:
                score += 10
        
        # Cap score at 100
        score = min(score, 100)
        
        return score, issues, passed
    
    def update_strength_meter(self, score, color):
        """Update the visual strength meter"""
        width = self.meter_canvas.winfo_width()
        
        # Handle the case when the canvas is not yet fully laid out
        if width <= 1:  # Window not fully created yet
            self.root.update()
            width = self.meter_canvas.winfo_width()
            if width <= 1:  # Still not ready, use a default width
                width = 300
        
        # Draw the filled portion of the meter
        fill_width = int((score / 100) * width)
        self.meter_canvas.create_rectangle(0, 0, fill_width, 30, fill=color, outline="")
        
        # Add score text
        self.meter_canvas.create_text(width // 2, 15, text=f"{score}/100", 
                                   fill="black", font=("Segoe UI", 9, "bold"))
    
    def update_criteria_indicators(self, passed):
        """Update the criteria indicators based on what passed"""
        for criterion, label in self.criteria_status.items():
            if criterion in passed and passed[criterion]:
                label.config(text="✓", fg=self.success_color)
            else:
                label.config(text="✘", fg=self.danger_color)
    
    def add_to_history(self, password):
        """Add a password check to history (storing only hash and score)"""
        # Create a hash of the password - don't store actual passwords
        hashed_password = hashlib.sha256(password.encode()).hexdigest()[:10]  # Just use first 10 chars of hash
        
        # Check if this password was already checked
        for entry in self.password_history:
            if entry['hash'] == hashed_password:
                return  # Already in history
        
        # Add to history
        score = self.score_var.get()
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.password_history.append({
            'hash': hashed_password,
            'score': score,
            'time': timestamp
        })
        
        # Limit history size
        if len(self.password_history) > 10:
            self.password_history.pop(0)
    
    def estimate_crack_time(self, password, score):
        """Estimate the time it would take to crack this password"""
        if score < 20:
            return "Instantly"
        elif score < 40:
            return "Minutes to hours"
        elif score < 60:
            return "Hours to days"
        elif score < 80:
            return "Days to months"
        else:
            return "Years to centuries"

def main():
    root = tk.Tk()
    app = PasswordComplexityChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()