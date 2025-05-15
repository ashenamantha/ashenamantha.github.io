import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.font import Font
import time

class ModernButton(tk.Button):
    """Custom button class with hover effects"""
    def __init__(self, master=None, **kwargs):
        tk.Button.__init__(self, master, **kwargs)
        self.default_bg = kwargs.get('background') or kwargs.get('bg') or 'SystemButtonFace'
        self.default_fg = kwargs.get('foreground') or kwargs.get('fg') or 'SystemButtonText'
        self.hover_bg = self._adjust_color(self.default_bg, -20)
        self.active_bg = self._adjust_color(self.default_bg, -40)
        
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _adjust_color(self, color, amount):
        """Lighten or darken a hex color"""
        if color.startswith('#'):
            # Convert hex to RGB
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            # Adjust RGB values
            r = max(0, min(255, r + amount))
            g = max(0, min(255, g + amount))
            b = max(0, min(255, b + amount))
            
            # Convert back to hex
            return f'#{r:02x}{g:02x}{b:02x}'
        return color
    
    def _on_enter(self, e):
        self.config(background=self.hover_bg)
        
    def _on_leave(self, e):
        self.config(background=self.default_bg)
        
    def _on_press(self, e):
        self.config(background=self.active_bg)
        
    def _on_release(self, e):
        self.config(background=self.hover_bg)


class EnhancedCaesarCipherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Caesar Cipher - Encryption & Decryption")
        self.root.geometry("650x680")
        
        # Color scheme
        self.primary_color = "#3f51b5"  # Indigo
        self.secondary_color = "#303f9f" # Darker Indigo
        self.accent_color = "#ff4081"    # Pink
        self.light_bg = "#f5f5f5"        # Almost white
        self.dark_text = "#212121"       # Almost black
        self.light_text = "#ffffff"      # White
        self.border_color = "#e0e0e0"    # Light gray
        
        self.root.configure(bg=self.light_bg)
        
        # Custom fonts
        self.title_font = Font(family="Helvetica", size=24, weight="bold")
        self.subtitle_font = Font(family="Helvetica", size=12, weight="bold")
        self.body_font = Font(family="Helvetica", size=11)
        self.button_font = Font(family="Helvetica", size=11, weight="bold")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container with padding
        main_container = tk.Frame(self.root, bg=self.light_bg, padx=20, pady=20)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # ===== Header Section =====
        header_frame = tk.Frame(main_container, bg=self.primary_color, pady=15)
        header_frame.pack(fill=tk.X)
        
        logo_label = tk.Label(header_frame, text="🔒", font=("Arial", 36), bg=self.primary_color, fg=self.light_text)
        logo_label.pack(side=tk.LEFT, padx=25)
        
        header_text_frame = tk.Frame(header_frame, bg=self.primary_color)
        header_text_frame.pack(side=tk.LEFT)
        
        title_label = tk.Label(header_text_frame, text="Caesar Cipher", font=self.title_font, 
                               bg=self.primary_color, fg=self.light_text)
        title_label.pack(anchor="w")
        
        subtitle_label = tk.Label(header_text_frame, text="Secure Text Encryption & Decryption", 
                                  font=self.subtitle_font, bg=self.primary_color, fg=self.light_text)
        subtitle_label.pack(anchor="w")
        
        # ===== Input Section =====
        input_frame = tk.LabelFrame(main_container, text="Input", font=self.subtitle_font,
                                   bg=self.light_bg, fg=self.dark_text, padx=15, pady=15)
        input_frame.pack(fill=tk.X, pady=15)
        
        msg_label = tk.Label(input_frame, text="Enter Your Message:", font=self.body_font,
                             bg=self.light_bg, fg=self.dark_text)
        msg_label.pack(anchor="w", pady=(0, 5))
        
        # Text input with scrollbar and border
        text_container = tk.Frame(input_frame, bg=self.border_color, padx=1, pady=1)
        text_container.pack(fill=tk.X)
        
        self.msg_entry = tk.Text(text_container, height=5, font=self.body_font,
                                wrap=tk.WORD, relief=tk.FLAT, padx=10, pady=10)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(text_container, command=self.msg_entry.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.msg_entry.configure(yscrollcommand=scrollbar.set)
        
        # ===== Shift Value Section =====
        shift_frame = tk.Frame(main_container, bg=self.light_bg, pady=10)
        shift_frame.pack(fill=tk.X)
        
        shift_label = tk.Label(shift_frame, text="Shift Value:", font=self.body_font,
                              bg=self.light_bg, fg=self.dark_text)
        shift_label.pack(side=tk.LEFT)
        
        self.shift_var = tk.IntVar(value=3)
        
        # Fixed: Use default style for slider instead of custom style that caused an error
        self.shift_slider = ttk.Scale(shift_frame, from_=1, to=25, orient="horizontal", 
                                     variable=self.shift_var, length=250,
                                     command=self.update_shift_value)
        self.shift_slider.pack(side=tk.LEFT, padx=10)
        
        # Value display with nice border
        value_display = tk.Frame(shift_frame, bg=self.border_color, padx=1, pady=1)
        value_display.pack(side=tk.LEFT)
        
        self.shift_value_label = tk.Label(value_display, textvariable=self.shift_var, width=2,
                                         font=self.body_font, bg=self.light_text, padx=10, pady=2)
        self.shift_value_label.pack()
        
        # ===== Action Buttons Section =====
        btn_frame = tk.Frame(main_container, bg=self.light_bg, pady=15)
        btn_frame.pack(fill=tk.X)
        
        self.encrypt_btn = ModernButton(btn_frame, text="Encrypt", command=self.animate_encrypt,
                                      font=self.button_font, bg=self.primary_color, fg=self.light_text,
                                      activebackground=self.secondary_color, activeforeground=self.light_text,
                                      bd=0, padx=20, pady=10, width=12)
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.decrypt_btn = ModernButton(btn_frame, text="Decrypt", command=self.animate_decrypt,
                                      font=self.button_font, bg=self.secondary_color, fg=self.light_text,
                                      activebackground=self.primary_color, activeforeground=self.light_text,
                                      bd=0, padx=20, pady=10, width=12)
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)
        
        self.clear_btn = ModernButton(btn_frame, text="Clear All", command=self.clear,
                                    font=self.button_font, bg="#9e9e9e", fg=self.light_text,
                                    activebackground="#757575", activeforeground=self.light_text,
                                    bd=0, padx=20, pady=10, width=12)
        self.clear_btn.pack(side=tk.LEFT, padx=10)
        
        # ===== Stats Section =====
        stats_frame = tk.Frame(main_container, bg=self.light_bg, pady=5)
        stats_frame.pack(fill=tk.X)
        
        self.stats_var = tk.StringVar(value="Characters: 0 | Words: 0")
        stats_label = tk.Label(stats_frame, textvariable=self.stats_var, font=("Helvetica", 9),
                              bg=self.light_bg, fg="#757575")
        stats_label.pack(anchor="w")
        
        # Bind text changes to update stats
        self.msg_entry.bind("<KeyRelease>", self.update_stats)
        
        # ===== Result Section =====
        result_frame = tk.LabelFrame(main_container, text="Result", font=self.subtitle_font,
                                    bg=self.light_bg, fg=self.dark_text, padx=15, pady=15)
        result_frame.pack(fill=tk.X, pady=10)
        
        # Result text area with scrollbar and border
        result_container = tk.Frame(result_frame, bg=self.border_color, padx=1, pady=1)
        result_container.pack(fill=tk.X)
        
        self.result_text = tk.Text(result_container, height=5, font=self.body_font,
                                  wrap=tk.WORD, relief=tk.FLAT, padx=10, pady=10,
                                  bg="#f8f8f8")
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.result_text.configure(state=tk.DISABLED)
        
        result_scrollbar = ttk.Scrollbar(result_container, command=self.result_text.yview)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        
        # ===== Additional Buttons =====
        extra_btn_frame = tk.Frame(main_container, bg=self.light_bg, pady=15)
        extra_btn_frame.pack(fill=tk.X)
        
        self.copy_btn = ModernButton(extra_btn_frame, text="Copy to Clipboard", command=self.copy_to_clipboard,
                                   font=self.button_font, bg=self.accent_color, fg=self.light_text,
                                   activebackground="#e91e63", activeforeground=self.light_text,
                                   bd=0, padx=20, pady=10)
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # ===== Caesar Cipher Info Section =====
        info_frame = tk.LabelFrame(main_container, text="About Caesar Cipher", font=self.subtitle_font,
                                  bg=self.light_bg, fg=self.dark_text, padx=15, pady=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        info_text = ("The Caesar Cipher is one of the simplest and most widely known encryption techniques. "
                    "It works by shifting each letter in the plaintext up or down a certain number of places "
                    "in the alphabet. For example, with a shift of 1, 'A' would become 'B', 'B' would become 'C', etc.")
        
        info_label = tk.Label(info_frame, text=info_text, font=("Helvetica", 10),
                             bg=self.light_bg, fg=self.dark_text, justify=tk.LEFT, wraplength=580)
        info_label.pack(anchor="w")
        
        # ===== Footer =====
        footer_frame = tk.Frame(main_container, bg=self.primary_color, pady=5)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        footer_text = tk.Label(footer_frame, text="© 2025 Caesar Cipher Encryption Tool", 
                              font=("Helvetica", 8), bg=self.primary_color, fg=self.light_text)
        footer_text.pack()
        
        # Initial stats update
        self.update_stats()
        
    def update_shift_value(self, event=None):
        self.shift_var.set(round(float(self.shift_slider.get())))
        
    def update_stats(self, event=None):
        text = self.msg_entry.get("1.0", tk.END).strip()
        char_count = len(text)
        word_count = len(text.split()) if text else 0
        self.stats_var.set(f"Characters: {char_count} | Words: {word_count}")
        
    def animate_encrypt(self):
        # Simple animation effect before encrypting
        self.encrypt_btn.config(relief=tk.SUNKEN)
        self.root.update()
        time.sleep(0.1)
        self.encrypt_btn.config(relief=tk.RAISED)
        self.encrypt()
        
    def animate_decrypt(self):
        # Simple animation effect before decrypting
        self.decrypt_btn.config(relief=tk.SUNKEN)
        self.root.update()
        time.sleep(0.1)
        self.decrypt_btn.config(relief=tk.RAISED)
        self.decrypt()
    
    def encrypt(self):
        text = self.msg_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Error", "Please enter a message to encrypt.")
            return
        
        shift = self.shift_var.get()
        encrypted = self._encrypt_text(text, shift)
        
        self.result_text.configure(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", encrypted)
        self.result_text.configure(state=tk.DISABLED)
    
    def decrypt(self):
        text = self.msg_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Error", "Please enter a message to decrypt.")
            return
        
        shift = self.shift_var.get()
        decrypted = self._encrypt_text(text, -shift)
        
        self.result_text.configure(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", decrypted)
        self.result_text.configure(state=tk.DISABLED)
    
    def clear(self):
        self.msg_entry.delete("1.0", tk.END)
        self.result_text.configure(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.configure(state=tk.DISABLED)
        self.shift_var.set(3)
        self.update_stats()
    
    def copy_to_clipboard(self):
        result_text = self.result_text.get("1.0", tk.END).strip()
        if not result_text:
            messagebox.showinfo("Copy to Clipboard", "No result to copy.")
            return
            
        self.root.clipboard_clear()
        self.root.clipboard_append(result_text)
        
        # Visual feedback for copy action
        original_text = self.copy_btn.cget("text")
        original_bg = self.copy_btn.cget("background")
        
        self.copy_btn.config(text="Copied!", background="#4caf50")
        self.root.update()
        
        # Reset after 1 second
        self.root.after(1000, lambda: self.copy_btn.config(text=original_text, background=original_bg))
    
    def _encrypt_text(self, text, shift):
        result = ""
        
        for char in text:
            if char.isalpha():
                # Determine the ASCII offset (97 for lowercase, 65 for uppercase)
                ascii_offset = 65 if char.isupper() else 97
                
                # Apply the shift formula: (position + shift) % 26
                shifted = (ord(char) - ascii_offset + shift) % 26
                
                # Convert back to character
                result += chr(shifted + ascii_offset)
            else:
                # Keep non-alphabetic characters unchanged
                result += char
                
        return result

def main():
    root = tk.Tk()
    app = EnhancedCaesarCipherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()