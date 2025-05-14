import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import os
import random
from datetime import datetime

class ImageEncryptionTool:
    def __init__(self, root):
        # Initialize the main window
        self.root = root
        self.root.title("Image Encryption Tool")
        self.root.geometry("1000x650")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(True, True)
        
        # Update with user's specific information
        self.username = "ashenamantha"
        self.timestamp = "2025-05-14 08:33:38"
        
        # Variables
        self.input_image_path = None
        self.output_image_path = None
        self.original_image = None
        self.processed_image = None
        self.encryption_key = tk.StringVar()
        self.selected_method = tk.StringVar(value="XOR Encryption")
        
        # Debug variables to track encryption state
        self.encryption_info = {}  # Stores parameters used for encryption
        self.debug_mode = tk.BooleanVar(value=True)  # Debug logging enabled by default
        
        # Create UI
        self.create_ui()
        
    def create_ui(self):
        # Header section
        header_frame = tk.Frame(self.root, bg="#3f51b5", height=80)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(
            header_frame, 
            text="Pixel Manipulation Image Encryption", 
            font=("Helvetica", 24, "bold"), 
            fg="white", 
            bg="#3f51b5",
            pady=15
        )
        title_label.pack()
        
        # Main content area
        content_frame = tk.Frame(self.root, bg="#f0f0f0")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left side - Settings panel
        settings_frame = tk.LabelFrame(
            content_frame, 
            text="Encryption Settings", 
            font=("Helvetica", 12, "bold"),
            bg="#f0f0f0",
            padx=15,
            pady=15
        )
        settings_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # File selection
        file_frame = tk.Frame(settings_frame, bg="#f0f0f0")
        file_frame.pack(fill=tk.X, pady=(0, 15))
        
        file_btn = ttk.Button(
            file_frame,
            text="Select Image",
            command=self.load_image
        )
        file_btn.pack(fill=tk.X)
        
        self.file_label = tk.Label(
            file_frame,
            text="No image selected",
            font=("Helvetica", 10),
            bg="#f0f0f0",
            wraplength=200
        )
        self.file_label.pack(fill=tk.X, pady=(5, 0))
        
        # Encryption key
        key_frame = tk.Frame(settings_frame, bg="#f0f0f0")
        key_frame.pack(fill=tk.X, pady=(0, 15))
        
        key_label = tk.Label(
            key_frame,
            text="Encryption Key:",
            font=("Helvetica", 10, "bold"),
            bg="#f0f0f0"
        )
        key_label.pack(anchor="w")
        
        key_entry = ttk.Entry(
            key_frame,
            textvariable=self.encryption_key,
            width=30
        )
        key_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Generate random key button
        random_key_btn = ttk.Button(
            key_frame,
            text="Generate Random Key",
            command=self.generate_random_key
        )
        random_key_btn.pack(fill=tk.X, pady=(5, 0))
        
        # Encryption method selection
        method_frame = tk.Frame(settings_frame, bg="#f0f0f0")
        method_frame.pack(fill=tk.X, pady=(0, 15))
        
        method_label = tk.Label(
            method_frame,
            text="Encryption Method:",
            font=("Helvetica", 10, "bold"),
            bg="#f0f0f0"
        )
        method_label.pack(anchor="w")
        
        methods = [
            "XOR Encryption", 
            "RGB Channel Swap", 
            "Pixel Value Shift", 
            "Bit Manipulation"
        ]
        
        for method in methods:
            rb = ttk.Radiobutton(
                method_frame,
                text=method,
                variable=self.selected_method,
                value=method
            )
            rb.pack(anchor="w", pady=(2, 0))
        
        # Debug mode checkbox
        debug_check = ttk.Checkbutton(
            method_frame,
            text="Debug Mode (Show detailed info)",
            variable=self.debug_mode
        )
        debug_check.pack(anchor="w", pady=(5, 0))
        
        # Action buttons
        btn_frame = tk.Frame(settings_frame, bg="#f0f0f0")
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        encrypt_btn = ttk.Button(
            btn_frame,
            text="Encrypt Image",
            command=self.encrypt_image
        )
        encrypt_btn.pack(fill=tk.X, pady=(0, 5))
        
        decrypt_btn = ttk.Button(
            btn_frame,
            text="Decrypt Image",
            command=self.decrypt_image
        )
        decrypt_btn.pack(fill=tk.X, pady=(0, 5))
        
        save_btn = ttk.Button(
            btn_frame,
            text="Save Result",
            command=self.save_image
        )
        save_btn.pack(fill=tk.X, pady=(0, 5))
        
        # Session info
        info_frame = tk.Frame(settings_frame, bg="#f0f0f0", pady=10)
        info_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        session_label = tk.Label(
            info_frame,
            text=f"User: {self.username}",
            font=("Helvetica", 8),
            bg="#f0f0f0",
            fg="#666666"
        )
        session_label.pack(anchor="w")
        
        time_label = tk.Label(
            info_frame,
            text=f"Session: {self.timestamp}",
            font=("Helvetica", 8),
            bg="#f0f0f0",
            fg="#666666"
        )
        time_label.pack(anchor="w")
        
        # Right side - Image display
        display_frame = tk.Frame(content_frame, bg="#f0f0f0")
        display_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Original image
        original_frame = tk.LabelFrame(
            display_frame,
            text="Original Image",
            font=("Helvetica", 12, "bold"),
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        original_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 5))
        
        self.original_image_label = tk.Label(original_frame, bg="#e0e0e0")
        self.original_image_label.pack(fill=tk.BOTH, expand=True)
        
        # Processed image
        processed_frame = tk.LabelFrame(
            display_frame,
            text="Processed Image",
            font=("Helvetica", 12, "bold"),
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        processed_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(5, 0))
        
        self.processed_image_label = tk.Label(processed_frame, bg="#e0e0e0")
        self.processed_image_label.pack(fill=tk.BOTH, expand=True)
        
        # Debug info panel
        self.debug_text = tk.Text(self.root, height=5, bg="#f5f5f5", fg="#333333")
        self.debug_text.pack(fill=tk.X, pady=(0, 10), padx=20)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initial debug info
        self.log_debug("Tool initialized. Ready for encryption/decryption operations.")
        self.log_debug(f"Current session: User '{self.username}' at {self.timestamp}")
    
    def log_debug(self, message):
        """Log debug information to the debug panel"""
        if self.debug_mode.get():
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.debug_text.see(tk.END)  # Scroll to the end
            
            # Limit number of lines
            if int(self.debug_text.index('end-1c').split('.')[0]) > 100:
                self.debug_text.delete('1.0', '2.0')
    
    def load_image(self):
        """Load an image from file system"""
        file_path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp *.gif"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            # Load the image using PIL
            self.input_image_path = file_path
            self.original_image = Image.open(file_path)
            
            # Update file label
            file_name = os.path.basename(file_path)
            self.file_label.config(text=f"Selected: {file_name}")
            
            # Display the original image
            self.display_image(self.original_image, self.original_image_label)
            
            # Clear processed image
            self.processed_image = None
            self.processed_image_label.config(image=None)
            
            # Log image info
            img_format = self.original_image.format
            img_mode = self.original_image.mode
            img_size = self.original_image.size
            self.log_debug(f"Loaded image: {file_name}")
            self.log_debug(f"Format: {img_format}, Mode: {img_mode}, Size: {img_size[0]}x{img_size[1]}")
            
            # Clear previous encryption info
            self.encryption_info = {}
            
            # Update status
            self.status_var.set(f"Loaded: {file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")
            self.status_var.set("Error loading image")
    
    def display_image(self, img, label):
        """Display an image on a label with proper resizing"""
        if img is None:
            return
            
        # Get label dimensions
        width = label.winfo_width()
        height = label.winfo_height()
        
        # If label hasn't been fully initialized yet, use default dimensions
        if width <= 1 or height <= 1:
            width = 300
            height = 300
        
        # Resize image to fit the label while maintaining aspect ratio
        img_width, img_height = img.size
        ratio = min(width / img_width, height / img_height)
        new_width = int(img_width * ratio)
        new_height = int(img_height * ratio)
        
        # Resize and convert to PhotoImage
        img_resized = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        img_tk = ImageTk.PhotoImage(img_resized)
        
        # Update label
        label.config(image=img_tk)
        label.image = img_tk  # Keep a reference to prevent garbage collection
    
    def generate_random_key(self):
        """Generate a random encryption key"""
        # Generate a random 16-character hexadecimal key
        key = ''.join(random.choice('0123456789abcdef') for _ in range(16))
        self.encryption_key.set(key)
        self.log_debug(f"Generated random key: {key}")
        self.status_var.set(f"Generated random key: {key}")
    
    def get_key_value(self):
        """Convert the encryption key to a numeric value"""
        key = self.encryption_key.get()
        if not key:
            messagebox.showerror("Error", "Please enter an encryption key")
            return None
            
        # Convert string key to an integer seed for deterministic encryption/decryption
        try:
            # Use a simple hash function to convert any string to a number
            key_value = sum(ord(c) * (i + 1) for i, c in enumerate(key))
            self.log_debug(f"Key '{key}' converted to numeric value: {key_value}")
            return key_value
        except:
            messagebox.showerror("Error", "Invalid encryption key")
            return None
    
    def encrypt_image(self):
        """Encrypt the loaded image using the selected method"""
        if self.original_image is None:
            messagebox.showinfo("Info", "Please load an image first")
            return
            
        key_value = self.get_key_value()
        if key_value is None:
            return
            
        method = self.selected_method.get()
        self.log_debug(f"Starting encryption with method: {method}")
        
        try:
            # Convert image to numpy array for processing
            img_array = np.array(self.original_image)
            
            # Save original image mode for later use
            original_mode = self.original_image.mode
            self.encryption_info['mode'] = original_mode
            
            # Check and handle image with alpha channel
            has_alpha = original_mode == 'RGBA'
            if has_alpha:
                self.log_debug("Image has alpha channel. Preserving transparency.")
                # Extract alpha channel before processing
                alpha = img_array[:, :, 3]
                # Process only RGB channels
                rgb = img_array[:, :, :3]
            else:
                rgb = img_array
            
            # Apply selected encryption method
            if method == "XOR Encryption":
                processed_rgb = self.apply_xor_encryption(rgb, key_value)
            elif method == "RGB Channel Swap":
                processed_rgb = self.apply_rgb_swap(rgb, key_value)
            elif method == "Pixel Value Shift":
                processed_rgb = self.apply_pixel_shift(rgb, key_value)
            elif method == "Bit Manipulation":
                processed_rgb = self.apply_bit_manipulation(rgb, key_value)
            else:
                messagebox.showerror("Error", "Invalid encryption method")
                return
                
            # Recombine with alpha if needed
            if has_alpha:
                processed_array = np.zeros(img_array.shape, dtype=np.uint8)
                processed_array[:, :, :3] = processed_rgb
                processed_array[:, :, 3] = alpha
            else:
                processed_array = processed_rgb
                
            # Store encryption info for later decryption
            self.encryption_info['key'] = key_value
            self.encryption_info['method'] = method
            self.encryption_info['original_shape'] = img_array.shape
            self.encryption_info['has_alpha'] = has_alpha
            
            # Convert back to PIL image
            self.processed_image = Image.fromarray(processed_array, mode=original_mode)
            
            # Display the processed image
            self.display_image(self.processed_image, self.processed_image_label)
            
            # Log success
            self.log_debug(f"Image encrypted successfully using {method}")
            self.log_debug("IMPORTANT: Use the SAME KEY and METHOD for decryption!")
            
            # Update status
            self.status_var.set(f"Image encrypted using {method}")
        except Exception as e:
            self.log_debug(f"Encryption failed: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {e}")
            self.status_var.set("Encryption failed")
            import traceback
            self.log_debug(traceback.format_exc())
    
    def decrypt_image(self):
        """Decrypt the processed image"""
        if self.original_image is None:
            messagebox.showinfo("Info", "No image loaded for decryption")
            return
            
        key_value = self.get_key_value()
        if key_value is None:
            return
            
        method = self.selected_method.get()
        self.log_debug(f"Starting decryption with method: {method}")
        self.log_debug(f"Using key value: {key_value}")
        
        try:
            # Convert image to numpy array for processing
            img_array = np.array(self.original_image)
            
            # Get image mode
            original_mode = self.original_image.mode
            
            # Check and handle image with alpha channel
            has_alpha = original_mode == 'RGBA'
            if has_alpha:
                self.log_debug("Image has alpha channel. Preserving transparency.")
                # Extract alpha channel before processing
                alpha = img_array[:, :, 3]
                # Process only RGB channels
                rgb = img_array[:, :, :3]
            else:
                rgb = img_array
            
            # Apply selected decryption method
            if method == "XOR Encryption":
                # XOR is its own inverse with the same key
                self.log_debug("Applying XOR decryption (same as encryption)")
                processed_rgb = self.apply_xor_encryption(rgb, key_value)
            elif method == "RGB Channel Swap":
                self.log_debug("Applying RGB channel swap inverse operation")
                processed_rgb = self.apply_rgb_swap_inverse(rgb, key_value)
            elif method == "Pixel Value Shift":
                self.log_debug("Applying pixel shift inverse operation")
                processed_rgb = self.apply_pixel_shift_inverse(rgb, key_value)
            elif method == "Bit Manipulation":
                self.log_debug("Applying bit manipulation inverse operation")
                processed_rgb = self.apply_bit_manipulation_inverse(rgb, key_value)
            else:
                messagebox.showerror("Error", "Invalid decryption method")
                return
                
            # Recombine with alpha if needed
            if has_alpha:
                processed_array = np.zeros(img_array.shape, dtype=np.uint8)
                processed_array[:, :, :3] = processed_rgb
                processed_array[:, :, 3] = alpha
            else:
                processed_array = processed_rgb
                
            # Convert back to PIL image
            self.processed_image = Image.fromarray(processed_array, mode=original_mode)
            
            # Display the processed image
            self.display_image(self.processed_image, self.processed_image_label)
            
            # Log success
            self.log_debug(f"Image decrypted using {method}")
            
            # Update status
            self.status_var.set(f"Image decrypted using {method}")
        except Exception as e:
            self.log_debug(f"Decryption failed: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {e}")
            self.status_var.set("Decryption failed")
            import traceback
            self.log_debug(traceback.format_exc())
    
    def save_image(self):
        """Save the processed image to a file"""
        if self.processed_image is None:
            messagebox.showinfo("Info", "No processed image to save")
            return
            
        # Get save path from user
        file_path = filedialog.asksaveasfilename(
            title="Save Image",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            # Make sure to save in a format that preserves all pixel data
            if file_path.lower().endswith('.jpg') or file_path.lower().endswith('.jpeg'):
                self.log_debug("WARNING: JPEG format is lossy and may prevent proper decryption!")
                result = messagebox.askyesno(
                    "Warning",
                    "JPEG format is lossy and may prevent proper decryption later. "
                    "Do you want to save as PNG instead?"
                )
                if result:
                    file_path = os.path.splitext(file_path)[0] + ".png"
            
            self.log_debug(f"Saving image to: {file_path}")
            self.processed_image.save(file_path)
            self.output_image_path = file_path
            self.status_var.set(f"Image saved to {os.path.basename(file_path)}")
            self.log_debug(f"Image saved successfully")
        except Exception as e:
            self.log_debug(f"Failed to save image: {str(e)}")
            messagebox.showerror("Error", f"Failed to save image: {e}")
            self.status_var.set("Error saving image")
    
    # Encryption methods
    def apply_xor_encryption(self, img_array, key):
        """Apply XOR encryption to each pixel value"""
        # Ensure the key is in a reasonable range for pixel values
        np.random.seed(key)
        xor_pattern = np.random.randint(0, 256, img_array.shape, dtype=np.uint8)
        self.log_debug(f"XOR pattern shape: {xor_pattern.shape}, img shape: {img_array.shape}")
        return np.bitwise_xor(img_array, xor_pattern)
    
    def apply_rgb_swap(self, img_array, key):
        """Swap the RGB channels based on the key"""
        # Handle grayscale images
        if img_array.ndim < 3:
            self.log_debug("Image is grayscale, RGB swap not applicable")
            return img_array
            
        if img_array.shape[2] < 3:
            self.log_debug(f"Image has only {img_array.shape[2]} channels, RGB swap not applicable")
            return img_array
            
        # Determine swap pattern based on key
        np.random.seed(key)
        indices = list(range(min(3, img_array.shape[2])))  # RGB channels (up to 3)
        np.random.shuffle(indices)
        
        self.log_debug(f"RGB channel swap pattern: {indices}")
        
        # Create a new array for the result
        result = img_array.copy()
        
        # Swap the RGB channels
        for i, idx in enumerate(indices):
            if i < 3 and idx < 3:  # Ensure we're only swapping RGB, not alpha
                result[..., i] = img_array[..., idx]
                
        return result
    
    def apply_rgb_swap_inverse(self, img_array, key):
        """Inverse operation for RGB channel swap"""
        # Handle grayscale images
        if img_array.ndim < 3:
            self.log_debug("Image is grayscale, RGB swap inverse not applicable")
            return img_array
            
        if img_array.shape[2] < 3:
            self.log_debug(f"Image has only {img_array.shape[2]} channels, RGB swap inverse not applicable")
            return img_array
            
        # Determine the original swap pattern
        np.random.seed(key)
        indices = list(range(min(3, img_array.shape[2])))
        np.random.shuffle(indices)
        
        self.log_debug(f"Original RGB swap pattern: {indices}")
        
        # Create inverse mapping
        inverse_indices = [0] * 3
        for i, idx in enumerate(indices):
            if i < len(inverse_indices) and idx < len(inverse_indices):
                inverse_indices[idx] = i
                
        self.log_debug(f"Inverse RGB swap pattern: {inverse_indices}")
            
        # Create a new array for the result
        result = img_array.copy()
        
        # Swap the RGB channels back
        for i, idx in enumerate(inverse_indices):
            if i < 3 and idx < 3 and i < img_array.shape[2] and idx < img_array.shape[2]:
                result[..., i] = img_array[..., idx]
                
        return result
    
    def apply_pixel_shift(self, img_array, key):
        """Shift pixel values by a value derived from the key"""
        # Generate shift amounts for each channel based on the key
        np.random.seed(key)
        
        # Create a shift pattern with the same shape as the image
        shift_pattern = np.random.randint(1, 100, img_array.shape, dtype=np.uint8)
        
        self.log_debug(f"Pixel shift pattern range: {np.min(shift_pattern)}-{np.max(shift_pattern)}")
        
        # Apply the shift, making sure to wrap around at 255
        return np.mod(img_array.astype(np.uint16) + shift_pattern, 256).astype(np.uint8)
    
    def apply_pixel_shift_inverse(self, img_array, key):
        """Inverse of pixel shift operation"""
        # Generate the same shift amounts as used in encryption
        np.random.seed(key)
        shift_pattern = np.random.randint(1, 100, img_array.shape, dtype=np.uint8)
        
        self.log_debug(f"Pixel shift pattern range: {np.min(shift_pattern)}-{np.max(shift_pattern)}")
        
        # Apply inverse shift (subtract instead of add)
        return np.mod(img_array.astype(np.int16) - shift_pattern, 256).astype(np.uint8)
    
    def apply_bit_manipulation(self, img_array, key):
        """Manipulate bits of each pixel value"""
        # Seed random number generator with the key
        np.random.seed(key)
        
        # Generate random bit masks for each pixel
        bit_shifts = np.random.randint(1, 5, size=1)[0]  # Shift by 1-4 bits
        
        self.log_debug(f"Bit manipulation: shift by {bit_shifts} bits")
        
        # Apply bit shift operations
        shifted = np.left_shift(img_array, bit_shifts) | np.right_shift(img_array, 8 - bit_shifts)
        
        # Make sure values stay in valid range (0-255)
        return shifted.astype(np.uint8)
    
    def apply_bit_manipulation_inverse(self, img_array, key):
        """Inverse of bit manipulation"""
        # Use the same seed to get the same random values
        np.random.seed(key)
        
        # Get the same bit shifts used in encryption
        bit_shifts = np.random.randint(1, 5, size=1)[0]
        
        self.log_debug(f"Bit manipulation inverse: shift by {bit_shifts} bits")
        
        # Apply inverse bit shift operations
        shifted = np.right_shift(img_array, bit_shifts) | np.left_shift(img_array, 8 - bit_shifts)
        
        # Make sure values stay in valid range (0-255)
        return shifted.astype(np.uint8)

def main():
    root = tk.Tk()
    app = ImageEncryptionTool(root)
    
    # Set style
    style = ttk.Style()
    style.configure("TButton", padding=6)
    style.configure("TRadiobutton", background="#f0f0f0")
    
    # Make the window responsive
    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()