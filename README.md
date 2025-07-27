# Image Steganography with Encryption

A Python GUI application for hiding (encoding) and extracting (decoding) encrypted messages inside images using steganography and password-based encryption.

## Features
- Hide secret messages in images (PNG, JPG, BMP)
- Encrypt messages with a password (Fernet/AES)
- Extract and decrypt messages from images
- User-friendly Tkinter GUI

## Usage
Run the main Python script (see below) with Python 3 and required libraries installed.

## Main Code
The main code for the application is as follows:

```python
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import numpy as np
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# --- ENCRYPTION UTILS ---

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message.encode()).decode()

# --- STEGANOGRAPHY UTILS ---

def encode_image(image_path, message):
    img = Image.open(image_path).convert("RGB")
    data = np.array(img)
    flat_data = data.flatten()

    binary_msg = ''.join([format(ord(c), '08b') for c in message]) + '1111111111111110'  # EOF
    if len(binary_msg) > len(flat_data):
        raise ValueError("Message too large for this image.")

    for i in range(len(binary_msg)):
        flat_data[i] = (flat_data[i] & 0xFE) | int(binary_msg[i])

    encoded_data = flat_data.reshape(data.shape)
    return Image.fromarray(encoded_data.astype('uint8'), 'RGB')

def decode_image(image_path):
    img = Image.open(image_path).convert("RGB")
    data = np.array(img).flatten()

    bits = []
    for value in data:
        bits.append(str(value & 1))
        if ''.join(bits[-16:]) == '1111111111111110':
            break

    binary_msg = ''.join(bits[:-16])
    return ''.join([chr(int(binary_msg[i:i+8], 2)) for i in range(0, len(binary_msg), 8)])

# --- GUI APPLICATION ---

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography with Encryption")
        self.root.geometry("1200x700")
        self.root.configure(bg="#eaeaea")

        self.encode_img_path = None
        self.decode_img_path = None

        self.build_gui()

    def build_gui(self):
        left_frame = tk.Frame(self.root, bg="#d9f0ff", width=600, padx=15, pady=15)
        right_frame = tk.Frame(self.root, bg="#fff3cd", width=600, padx=15, pady=15)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # ---------- LEFT: ENCODE ----------
        tk.Label(left_frame, text="ENCODE MESSAGE", font=("Helvetica", 18, "bold"), bg="#d9f0ff").pack(pady=10)

        tk.Button(left_frame, text="Choose Image", command=self.choose_encode_image,
                  bg="#007acc", fg="white", font=("Helvetica", 10, "bold")).pack(pady=5)

        self.encode_img_label = tk.Label(left_frame, text="No image selected", bg="#d9f0ff")
        self.encode_img_label.pack()

        tk.Label(left_frame, text="Secret Message:", bg="#d9f0ff", anchor='w', font=("Helvetica", 10)).pack(pady=(10, 0))
        self.message_entry = scrolledtext.ScrolledText(left_frame, height=7, width=60)
        self.message_entry.pack(pady=5)

        tk.Label(left_frame, text="Password:", bg="#d9f0ff").pack()
        self.password_entry = tk.Entry(left_frame, show="*", width=40)
        self.password_entry.pack(pady=5)

        tk.Button(left_frame, text="Encode & Save Image", command=self.encode_and_save,
                  bg="#28a745", fg="white", font=("Helvetica", 10, "bold")).pack(pady=15)

        # ---------- RIGHT: DECODE ----------
        tk.Label(right_frame, text="DECODE MESSAGE", font=("Helvetica", 18, "bold"), bg="#fff3cd").pack(pady=10)

        tk.Button(right_frame, text="Choose Image", command=self.choose_decode_image,
                  bg="#ff9900", fg="white", font=("Helvetica", 10, "bold")).pack(pady=5)

        self.decode_img_label = tk.Label(right_frame, text="No image selected", bg="#fff3cd")
        self.decode_img_label.pack()

        tk.Label(right_frame, text="Password:", bg="#fff3cd").pack()
        self.decode_password_entry = tk.Entry(right_frame, show="*", width=40)
        self.decode_password_entry.pack(pady=5)

        tk.Button(right_frame, text="Decode Message", command=self.decode_message,
                  bg="#d9534f", fg="white", font=("Helvetica", 10, "bold")).pack(pady=15)

        tk.Label(right_frame, text="Decoded Message:", bg="#fff3cd", anchor='w').pack()
        self.decoded_output = scrolledtext.ScrolledText(right_frame, height=8, width=60, bg="#fffef0")
        self.decoded_output.pack(pady=5)

    def choose_encode_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.bmp")])
        if path:
            self.encode_img_path = path
            self.show_image(self.encode_img_label, path)

    def choose_decode_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.bmp")])
        if path:
            self.decode_img_path = path
            self.show_image(self.decode_img_label, path)

    def show_image(self, label, path):
        try:
            img = Image.open(path)
            img.thumbnail((250, 250))
            img = ImageTk.PhotoImage(img)
            label.configure(image=img, text="")
            label.image = img
        except Exception as e:
            label.configure(text="Failed to load image")

    def encode_and_save(self):
        if not self.encode_img_path:
            messagebox.showwarning("No Image", "Please choose an image to encode.")
            return
        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        if not message or not password:
            messagebox.showwarning("Missing Info", "Please provide both message and password.")
            return
        try:
            encrypted = encrypt_message(message, password)
            encoded_img = encode_image(self.encode_img_path, encrypted)
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo("Success", f"Image saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Encoding Failed", str(e))

    def decode_message(self):
        if not self.decode_img_path:
            messagebox.showwarning("No Image", "Please choose an image to decode.")
            return
        password = self.decode_password_entry.get()
        if not password:
            messagebox.showwarning("Missing Password", "Please enter the decryption password.")
            return
        try:
            encrypted_msg = decode_image(self.decode_img_path)
            decrypted_msg = decrypt_message(encrypted_msg, password)
            self.decoded_output.delete("1.0", tk.END)
            self.decoded_output.insert(tk.END, decrypted_msg)
        except Exception as e:
            messagebox.showerror("Decoding Failed", str(e))

# --- MAIN APP ---
if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()
```

## Requirements
- Python 3.x
- tkinter
- pillow
- numpy
- cryptography

Install requirements with:
```bash
pip install pillow numpy cryptography
```

---

*This project is for demonstration and educational purposes only.* 