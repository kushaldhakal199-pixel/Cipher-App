import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox
import random, string, os, base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =========================
# Crypto (AES-256-GCM)
# =========================
KDF_ITERATIONS = 200_000
SALT_LEN = 16           # 128-bit salt for PBKDF2
NONCE_LEN = 12          # 96-bit nonce recommended for GCM

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password required")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # 256-bit key
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def aes_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    # Pack: salt || nonce || ciphertext (ciphertext includes GCM tag at end)
    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode("utf-8")

def aes_decrypt(b64_blob: str, password: str) -> str:
    try:
        blob = base64.b64decode(b64_blob)
    except Exception:
        raise ValueError("Input is not valid Base64.")
    if len(blob) < SALT_LEN + NONCE_LEN + 16:
        # 16 is minimal tag, but ciphertext must be longer than salt+nonce
        raise ValueError("Encrypted data is too short or malformed.")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    ciphertext = blob[SALT_LEN+NONCE_LEN:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")
    return plaintext.decode("utf-8")

# =========================
# UI Actions
# =========================
def do_encrypt():
    text = input_box.get("1.0", tk.END).strip()
    pwd = password_entry.get()
    if not text:
        messagebox.showwarning("Empty", "Please enter text to encrypt.")
        return
    try:
        out = aes_encrypt(text, pwd)
        output_box.configure(state="normal")
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, out)
        output_box.configure(state="disabled")
        status_var.set("Encrypted with AES-256-GCM ✔")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        status_var.set("Error during encryption")

def do_decrypt():
    b64_in = input_box.get("1.0", tk.END).strip()
    pwd = password_entry.get()
    if not b64_in:
        messagebox.showwarning("Empty", "Paste Base64 ciphertext to decrypt.")
        return
    try:
        out = aes_decrypt(b64_in, pwd)
        output_box.configure(state="normal")
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, out)
        output_box.configure(state="disabled")
        status_var.set("Decrypted successfully ✔")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        status_var.set("Error during decryption")

def copy_output():
    data = output_box.get("1.0", tk.END).strip()
    if data:
        root.clipboard_clear()
        root.clipboard_append(data)
        status_var.set("Copied to clipboard")

def clear_all():
    input_box.delete("1.0", tk.END)
    output_box.configure(state="normal")
    output_box.delete("1.0", tk.END)
    output_box.configure(state="disabled")
    password_entry.delete(0, tk.END)
    status_var.set("Cleared")

def toggle_password():
    if show_var.get() == 1:
        password_entry.configure(show="")
    else:
        password_entry.configure(show="•")

# =========================

# =========================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

root = ctk.CTk()
root.title("🔐 AES-256 Matrix Cipher (GCM)")
root.geometry("980x640")

# Matrix background
canvas = tk.Canvas(root, bg="black", highlightthickness=0)
canvas.place(relwidth=1, relheight=1)

columns = 120
drops = [0 for _ in range(columns)]

def draw_matrix():
    canvas.delete("all")
    for i in range(columns):
        char = random.choice(string.ascii_letters + string.digits + "!@#$%^&*")
        x = i * 8
        y = drops[i] * 14
        canvas.create_text(x, y, text=char, fill="#00ff00", font=("Consolas", 11, "bold"))
        if y > root.winfo_height() or random.random() > 0.975:
            drops[i] = 0
        drops[i] += 1
    root.after(45, draw_matrix)

draw_matrix()

# Front panel (glass card)
frame = ctk.CTkFrame(root, corner_radius=24, fg_color="#101010")
frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.9)

title = ctk.CTkLabel(frame, text="AES-256 (GCM) — Matrix Mode", font=("Consolas", 26, "bold"))
title.pack(pady=16)

# Password row
pwd_row = ctk.CTkFrame(frame, fg_color="transparent")
pwd_row.pack(fill="x", padx=20, pady=6)
ctk.CTkLabel(pwd_row, text="Password:", font=("Consolas", 14)).pack(side="left", padx=(0,10))
password_entry = ctk.CTkEntry(pwd_row, width=260, show="•")
password_entry.pack(side="left")

show_var = tk.IntVar(value=0)
show_btn = ctk.CTkCheckBox(pwd_row, text="Show", variable=show_var, command=toggle_password)
show_btn.pack(side="left", padx=10)

# Input label
ctk.CTkLabel(frame, text="Input (plaintext for Encrypt, Base64 for Decrypt):", font=("Consolas", 14)).pack(anchor="w", padx=20, pady=(12,4))
input_box = ctk.CTkTextbox(frame, height=160, corner_radius=16, font=("Consolas", 12))
input_box.pack(padx=20, fill="x")

# Buttons
btns = ctk.CTkFrame(frame, fg_color="transparent")
btns.pack(pady=14)

ctk.CTkButton(btns, text="🔒 Encrypt (AES-256-GCM)", width=220,
              fg_color="#00c9a7", hover_color="#00a189", command=do_encrypt).pack(side="left", padx=10)
ctk.CTkButton(btns, text="🔓 Decrypt", width=120,
              fg_color="#7c4dff", hover_color="#5b35cc", command=do_decrypt).pack(side="left", padx=10)
ctk.CTkButton(btns, text="📋 Copy Output", width=140,
              fg_color="#ff33cc", hover_color="#cc0099", command=copy_output).pack(side="left", padx=10)
ctk.CTkButton(btns, text="❌ Clear", width=100,
              fg_color="#ff4444", hover_color="#cc0000", command=clear_all).pack(side="left", padx=10)

# Output
ctk.CTkLabel(frame, text="Output:", font=("Consolas", 14)).pack(anchor="w", padx=20, pady=(6,4))
output_box = ctk.CTkTextbox(frame, height=160, corner_radius=16, font=("Consolas", 12), state="disabled")
output_box.pack(padx=20, fill="x")

# Status bar
status_var = tk.StringVar(value="Ready")
status = ctk.CTkLabel(root, textvariable=status_var, anchor="w", height=24)
status.pack(side="bottom", fill="x")

root.mainloop()
