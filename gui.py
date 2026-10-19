import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import hashlib
import string
import secrets

ITERATIONS = 390000
SALT_SIZE = 16
HASH_SIZE = 64


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()


def format_size(size):
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def add_history(message):
    history_list.insert(0, message)
    while history_list.size() > 8:
        history_list.delete(tk.END)


def select_files():
    filenames = filedialog.askopenfilenames(title="Select files")
    if not filenames:
        return

    selected_file.set("|".join(filenames))
    try:
        total_size = sum(os.path.getsize(name) for name in filenames)
    except OSError as exc:
        messagebox.showerror("File Error", str(exc))
        return

    info_label.config(
        text=f"{len(filenames)} file(s) selected  •  Total size: {format_size(total_size)}"
    )
    status_label.config(text=f"{len(filenames)} file(s) selected. Ready.")


def encrypt_file():
    files = selected_file.get().split("|")
    password = password_entry.get()

    if not files or files == [""]:
        messagebox.showwarning("No File Selected", "Please select at least one file.")
        return
    if len(password) < 6:
        messagebox.showwarning(
            "Password Required", "Please enter a password with at least 6 characters."
        )
        return

    progress_bar.configure(maximum=len(files), value=0)
    count = 0
    try:
        for filename in files:
            if not os.path.isfile(filename):
                raise FileNotFoundError(f"File not found: {filename}")

            with open(filename, "rb") as source:
                data = source.read()

            salt = os.urandom(SALT_SIZE)
            key = derive_key(password, salt)
            encrypted_data = Fernet(key).encrypt(data)
            digest = calculate_hash(encrypted_data).encode("ascii")
            output_file = filename + ".encrypted"

            with open(output_file, "wb") as destination:
                destination.write(salt + encrypted_data + digest)

            add_history(f"🔒 {os.path.basename(filename)} | ENCRYPTED")
            count += 1
            progress_bar.configure(value=count)
            status_label.config(text=f"Encrypting files: {count}/{len(files)}")
            window.update_idletasks()

        status_label.config(text=f"✓ {count} file(s) encrypted successfully!")
        messagebox.showinfo(
            "Encryption Successful", f"{count} file(s) encrypted successfully!"
        )
    except Exception as exc:
        messagebox.showerror("Encryption Error", str(exc))
        status_label.config(text="✗ Encryption failed.")
    finally:
        # Keep the completed bar visible briefly, then reset it for the next task.
        window.after(1200, lambda: progress_bar.configure(value=0))


def decrypt_file():
    filename = filedialog.askopenfilename(
        title="Select encrypted file",
        filetypes=[("Encrypted Files", "*.encrypted"), ("All Files", "*.*")],
    )
    if not filename:
        return

    password = password_entry.get()
    if len(password) < 6:
        messagebox.showwarning(
            "Password Required", "Enter the password used during encryption."
        )
        return

    try:
        with open(filename, "rb") as source:
            encrypted_file = source.read()

        if len(encrypted_file) <= SALT_SIZE + HASH_SIZE:
            raise ValueError("Invalid or incomplete encrypted file.")

        salt = encrypted_file[:SALT_SIZE]
        encrypted_content = encrypted_file[SALT_SIZE:-HASH_SIZE]
        stored_hash = encrypted_file[-HASH_SIZE:].decode("ascii", errors="strict")

        if calculate_hash(encrypted_content) != stored_hash:
            messagebox.showerror(
                "Integrity Check Failed",
                "The encrypted file has been modified or corrupted.",
            )
            status_label.config(text="✗ Integrity verification failed.")
            return

        key = derive_key(password, salt)
        decrypted_data = Fernet(key).decrypt(encrypted_content)
        output_file = filename[:-len(".encrypted")]

        # Avoid silently overwriting an existing file.
        if os.path.exists(output_file):
            overwrite = messagebox.askyesno(
                "File Already Exists",
                f"{os.path.basename(output_file)} already exists. Replace it?",
            )
            if not overwrite:
                status_label.config(text="Decryption cancelled.")
                return

        with open(output_file, "wb") as destination:
            destination.write(decrypted_data)

        add_history(f"🔓 {os.path.basename(output_file)} | DECRYPTED")
        status_label.config(text="✓ Integrity verified. File decrypted successfully!")
        messagebox.showinfo(
            "Decryption Successful",
            "Integrity verified successfully.\n\nFile decrypted successfully!",
        )
    except InvalidToken:
        messagebox.showerror(
            "Decryption Failed", "Incorrect password or corrupted encrypted file."
        )
        status_label.config(text="✗ Decryption failed.")
    except (OSError, ValueError, UnicodeError) as exc:
        messagebox.showerror("Decryption Error", str(exc))
        status_label.config(text="✗ Decryption failed.")
    except Exception as exc:
        messagebox.showerror("Decryption Error", str(exc))
        status_label.config(text="✗ Decryption failed.")


def check_password_strength(event=None):
    password = password_entry.get()
    if not password:
        text = "Password Strength: Not entered"
    elif len(password) < 6:
        text = "Password Strength: Weak"
    elif (
        len(password) >= 8
        and any(char.isupper() for char in password)
        and any(char.islower() for char in password)
        and any(char.isdigit() for char in password)
        and any(char in "!@#$%^&*()_+-=" for char in password)
    ):
        text = "Password Strength: Strong"
    else:
        text = "Password Strength: Medium"
    strength_label.config(text=text)


def generate_password():
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(characters) for _ in range(14))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    check_password_strength()


def show_password():
    if password_entry.cget("show") == "":
        password_entry.config(show="•")
        show_button.config(text="Show")
    else:
        password_entry.config(show="")
        show_button.config(text="Hide")


def clear_all():
    selected_file.set("")
    password_entry.delete(0, tk.END)
    info_label.config(text="No file selected")
    strength_label.config(text="Password Strength: Not entered")
    status_label.config(text="Ready")
    progress_bar.configure(value=0)


def show_about():
    messagebox.showinfo(
        "About Project",
        "SECURE FILE ENCRYPTION SYSTEM\n\n"
        "Encryption: Fernet authenticated symmetric encryption\n"
        "Key derivation: PBKDF2-HMAC-SHA256\n"
        "Integrity check: SHA-256\n"
        "Programming: Python | GUI: Tkinter\n\n"
        "Purpose: Protect files from unauthorized access using password-based cryptography.",
    )


# -------------------- MAIN WINDOW --------------------
window = tk.Tk()
window.title("Secure File Encryption System")
window.geometry("780x700")
window.minsize(700, 650)
window.configure(bg="#eef2f7")

header = tk.Frame(window, bg="#182848", padx=12, pady=12)
header.pack(fill="x")

tk.Label(
    header,
    text="🔐 Secure File Encryption",
    bg="#182848",
    fg="white",
    font=("Segoe UI", 21, "bold"),
).pack(pady=(0, 2))

tk.Label(
    header,
    text="Password-Protected File Security System",
    bg="#182848",
    fg="#dbeafe",
    font=("Segoe UI", 10),
).pack()

card = tk.Frame(window, bg="white", padx=22, pady=12)
card.pack(padx=22, pady=10, fill="both", expand=True)

tk.Label(
    card, text="1. Select File(s)", bg="white", fg="#182848", font=("Segoe UI", 11, "bold")
).pack(anchor="w")

tk.Button(
    card,
    text="📁  Choose File(s)",
    command=select_files,
    bg="#2563eb",
    fg="white",
    activebackground="#1d4ed8",
    activeforeground="white",
    font=("Segoe UI", 10, "bold"),
    width=23,
    height=1,
    relief="flat",
    cursor="hand2",
).pack(pady=5)

selected_file = tk.StringVar()
info_label = tk.Label(
    card,
    text="No file selected",
    bg="#f1f5f9",
    fg="#475569",
    font=("Segoe UI", 9),
    width=62,
    pady=7,
    wraplength=650,
)
info_label.pack(pady=3)

tk.Label(
    card, text="2. Enter Password", bg="white", fg="#182848", font=("Segoe UI", 11, "bold")
).pack(anchor="w", pady=(7, 3))

password_frame = tk.Frame(card, bg="white")
password_frame.pack()
password_entry = tk.Entry(password_frame, width=30, show="•", font=("Segoe UI", 11), relief="solid", bd=1)
password_entry.pack(side="left", ipady=4)
show_button = tk.Button(password_frame, text="Show", command=show_password, width=7)
show_button.pack(side="left", padx=5)

tk.Label(card, text="Minimum 6 characters", bg="white", fg="#64748b", font=("Segoe UI", 8)).pack(pady=1)
strength_label = tk.Label(
    card, text="Password Strength: Not entered", bg="white", fg="#64748b", font=("Segoe UI", 9, "bold")
)
strength_label.pack(pady=1)
password_entry.bind("<KeyRelease>", check_password_strength)

tk.Button(
    card,
    text="🔑 Generate Strong Password",
    command=generate_password,
    bg="#7c3aed",
    fg="white",
    activebackground="#6d28d9",
    activeforeground="white",
    font=("Segoe UI", 9, "bold"),
    width=25,
    height=1,
    relief="flat",
    cursor="hand2",
).pack(pady=4)

button_frame = tk.Frame(card, bg="white")
button_frame.pack(pady=5)

tk.Button(
    button_frame, text="🔒  Encrypt", command=encrypt_file, bg="#16a34a", fg="white",
    activebackground="#15803d", activeforeground="white", font=("Segoe UI", 10, "bold"),
    width=16, height=1, relief="flat", cursor="hand2"
).pack(side="left", padx=6)

tk.Button(
    button_frame, text="🔓  Decrypt", command=decrypt_file, bg="#ea580c", fg="white",
    activebackground="#c2410c", activeforeground="white", font=("Segoe UI", 10, "bold"),
    width=16, height=1, relief="flat", cursor="hand2"
).pack(side="left", padx=6)

status_label = tk.Label(
    card, text="Ready", bg="#ecfdf5", fg="#166534", font=("Segoe UI", 9, "bold"), width=62, pady=5
)
status_label.pack(pady=3)

progress_bar = ttk.Progressbar(card, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(fill="x", padx=15, pady=3)
progress_bar["value"] = 0

tk.Label(card, text="Recent Activity", bg="white", fg="#182848", font=("Segoe UI", 10, "bold")).pack(
    anchor="w", pady=(5, 2)
)
history_list = tk.Listbox(card, width=65, height=3, font=("Segoe UI", 9), bg="#f8fafc", fg="#334155")
history_list.pack(fill="x")

bottom_frame = tk.Frame(window, bg="#eef2f7")
bottom_frame.pack(pady=(0, 5))
tk.Button(bottom_frame, text="Clear", command=clear_all, width=13).pack(side="left", padx=5)
tk.Button(bottom_frame, text="About Project", command=show_about, width=13).pack(side="left", padx=5)
tk.Label(
    window, text="CNS Mini Project • Secure Data Protection", bg="#eef2f7", fg="#64748b", font=("Segoe UI", 8)
).pack(pady=(0, 4))

window.mainloop()
