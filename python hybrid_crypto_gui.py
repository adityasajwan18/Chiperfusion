import os
import threading
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import customtkinter as ctk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

# ========== CONFIG ==========
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ========== CRYPTO UTILS ==========

def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, password: bytes, folder="keys"):
    if not os.path.exists(folder):
        os.makedirs(folder)

    # Save password-protected private key
    with open(os.path.join(folder, "private_key.pem"), "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password),
            )
        )

    # Save public key
    with open(os.path.join(folder, "public_key.pem"), "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def load_keys(password: bytes, folder="keys"):
    try:
        with open(os.path.join(folder, "private_key.pem"), "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=password)

        with open(os.path.join(folder, "public_key.pem"), "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        return private_key, public_key

    except Exception as e:
        raise ValueError("❌ Failed to load keys. Wrong password or missing files.") from e


def hybrid_encrypt(file_path, public_key, progress_callback=None):
    eph_private_key = ec.generate_private_key(ec.SECP384R1())
    eph_public_key = eph_private_key.public_key()
    eph_pub_bytes = eph_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    shared_key = eph_private_key.exchange(ec.ECDH(), public_key)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecc-hybrid").derive(shared_key)
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    encrypted_file = file_path + ".enc"
    total_size = os.path.getsize(file_path)
    processed = 0

    with open(file_path, "rb") as f_in, open(encrypted_file, "wb") as f_out:
        f_out.write(eph_pub_bytes)
        f_out.write(b"---IV---")
        f_out.write(iv)

        while chunk := f_in.read(1024 * 1024):
            f_out.write(encryptor.update(chunk))
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed / total_size * 100)

        f_out.write(encryptor.finalize())

    if progress_callback:
        progress_callback(100)
    return encrypted_file


def hybrid_decrypt(encrypted_file, private_key, progress_callback=None):
    with open(encrypted_file, "rb") as f_in:
        data = f_in.read()

    eph_pub_bytes, rest = data.split(b"---IV---", 1)
    iv = rest[:16]
    ciphertext = rest[16:]

    shared_key = private_key.exchange(ec.ECDH(), serialization.load_pem_public_key(eph_pub_bytes))
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecc-hybrid").derive(shared_key)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_file = encrypted_file.replace(".enc", "_decrypted")
    total_size = len(ciphertext)
    processed = 0

    with open(decrypted_file, "wb") as f_out:
        for i in range(0, len(ciphertext), 1024 * 1024):
            chunk = ciphertext[i:i + 1024 * 1024]
            f_out.write(decryptor.update(chunk))
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed / total_size * 100)

        f_out.write(decryptor.finalize())

    if progress_callback:
        progress_callback(100)
    return decrypted_file

# ========== GUI ==========

class CipherFusionECC(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CipherFusion ECC 🔐 - Hybrid Cryptography")
        self.geometry("750x580")
        self.resizable(False, False)

        self.private_key = None
        self.public_key = None
        self.create_widgets()
        self.bind_drag_drop()

    def create_widgets(self):
        self.label = ctk.CTkLabel(self, text="CipherFusion ECC 🔐", font=("Segoe UI", 28, "bold"))
        self.label.pack(pady=15)

        self.file_entry = ctk.CTkEntry(self, placeholder_text="Drop a file or select manually...", width=500)
        self.file_entry.pack(pady=10)

        self.browse_btn = ctk.CTkButton(self, text="Browse File", command=self.browse_file)
        self.browse_btn.pack(pady=5)

        self.encrypt_btn = ctk.CTkButton(self, text="Encrypt File", fg_color="#007BFF", command=self.encrypt_file)
        self.encrypt_btn.pack(pady=10)

        self.decrypt_btn = ctk.CTkButton(self, text="Decrypt File", fg_color="#FF5733", command=self.decrypt_file)
        self.decrypt_btn.pack(pady=5)

        self.progress_label = ctk.CTkLabel(self, text="Progress:")
        self.progress_label.pack(pady=5)

        self.progress_bar = ctk.CTkProgressBar(self, width=500)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        # --- Key Management Buttons ---
        self.key_frame = ctk.CTkFrame(self)
        self.key_frame.pack(pady=15)

        self.gen_key_btn = ctk.CTkButton(self.key_frame, text="Generate New Keys", fg_color="#28A745", command=self.generate_keys)
        self.gen_key_btn.grid(row=0, column=0, padx=10)

        self.load_key_btn = ctk.CTkButton(self.key_frame, text="Load Existing Keys", fg_color="#FFC107", command=self.load_keys)
        self.load_key_btn.grid(row=0, column=1, padx=10)

        self.theme_label = ctk.CTkLabel(self, text="Theme:")
        self.theme_label.pack(pady=5)

        self.theme_menu = ctk.CTkOptionMenu(self, values=["Dark", "Light", "Green", "Blue"], command=self.change_theme)
        self.theme_menu.pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="Ready.", font=("Segoe UI", 12))
        self.status_label.pack(pady=15)

    # --- FILE HANDLING ---
    def browse_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file)

    # --- ENCRYPTION/DECRYPTION ---
    def encrypt_file(self):
        if not self.public_key:
            messagebox.showerror("Error", "⚠️ Load or generate keys first!")
            return
        file_path = self.file_entry.get().strip()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Select a valid file first.")
            return

        self.status_label.configure(text="Encrypting...")
        self.progress_bar.set(0)
        threading.Thread(target=self._encrypt_task, args=(file_path,)).start()

    def _encrypt_task(self, file_path):
        def update_progress(value):
            self.progress_bar.set(value / 100)
            self.update_idletasks()

        enc_file = hybrid_encrypt(file_path, self.public_key, progress_callback=update_progress)
        self.status_label.configure(text=f"✅ Encrypted: {os.path.basename(enc_file)}")

    def decrypt_file(self):
        if not self.private_key:
            messagebox.showerror("Error", "⚠️ Load private key first!")
            return
        file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc")])
        if not file_path:
            return

        self.status_label.configure(text="Decrypting...")
        self.progress_bar.set(0)
        threading.Thread(target=self._decrypt_task, args=(file_path,)).start()

    def _decrypt_task(self, file_path):
        def update_progress(value):
            self.progress_bar.set(value / 100)
            self.update_idletasks()

        dec_file = hybrid_decrypt(file_path, self.private_key, progress_callback=update_progress)
        self.status_label.configure(text=f"✅ Decrypted: {os.path.basename(dec_file)}")

    # --- KEY MANAGEMENT ---
    def generate_keys(self):
        password = simpledialog.askstring("Password", "Enter a password to protect your key:", show="*")
        if not password:
            messagebox.showerror("Error", "Password required to generate keys.")
            return
        self.private_key, self.public_key = generate_ecc_keys()
        save_keys(self.private_key, self.public_key, password=password.encode())
        messagebox.showinfo("Success", "✅ Keys generated and saved successfully.")
        self.status_label.configure(text="Keys generated and saved.")

    def load_keys(self):
        password = simpledialog.askstring("Password", "Enter your key password:", show="*")
        if not password:
            return
        try:
            self.private_key, self.public_key = load_keys(password=password.encode())
            messagebox.showinfo("Success", "✅ Keys loaded successfully.")
            self.status_label.configure(text="Keys loaded.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # --- THEMES & DRAG-DROP ---
    def change_theme(self, choice):
        themes = {"Dark": "dark-blue", "Light": "light-blue", "Green": "green", "Blue": "blue"}
        ctk.set_default_color_theme(themes.get(choice, "blue"))

    def bind_drag_drop(self):
        def drop(event):
            file = event.data.strip("{}")
            if os.path.isfile(file):
                self.file_entry.delete(0, tk.END)
                self.file_entry.insert(0, file)
        try:
            self.drop_target_register("DND_Files")
            self.dnd_bind("<<Drop>>", drop)
        except Exception:
            pass

if __name__ == "__main__":
    app = CipherFusionECC()
    app.mainloop()
