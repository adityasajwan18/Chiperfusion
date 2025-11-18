import os
import threading
import secrets
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import customtkinter as ctk

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoManager:
    
    @staticmethod
    def generate_ecc_keys():
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_keys(private_key, public_key, password: bytes, folder="keys"):
        if not os.path.exists(folder):
            os.makedirs(folder)

        with open(os.path.join(folder, "private_key.pem"), "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password),
                )
            )

        with open(os.path.join(folder, "public_key.pem"), "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    @staticmethod
    def load_keys(password: bytes, folder="keys"):
        try:
            with open(os.path.join(folder, "private_key.pem"), "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=password)

            with open(os.path.join(folder, "public_key.pem"), "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            return private_key, public_key
        except Exception as e:
            raise ValueError("Invalid password or corrupted key files.") from e

    @staticmethod
    def hybrid_encrypt(file_path, public_key, progress_callback=None):
        eph_private_key = ec.generate_private_key(ec.SECP384R1())
        eph_public_key = eph_private_key.public_key()
        eph_pub_bytes = eph_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        shared_key = eph_private_key.exchange(ec.ECDH(), public_key)
        
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecc-hybrid-gcm"
        ).derive(shared_key)

        iv = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()

        encrypted_file = file_path + ".enc"
        file_size = os.path.getsize(file_path)
        processed = 0

        with open(file_path, "rb") as f_in, open(encrypted_file, "wb") as f_out:
            f_out.write(len(eph_pub_bytes).to_bytes(4, 'big'))
            f_out.write(eph_pub_bytes)
            f_out.write(iv)

            while True:
                chunk = f_in.read(1024 * 1024)
                if not chunk:
                    break
                f_out.write(encryptor.update(chunk))
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed / file_size * 100)

            f_out.write(encryptor.finalize())
            f_out.write(encryptor.tag)

        if progress_callback: progress_callback(100)
        return encrypted_file

    @staticmethod
    def hybrid_decrypt(encrypted_file, private_key, progress_callback=None):
        file_size = os.path.getsize(encrypted_file)
        
        with open(encrypted_file, "rb") as f_in:
            key_len_bytes = f_in.read(4)
            key_len = int.from_bytes(key_len_bytes, 'big')
            eph_pub_bytes = f_in.read(key_len)
            iv = f_in.read(12)
            
            header_size = 4 + key_len + 12
            tag_size = 16
            ciphertext_size = file_size - header_size - tag_size
            
            if ciphertext_size < 0:
                raise ValueError("File corrupted or not a valid encrypted file.")

            try:
                peer_public_key = serialization.load_pem_public_key(eph_pub_bytes)
                shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
                aes_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"ecc-hybrid-gcm"
                ).derive(shared_key)
            except Exception as e:
                raise ValueError("Key exchange failed.") from e

            f_in.seek(-16, 2) 
            tag = f_in.read(16)
            
            f_in.seek(header_size)
            
            decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
            
            decrypted_file = encrypted_file.replace(".enc", "_decrypted")
            processed = 0

            with open(decrypted_file, "wb") as f_out:
                bytes_remaining = ciphertext_size
                
                while bytes_remaining > 0:
                    chunk_size = min(1024 * 1024, bytes_remaining)
                    chunk = f_in.read(chunk_size)
                    f_out.write(decryptor.update(chunk))
                    processed += len(chunk)
                    bytes_remaining -= len(chunk)
                    
                    if progress_callback:
                        progress_callback(processed / ciphertext_size * 100)

                f_out.write(decryptor.finalize())

        if progress_callback: progress_callback(100)
        return decrypted_file


class CipherFusionECC(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CipherFusion ECC 🛡️ - Secure Hybrid Encryption")
        self.geometry("750x600")
        self.resizable(False, False)

        self.private_key = None
        self.public_key = None
        
        self.grid_columnconfigure(0, weight=1)
        self.create_widgets()

    def create_widgets(self):
        self.label = ctk.CTkLabel(self, text="CipherFusion ECC 🛡️", font=("Roboto", 28, "bold"))
        self.label.pack(pady=20)

        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(pady=10, padx=20, fill="x")
        
        self.file_entry = ctk.CTkEntry(self.file_frame, placeholder_text="Select a file...", height=35)
        self.file_entry.pack(side="left", expand=True, fill="x", padx=10, pady=10)
        
        self.browse_btn = ctk.CTkButton(self.file_frame, text="Browse", width=100, command=self.browse_file)
        self.browse_btn.pack(side="right", padx=10, pady=10)

        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=10)

        self.encrypt_btn = ctk.CTkButton(self.action_frame, text="🔒 Encrypt File", fg_color="#1f6aa5", width=160, height=40, command=self.encrypt_file)
        self.encrypt_btn.grid(row=0, column=0, padx=10)

        self.decrypt_btn = ctk.CTkButton(self.action_frame, text="🔓 Decrypt File", fg_color="#b83e3e", width=160, height=40, command=self.decrypt_file)
        self.decrypt_btn.grid(row=0, column=1, padx=10)

        self.progress_label = ctk.CTkLabel(self, text="Ready")
        self.progress_label.pack(pady=(20, 5))

        self.progress_bar = ctk.CTkProgressBar(self, width=500)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        self.key_frame = ctk.CTkFrame(self)
        self.key_frame.pack(pady=30, padx=20, fill="x")
        
        key_lbl = ctk.CTkLabel(self.key_frame, text="Key Management", font=("Roboto", 14, "bold"))
        key_lbl.pack(pady=5)

        self.gen_key_btn = ctk.CTkButton(self.key_frame, text="Generate New Keys", fg_color="#2e8b57", command=self.generate_keys)
        self.gen_key_btn.pack(side="left", expand=True, padx=20, pady=10)

        self.load_key_btn = ctk.CTkButton(self.key_frame, text="Load Existing Keys", fg_color="#d2691e", command=self.load_keys)
        self.load_key_btn.pack(side="right", expand=True, padx=20, pady=10)

        self.theme_switch = ctk.CTkSwitch(self, text="Dark Mode", command=self.toggle_theme, onvalue="Dark", offvalue="Light")
        self.theme_switch.select() 
        self.theme_switch.pack(pady=20)

    def toggle_theme(self):
        mode = self.theme_switch.get()
        ctk.set_appearance_mode(mode)

    def browse_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file)

    def update_progress_safe(self, value):
        self.after(0, lambda: self.progress_bar.set(value / 100))

    def update_status_safe(self, text, is_error=False):
        color = "#ff5555" if is_error else "#ffffff" if ctk.get_appearance_mode() == "Dark" else "#000000"
        self.after(0, lambda: self.progress_label.configure(text=text, text_color=color))

    def encrypt_file(self):
        if not self.public_key:
            messagebox.showwarning("Key Missing", "Please load or generate keys first!")
            return
        
        file_path = self.file_entry.get().strip()
        if not os.path.exists(file_path):
            messagebox.showerror("File Error", "File not found!")
            return

        self.progress_bar.set(0)
        self.progress_label.configure(text="Encrypting...", text_color="white")
        
        threading.Thread(target=self._encrypt_task, args=(file_path,), daemon=True).start()

    def _encrypt_task(self, file_path):
        try:
            out = CryptoManager.hybrid_encrypt(file_path, self.public_key, self.update_progress_safe)
            self.update_status_safe(f"Encryption Complete: {os.path.basename(out)}")
            self.after(0, lambda: messagebox.showinfo("Success", "File Encrypted Successfully!"))
        except Exception as e:
            self.update_status_safe(f"Error: {str(e)}", True)

    def decrypt_file(self):
        if not self.private_key:
            messagebox.showwarning("Key Missing", "Please load your private key first!")
            return
        
        file_path = self.file_entry.get().strip()
        if not os.path.exists(file_path):
            file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted", "*.enc")])
            if not file_path: return

        self.progress_bar.set(0)
        self.progress_label.configure(text="Decrypting & Verifying...", text_color="white")
        
        threading.Thread(target=self._decrypt_task, args=(file_path,), daemon=True).start()

    def _decrypt_task(self, file_path):
        try:
            out = CryptoManager.hybrid_decrypt(file_path, self.private_key, self.update_progress_safe)
            self.update_status_safe(f"Decryption Complete: {os.path.basename(out)}")
            self.after(0, lambda: messagebox.showinfo("Success", "File Decrypted & Verified!"))
        except Exception as e:
            self.update_status_safe("Decryption Failed: Integrity Check Failed or Wrong Key", True)
            self.after(0, lambda: messagebox.showerror("Integrity Error", "Decryption failed.\nEither the password/key is wrong, or the file has been tampered with."))

    def generate_keys(self):
        pwd = simpledialog.askstring("Password", "Set a password for your private key:", show="*")
        if not pwd: return
        
        try:
            self.private_key, self.public_key = CryptoManager.generate_ecc_keys()
            CryptoManager.save_keys(self.private_key, self.public_key, pwd.encode())
            messagebox.showinfo("Keys Generated", "Keys saved to 'keys' folder.")
            self.progress_label.configure(text="New Keys Loaded")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_keys(self):
        pwd = simpledialog.askstring("Password", "Enter private key password:", show="*")
        if not pwd: return
        
        try:
            self.private_key, self.public_key = CryptoManager.load_keys(pwd.encode())
            messagebox.showinfo("Success", "Keys loaded successfully.")
            self.progress_label.configure(text="Keys Loaded Active")
        except Exception as e:
            messagebox.showerror("Load Error", "Incorrect password or missing key files.")

if __name__ == "__main__":
    app = CipherFusionECC()
    app.mainloop()