import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox
import os
import json
import hashlib
import base58
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ecdsa
import subprocess
import sys
from seed2privatekey import seed_to_private_key
from XSNFTP import get_info, get_file, cast_file, transfer_file
from sha256_22 import sha256_22

PRIVATE_KEY_FILE = "private_key.json"
NFT_STORAGE_FILE = "my_nfts.json"
NFT_DOWNLOAD_DIR = "download_nft_files"
KEY_SIZE = 32

class XSNFTP_GUI(tb.Window):
    def __init__(self, theme='superhero'):
        super().__init__(themename=theme)
        self.title("XSNFTP Wallet")
        self.geometry("950x750")

        self.private_key = None
        self.current_password = None
        self.wallet_address = None

        if not os.path.exists(NFT_DOWNLOAD_DIR):
            try:
                os.makedirs(NFT_DOWNLOAD_DIR)
            except OSError as e:
                Messagebox.show_error(f"Could not create base NFT download directory '{NFT_DOWNLOAD_DIR}': {e}", "Startup Error")

        self.setup_initial_screen()

    def log_message(self, message, level="info"):
        if hasattr(self, 'log_area'):
            self.log_area.configure(state='normal')
            tag = ()
            log_prefix = ""
            if level == "error":
                tag = ('error',)
                log_prefix = "ERROR: "
            elif level == "success":
                tag = ('success',)
                log_prefix = "SUCCESS: "
            elif level == "warning":
                tag = ('warning',)
                log_prefix = "WARNING: "

            self.log_area.insert(tk.END, log_prefix + message + "\n", tag)
            self.log_area.configure(state='disabled')
            self.log_area.see(tk.END)
        else:
            print(message)

    def _encrypt_data(self, data, password):
        key = hashlib.sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base58.b58encode(cipher.iv + ct_bytes).decode('utf-8')

    def _decrypt_data(self, encrypted_data, password):
        key = hashlib.sha256(password.encode()).digest()
        encrypted_data_bytes = base58.b58decode(encrypted_data.encode('utf-8'))
        iv = encrypted_data_bytes[:AES.block_size]
        ct = encrypted_data_bytes[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

    def _load_private_key_from_file(self, password):
        if os.path.exists(PRIVATE_KEY_FILE):
            try:
                with open(PRIVATE_KEY_FILE, "r") as file:
                    data = json.load(file)
                encrypted_private_key = data.get("private_key")
                if not encrypted_private_key:
                    self.log_message("Private key not found in file.", "error")
                    return None
                private_key = self._decrypt_data(encrypted_private_key, password)
                self.log_message("Private key decrypted successfully.")
                return private_key
            except json.JSONDecodeError:
                self.log_message(f"Error reading {PRIVATE_KEY_FILE}. File might be corrupted.", "error")
                return "Incorrect password"
            except Exception:
                self.log_message("Decryption failed. Likely incorrect password or corrupted data.", "error")
                return "Incorrect password"
        else:
            self.log_message(f"{PRIVATE_KEY_FILE} not found.", "info")
            return None

    def _save_private_key_to_file(self, private_key, password):
        try:
            encrypted_private_key = self._encrypt_data(private_key, password)
            with open(PRIVATE_KEY_FILE, "w") as file:
                json.dump({"private_key": encrypted_private_key}, file)
            self.log_message("Private key has been encrypted and saved.", "success")
            Messagebox.show_info("Key Saved", "Your private key has been encrypted and saved successfully.")
            self.current_password = password
        except Exception as e:
            self.log_message(f"Failed to save private key: {e}", "error")
            Messagebox.show_error(f"Failed to save private key: {e}", "Save Error")

    def _get_private_key_from_inputs(self, mnemonic=None, private_key_hex=None):
        if mnemonic:
            try:
                pk_bytes = seed_to_private_key(mnemonic)
                return pk_bytes.hex()
            except Exception as e:
                self.log_message(f"Error generating key from mnemonic: {e}", "error")
                Messagebox.show_error(f"Error generating key from mnemonic: {e}", "Mnemonic Error")
                return None
        elif private_key_hex:
            if all(c in '0123456789abcdefABCDEF' for c in private_key_hex) and len(private_key_hex) == 64:
                 return private_key_hex
            else:
                self.log_message("Invalid private key format. Must be a 64-character hex string.", "error")
                Messagebox.show_error("Invalid private key format. Must be a 64-character hex string.", "Key Format Error")
                return None
        else:
            self.log_message("You must provide either a mnemonic or private key hex.", "error")
            Messagebox.show_error("Input Error", "You must provide either a mnemonic or a private key hex string.")
            return None

    def _private_key_to_address(self, private_key_hex):
        try:
            private_key_bytes = bytes.fromhex(private_key_hex)
            private_key_obj = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            public_key = private_key_obj.get_verifying_key()
            x = public_key.pubkey.point.x()
            y = public_key.pubkey.point.y()
            prefix = b'\x02' if y % 2 == 0 else b'\x03'
            x_bin = x.to_bytes(32, 'big')
            compressed_pubkey = prefix + x_bin
            sha256_hash = hashlib.sha256(compressed_pubkey).digest()
            ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
            pubkey_hash = ripemd160_hash
            checksum = hashlib.sha256(hashlib.sha256(pubkey_hash).digest()).digest()[:4]
            address_bin = pubkey_hash + checksum
            address_str = base58.b58encode(address_bin).decode('utf-8')
            return address_str
        except Exception as e:
            self.log_message(f"Error deriving address from private key: {e}", "error")
            Messagebox.show_error(f"Could not derive address from private key: {e}", "Address Derivation Error")
            return None

    def setup_initial_screen(self):
        self.initial_frame = tb.Frame(self, padding=20)
        self.initial_frame.pack(expand=True, fill=tk.BOTH)
        tb.Label(self.initial_frame, text="XSNFTP Wallet Setup/Login", font=("Helvetica", 16, "bold")).pack(pady=20)

        self.log_area_initial = scrolledtext.ScrolledText(self.initial_frame, height=8, width=80, wrap=tk.WORD, state='disabled')
        self.log_area_initial.pack(pady=10, padx=10, fill=tk.X)
        self.log_area_initial.tag_config('error', foreground='red')
        self.log_area_initial.tag_config('success', foreground='green')
        self.log_area_initial.tag_config('warning', foreground='orange')
        self.log_area = self.log_area_initial

        login_frame = tb.Labelframe(self.initial_frame, text="Login with Existing Key", padding=15)
        login_frame.pack(pady=10, padx=10, fill=tk.X)
        tb.Label(login_frame, text="Enter Password:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tb.Entry(login_frame, show="*", width=40)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.password_entry.bind("<Return>", lambda event: self.attempt_login())
        self.login_button = tb.Button(login_frame, text="Login / Load Key", command=self.attempt_login, style="success.TButton")
        self.login_button.grid(row=0, column=2, padx=10, pady=5)

        self.import_frame = tb.Labelframe(self.initial_frame, text="Import or Setup New Key", padding=15)
        self.import_frame.pack(pady=10, padx=10, fill=tk.X)
        tb.Label(self.import_frame, text="Mnemonic (leave empty if using private key hex):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.mnemonic_entry = tb.Entry(self.import_frame, width=50)
        self.mnemonic_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text="Or Private Key (Hex):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.pk_hex_entry = tb.Entry(self.import_frame, width=50)
        self.pk_hex_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text="Set New Password (for this key):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.new_password_entry = tb.Entry(self.import_frame, show="*", width=40)
        self.new_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text="Confirm New Password:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.confirm_password_entry = tb.Entry(self.import_frame, show="*", width=40)
        self.confirm_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.import_button = tb.Button(self.import_frame, text="Import and Save Key", command=self.import_and_save_key, style="primary.TButton")
        self.import_button.grid(row=4, column=1, pady=10, sticky="e")
        
        self.log_message("Welcome! Enter your password to load an existing key, or import a new one.")
        if not os.path.exists(PRIVATE_KEY_FILE):
            self.log_message(f"{PRIVATE_KEY_FILE} not found. Please use the 'Import or Setup New Key' section.", "warning")
            self.password_entry.configure(state="disabled")
            self.login_button.configure(state="disabled")

    def attempt_login(self):
        password = self.password_entry.get()
        if not password:
            Messagebox.show_warning("Password cannot be empty.", "Login Warning")
            return

        private_key_loaded = self._load_private_key_from_file(password)

        if private_key_loaded and private_key_loaded != "Incorrect password":
            self.private_key = private_key_loaded
            self.current_password = password
            self.wallet_address = self._private_key_to_address(self.private_key)
            if self.wallet_address:
                self.log_message("Login successful! Wallet address derived.", "success")
                Messagebox.show_info("Login Success", f"Successfully loaded wallet.\nAddress: {self.wallet_address}")
                self.initial_frame.pack_forget()
                self.destroy_initial_screen_widgets()
                self.setup_main_application()
            else:
                self.log_message("Failed to derive wallet address from loaded key.", "error")
                self.private_key = None
                self.current_password = None
        elif private_key_loaded == "Incorrect password":
            self.log_message("Incorrect password. Please try again or import key.", "error")
            Messagebox.show_error("Incorrect password. Please try again.", "Login Failed")
        else:
             self.log_message(f"{PRIVATE_KEY_FILE} not found. Please use the 'Import or Setup New Key' section.", "info")
             Messagebox.show_info("No Key File", f"{PRIVATE_KEY_FILE} not found. Please import a key.")
             self.password_entry.configure(state="disabled")
             self.login_button.configure(state="disabled")

    def import_and_save_key(self):
        mnemonic = self.mnemonic_entry.get().strip()
        pk_hex = self.pk_hex_entry.get().strip()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not (mnemonic or pk_hex):
            Messagebox.show_warning("Please enter either a mnemonic or a private key hex.", "Import Warning")
            return
        if mnemonic and pk_hex:
            Messagebox.show_warning("Please provide EITHER a mnemonic OR a private key, not both.", "Input Error")
            return
        if not new_password or not confirm_password:
            Messagebox.show_warning("Please enter and confirm your new password.", "Password Warning")
            return
        if new_password != confirm_password:
            Messagebox.show_error("Passwords do not match.", "Password Error")
            return

        temp_pk = self._get_private_key_from_inputs(mnemonic=mnemonic, private_key_hex=pk_hex)

        if temp_pk:
            self._save_private_key_to_file(temp_pk, new_password) # This will show its own success/error messagebox
            self.private_key = temp_pk
            self.current_password = new_password
            self.wallet_address = self._private_key_to_address(self.private_key)
            if self.wallet_address:
                self.log_message("Key imported, saved, and wallet address derived!", "success")
                Messagebox.show_info("Import Success", f"Key imported and wallet address derived.\nAddress: {self.wallet_address}")
                self.initial_frame.pack_forget()
                self.destroy_initial_screen_widgets()
                self.setup_main_application()
            else: # _private_key_to_address would have shown error
                self.log_message("Key imported and saved, but failed to derive wallet address.", "error")
                self.private_key = None 
                self.current_password = None

    def destroy_initial_screen_widgets(self):
        if hasattr(self, 'initial_frame'):
            for widget in self.initial_frame.winfo_children():
                widget.destroy()
            self.initial_frame.destroy()
            del self.initial_frame
        if hasattr(self, 'log_area_initial'):
             del self.log_area_initial

    def setup_main_application(self):
        main_frame = tb.Frame(self, padding=10)
        main_frame.pack(expand=True, fill=tk.BOTH)

        header_frame = tb.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0,10))
        tb.Label(header_frame, text="XSNFTP Wallet", font=("Helvetica", 18, "bold")).pack(side=tk.LEFT)
        if self.wallet_address:
            tb.Label(header_frame, text=f"Your Address: {self.wallet_address}", font=("Courier", 10)).pack(side=tk.RIGHT, padx=10)

        log_frame = tb.Labelframe(main_frame, text="Activity Log", padding=5)
        log_frame.pack(pady=10, padx=5, fill=tk.BOTH, expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, width=100, wrap=tk.WORD, state='disabled')
        self.log_area.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        self.log_area.tag_config('error', foreground='red')
        self.log_area.tag_config('success', foreground='green')
        self.log_area.tag_config('warning', foreground='orange')

        self.log_message(f"Wallet loaded. Address: {self.wallet_address}", "success")
        # Welcome messages for log can stay.

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill='both', pady=10)

        info_tab = tb.Frame(notebook, padding=10)
        notebook.add(info_tab, text='NFT Info')
        self.setup_info_tab(info_tab)

        get_nft_file_tab = tb.Frame(notebook, padding=10)
        notebook.add(get_nft_file_tab, text='Get a NFT File')
        self.setup_get_nft_file_tab(get_nft_file_tab)

        cast_nft_file_tab = tb.Frame(notebook, padding=10)
        notebook.add(cast_nft_file_tab, text='Cast a NFT File')
        self.setup_cast_nft_file_tab(cast_nft_file_tab)

        transfer_tab = tb.Frame(notebook, padding=10)
        notebook.add(transfer_tab, text='Transfer NFT')
        self.setup_transfer_tab(transfer_tab)

        my_nfts_tab = tb.Frame(notebook, padding=10)
        notebook.add(my_nfts_tab, text='My NFTs')
        self.setup_my_nfts_tab(my_nfts_tab)

    def setup_info_tab(self, tab):
        tb.Label(tab, text="Get Information about an NFT", font=("Helvetica", 12)).pack(pady=10)
        entry_frame = tb.Frame(tab)
        entry_frame.pack(pady=5, fill=tk.X)
        tb.Label(entry_frame, text="NFT Address:").pack(side=tk.LEFT, padx=5)
        self.info_nft_address_entry = tb.Entry(entry_frame, width=60)
        self.info_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(tab, text="Get Info", command=self.gui_get_info, style="primary.TButton").pack(pady=10)

    def gui_get_info(self):
        if not self.private_key:
            self.log_message("Private key not loaded.", "error")
            Messagebox.show_error("Error: Private key is not loaded.", "Key Error")
            return

        nft_address = self.info_nft_address_entry.get().strip()
        if not nft_address:
            Messagebox.show_warning("Please provide the NFT address.", "Input Error")
            self.log_message("NFT address cannot be empty for 'get_info'.", "error")
            return

        self.log_message(f"Executing: get_info {nft_address}")
        try:
            info = get_info(nft_address)
            if not info or info.get("owner") is None:
                msg = f"Failed to get NFT info for {nft_address}. The NFT might not exist or there was a network error."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Get Info Failed")
                return

            owner_str = info["owner"].decode('utf-8', 'replace') if isinstance(info["owner"], bytes) else str(info["owner"])
            user_address_hashed_for_nft_owner_check = sha256_22(self.wallet_address).encode()
            owner_indicator = " (you)" if info["owner"] == user_address_hashed_for_nft_owner_check else ""
            name_str = info["name"].decode('utf-8', 'replace') if isinstance(info["name"], bytes) else str(info["name"])
            
            info_message = (f"Information for NFT: {nft_address}\n"
                            f"-----------------------------------\n"
                            f"Owner: {owner_str}{owner_indicator}\n"
                            f"Name: {name_str}")
            self.log_message(f"Info for NFT {nft_address}: Owner: {owner_str}{owner_indicator}, Name: {name_str}", "info")
            Messagebox.show_info("NFT Information", info_message)

        except Exception as e:
            self.log_message(f"An error occurred during get_info: {e}", "error")
            Messagebox.show_error(f"An error occurred while getting NFT info: {e}", "Get Info Error")

    def setup_get_nft_file_tab(self, tab): # New method, derived from old files_tab
        tb.Label(tab, text="Download File from NFT", font=("Helvetica", 11)).pack(pady=10)
        
        gf_nft_frame = tb.Frame(tab)
        gf_nft_frame.pack(pady=5, fill=tk.X)
        tb.Label(gf_nft_frame, text="NFT Address:").pack(side=tk.LEFT, padx=5)
        self.get_file_nft_address_entry = tb.Entry(gf_nft_frame, width=50)
        self.get_file_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        gf_dir_frame = tb.Frame(tab)
        gf_dir_frame.pack(pady=5, fill=tk.X)
        tb.Label(gf_dir_frame, text="Output Directory:").pack(side=tk.LEFT, padx=5)
        self.get_file_output_dir_entry = tb.Entry(gf_dir_frame, width=40)
        self.get_file_output_dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(gf_dir_frame, text="Browse...", command=self.browse_output_directory_for_get_file).pack(side=tk.LEFT, padx=5)

        tb.Button(tab, text="Get NFT File", command=self.gui_get_file, style="primary.TButton").pack(pady=10)

    def setup_cast_nft_file_tab(self, tab): # New method, derived from old files_tab
        tb.Label(tab, text="Publish File to an NFT", font=("Helvetica", 11)).pack(pady=10)

        cf_file_frame = tb.Frame(tab)
        cf_file_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_file_frame, text="File Path to Cast:").pack(side=tk.LEFT, padx=5)
        self.cast_file_path_entry = tb.Entry(cf_file_frame, width=40)
        self.cast_file_path_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(cf_file_frame, text="Browse...", command=self.browse_cast_file_path).pack(side=tk.LEFT, padx=5)
        
        cf_nft_addr_frame = tb.Frame(tab)
        cf_nft_addr_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_nft_addr_frame, text="Target NFT Address (New/Existing):").pack(side=tk.LEFT, padx=5)
        self.cast_file_nft_address_entry = tb.Entry(cf_nft_addr_frame, width=40)
        self.cast_file_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        cf_name_frame = tb.Frame(tab)
        cf_name_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_name_frame, text="NFT Name (for this file):").pack(side=tk.LEFT, padx=5)
        self.cast_file_name_entry = tb.Entry(cf_name_frame, width=40)
        self.cast_file_name_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        tb.Button(tab, text="Cast NFT File", command=self.gui_cast_file, style="success.TButton").pack(pady=10)

    def browse_output_directory_for_get_file(self): # Renamed for clarity
        directory = filedialog.askdirectory()
        if directory:
            self.get_file_output_dir_entry.delete(0, tk.END)
            self.get_file_output_dir_entry.insert(0, directory)

    def browse_cast_file_path(self): # Renamed for clarity
        filepath = filedialog.askopenfilename()
        if filepath:
            self.cast_file_path_entry.delete(0, tk.END)
            self.cast_file_path_entry.insert(0, filepath)

    def gui_get_file(self):
        if not self.private_key:
            Messagebox.show_error("Private key not loaded.", "Key Error"); self.log_message("Attempted Get File with no key.", "error"); return
        nft_address = self.get_file_nft_address_entry.get().strip()
        output_dir = self.get_file_output_dir_entry.get().strip()

        if not nft_address or not output_dir:
            Messagebox.show_warning("NFT Address and Output Directory are required.", "Input Error")
            self.log_message("NFT Address and Output Directory cannot be empty for 'get_file'.", "error")
            return

        self.log_message(f"Executing: get_file {nft_address} to {output_dir}")
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                self.log_message(f"Output directory '{output_dir}' did not exist. Created it.", "info")
            except OSError as e:
                self.log_message(f"Could not create output directory '{output_dir}': {e}", "error")
                Messagebox.show_error(f"Error creating directory: {e}", "Directory Error")
                return
        
        try:
            success = get_file(nft_address, output_dir)
            if success:
                msg = f"File(s) for NFT {nft_address} requested/downloaded to {output_dir}."
                self.log_message(msg, "success")
                Messagebox.show_info("Download Initiated/Completed", msg)
            else:
                msg = f"Failed to get file for NFT {nft_address}. The operation returned failure."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Download Error")
        except Exception as e:
            self.log_message(f"An error occurred during get_file: {e}", "error")
            Messagebox.show_error(f"Error getting file: {e}", "Download Error")

    def gui_cast_file(self):
        if not self.private_key:
            Messagebox.show_error("Private key not loaded.", "Key Error"); self.log_message("Attempted Cast File with no key.", "error"); return
        file_path = self.cast_file_path_entry.get().strip()
        nft_address_cast = self.cast_file_nft_address_entry.get().strip()
        name = self.cast_file_name_entry.get().strip()

        if not file_path or not nft_address_cast or not name:
            Messagebox.show_warning("File Path, Target NFT Address, and NFT Name are required.", "Input Error")
            self.log_message("File Path, NFT Address, and NFT Name cannot be empty for 'cast_file'.", "error")
            return
        
        if not os.path.exists(file_path):
            Messagebox.show_error(f"File not found: {file_path}", "File Error")
            self.log_message(f"File path does not exist: {file_path}", "error")
            return

        self.log_message(f"Executing: cast_file {file_path} to NFT {nft_address_cast} with name {name}")
        try:
            current_user_address = self.wallet_address
            success = cast_file(file_path, current_user_address, nft_address_cast, name, self.private_key)

            if success:
                msg = f"File '{os.path.basename(file_path)}' cast successfully to NFT {nft_address_cast} with name '{name}'!"
                self.log_message(msg, "success")
                Messagebox.show_info("Success", msg)
            else:
                msg = "Failed to cast the file. The operation returned failure."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Cast Error")
        except Exception as e:
            self.log_message(f"An error occurred during cast_file: {e}", "error")
            Messagebox.show_error(f"Error casting file: {e}", "Cast Error")

    def setup_transfer_tab(self, tab):
        tb.Label(tab, text="Transfer an NFT to Another Address", font=("Helvetica", 12)).pack(pady=10)
        nft_addr_frame = tb.Frame(tab)
        nft_addr_frame.pack(pady=5, fill=tk.X)
        tb.Label(nft_addr_frame, text="NFT Address to Transfer:").pack(side=tk.LEFT, padx=5)
        self.transfer_nft_address_entry = tb.Entry(nft_addr_frame, width=50)
        self.transfer_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        recipient_frame = tb.Frame(tab)
        recipient_frame.pack(pady=5, fill=tk.X)
        tb.Label(recipient_frame, text="Recipient Address:").pack(side=tk.LEFT, padx=5)
        self.transfer_recipient_address_entry = tb.Entry(recipient_frame, width=50)
        self.transfer_recipient_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(tab, text="Transfer NFT", command=self.gui_transfer_nft, style="warning.TButton").pack(pady=20)

    def gui_transfer_nft(self):
        if not self.private_key:
            Messagebox.show_error("Private key not loaded.", "Key Error"); self.log_message("Attempted Transfer with no key.", "error"); return

        nft_address_transfer = self.transfer_nft_address_entry.get().strip()
        to_address = self.transfer_recipient_address_entry.get().strip()

        if not nft_address_transfer or not to_address:
            Messagebox.show_warning("NFT Address to transfer and Recipient Address are required.", "Input Error")
            self.log_message("NFT Address and Recipient Address cannot be empty for 'transfer'.", "error")
            return

        self.log_message(f"Executing: transfer {nft_address_transfer} to {to_address}")
        try:
            current_user_address = self.wallet_address
            success = transfer_file(current_user_address, self.private_key, to_address, nft_address_transfer)

            if success:
                msg = f"NFT {nft_address_transfer} transferred successfully to {to_address}!"
                self.log_message(msg, "success")
                Messagebox.show_info("Success", msg)
                self.refresh_my_nfts_list()
            else:
                msg = f"Failed to transfer NFT {nft_address_transfer}. You might not be the owner or an error occurred."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Transfer Error")
        except Exception as e:
            self.log_message(f"An error occurred during transfer: {e}", "error")
            Messagebox.show_error(f"Error transferring NFT: {e}", "Transfer Error")

    def setup_my_nfts_tab(self, tab):
        controls_frame = tb.Frame(tab)
        controls_frame.pack(fill=tk.X, pady=5)

        tb.Label(controls_frame, text="Add NFT you own:", font=("Helvetica", 10)).pack(side=tk.LEFT, pady=5)
        self.add_nft_address_entry = tb.Entry(controls_frame, width=30) # Adjusted width
        self.add_nft_address_entry.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        tb.Button(controls_frame, text="Add NFT", command=self.gui_add_nft, style="info.TButton").pack(side=tk.LEFT, padx=5, pady=5)
        tb.Button(controls_frame, text="Refresh List", command=self.refresh_my_nfts_list, style="secondary.TButton").pack(side=tk.LEFT, padx=5, pady=5)

        columns = ("name", "address", "local_path") # Added local_path
        self.nft_tree = ttk.Treeview(tab, columns=columns, show="headings", bootstyle="primary")
        self.nft_tree.heading("name", text="NFT Name")
        self.nft_tree.heading("address", text="NFT Address")
        self.nft_tree.heading("local_path", text="Local Path") # New heading

        self.nft_tree.column("name", width=180, anchor=tk.W)
        self.nft_tree.column("address", width=300, anchor=tk.W)
        self.nft_tree.column("local_path", width=250, anchor=tk.W) # New column

        self.nft_tree.pack(expand=True, fill="both", pady=10)
        self.nft_tree.bind("<<TreeviewSelect>>", self.on_nft_select_from_tree)
        self.nft_tree.bind("<Double-1>", self.on_nft_double_click) # Bind double-click

        self.refresh_my_nfts_list()

    def on_nft_select_from_tree(self, event):
        selected_item = self.nft_tree.focus()
        if not selected_item: return
        
        item_values = self.nft_tree.item(selected_item, "values")
        if item_values and len(item_values) >= 2: # local_path might be missing for older entries
            nft_name, nft_address = item_values[0], item_values[1]
            
            if hasattr(self, 'info_nft_address_entry'):
                self.info_nft_address_entry.delete(0, tk.END); self.info_nft_address_entry.insert(0, nft_address)
            if hasattr(self, 'get_file_nft_address_entry'):
                self.get_file_nft_address_entry.delete(0, tk.END); self.get_file_nft_address_entry.insert(0, nft_address)
            if hasattr(self, 'transfer_nft_address_entry'):
                self.transfer_nft_address_entry.delete(0, tk.END); self.transfer_nft_address_entry.insert(0, nft_address)
            if hasattr(self, 'add_nft_address_entry'):
                self.add_nft_address_entry.delete(0, tk.END); self.add_nft_address_entry.insert(0, nft_address)
            self.log_message(f"Selected '{nft_name}' ({nft_address}). NFT address copied to relevant fields.", "info")

    def on_nft_double_click(self, event):
        selected_item_id = self.nft_tree.focus()
        if not selected_item_id: return

        item_values = self.nft_tree.item(selected_item_id, "values")
        if item_values and len(item_values) == 3:
            local_path = item_values[2]
            if local_path and local_path != "N/A" and os.path.exists(local_path):
                try:
                    self.log_message(f"Opening local path: {local_path}", "info")
                    if sys.platform == "win32":
                        os.startfile(os.path.realpath(local_path))
                    elif sys.platform == "darwin":
                        subprocess.call(['open', os.path.realpath(local_path)])
                    else: # Assume Linux or other Unix-like system
                        subprocess.call(['xdg-open', os.path.realpath(local_path)])
                except Exception as e:
                    self.log_message(f"Failed to open path {local_path}: {e}", "error")
                    Messagebox.show_error(f"Could not open path '{local_path}':\n{e}", "File Open Error")
            elif local_path and local_path != "N/A":
                self.log_message(f"Local path {local_path} does not exist.", "warning")
                Messagebox.show_warning(f"The path '{local_path}' does not exist or could not be accessed.", "Path Not Found")
            else:
                self.log_message("No local path stored or available for this NFT.", "info")
                Messagebox.show_info("No Local Path", "No local path is stored for the selected NFT.")


    def _load_nft_storage(self):
        if os.path.exists(NFT_STORAGE_FILE):
            try:
                with open(NFT_STORAGE_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self.log_message(f"Error decoding {NFT_STORAGE_FILE}. Starting with empty storage.", "error")
                return {}
        return {}

    def _save_nft_storage(self, nft_storage_data):
        try:
            with open(NFT_STORAGE_FILE, "w") as f:
                json.dump(nft_storage_data, f, indent=4)
        except Exception as e:
            self.log_message(f"Error saving NFT storage: {e}", "error")
            Messagebox.show_error(f"Could not save NFT collection to file: {e}", "Storage Save Error")


    def gui_add_nft(self):
        if not self.private_key or not self.wallet_address:
            Messagebox.show_error("Private key or wallet address not loaded.", "Key Error"); self.log_message("Attempted Add NFT with no key/address.", "error"); return

        nft_address_to_add = self.add_nft_address_entry.get().strip()
        if not nft_address_to_add:
            Messagebox.show_warning("Please provide the NFT address to add.", "Input Error")
            self.log_message("NFT address cannot be empty for 'add_nft'.", "error")
            return

        self.log_message(f"Attempting to add NFT: {nft_address_to_add}")
        try:
            info = get_info(nft_address_to_add)
            if not info or info.get("owner") is None:
                msg = f"Failed to get info for NFT {nft_address_to_add}. Cannot verify ownership."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Add NFT Error")
                return

            user_owner_hash_expected = sha256_22(self.wallet_address).encode()
            if info["owner"] != user_owner_hash_expected:
                msg = f"You are not the owner of NFT {nft_address_to_add}. Cannot add."
                self.log_message(msg, "error")
                Messagebox.show_error(msg, "Ownership Error")
                return

            nft_storage = self._load_nft_storage()
            my_nfts_list = nft_storage.get(self.wallet_address, [])
            for nft_entry in my_nfts_list:
                if nft_entry.get("address") == nft_address_to_add:
                    self.log_message(f"NFT {nft_address_to_add} is already in your collection.", "info")
                    Messagebox.show_info("Already Added", "This NFT is already in your collection.")
                    return
            
            nft_local_storage_path = os.path.join(NFT_DOWNLOAD_DIR, nft_address_to_add)
            download_message_suffix = ""
            try:
                if not os.path.exists(nft_local_storage_path):
                    os.makedirs(nft_local_storage_path)
                
                self.log_message(f"Downloading file(s) for NFT {nft_address_to_add} to {nft_local_storage_path}...")
                get_file(nft_address_to_add, nft_local_storage_path)
                self.log_message(f"File(s) for NFT {nft_address_to_add} downloaded to {nft_local_storage_path}.", "success")
                download_message_suffix = f"\nFile(s) downloaded to: {nft_local_storage_path}"
                stored_path_for_json = nft_local_storage_path
            except Exception as e:
                self.log_message(f"Error during file download for NFT {nft_address_to_add}: {e}", "error")
                download_message_suffix = f"\nError during file download: {e}"
                stored_path_for_json = "Download Error"


            nft_name = info["name"].decode('utf-8', 'replace') if isinstance(info["name"], bytes) else str(info["name"])
            new_entry = {"name": nft_name, "address": nft_address_to_add, "file_path": stored_path_for_json}
            my_nfts_list.append(new_entry)
            nft_storage[self.wallet_address] = my_nfts_list
            self._save_nft_storage(nft_storage)

            final_msg = f"NFT '{nft_name}' ({nft_address_to_add}) added to your collection!{download_message_suffix}"
            self.log_message(final_msg, "success")
            Messagebox.show_info("NFT Added", final_msg)
            self.refresh_my_nfts_list()
            self.add_nft_address_entry.delete(0, tk.END)
            try:
                self.log_message(f"Opening local path: {nft_local_storage_path}", "info")
                if sys.platform == "win32":
                    os.startfile(os.path.realpath(nft_local_storage_path))
                elif sys.platform == "darwin":
                    subprocess.call(['open', os.path.realpath(nft_local_storage_path)])
                else: # Assume Linux or other Unix-like system
                    subprocess.call(['xdg-open', os.path.realpath(nft_local_storage_path)])
            except Exception as e:
                self.log_message(f"Failed to open path {nft_local_storage_path}: {e}", "error")
                Messagebox.show_error(f"Could not open path '{nft_local_storage_path}':\n{e}", "File Open Error")

        except Exception as e:
            self.log_message(f"An error occurred during add_nft: {e}", "error")
            Messagebox.show_error(f"Error adding NFT: {e}", "Add NFT Error")

    def refresh_my_nfts_list(self):
        if not hasattr(self, 'nft_tree') or not self.wallet_address:
            return

        for item in self.nft_tree.get_children():
            self.nft_tree.delete(item)

        nft_storage = self._load_nft_storage()
        my_nfts_list = nft_storage.get(self.wallet_address, [])

        if not my_nfts_list:
            self.log_message("No NFTs found in your local collection for this address.", "info")
            return
        
        for nft_entry in my_nfts_list:
            name = nft_entry.get("name", "N/A")
            address = nft_entry.get("address", "N/A")
            file_path = nft_entry.get("file_path", "N/A")
            self.nft_tree.insert("", tk.END, values=(name, address, file_path))


if __name__ == "__main__":
    app = XSNFTP_GUI(theme='superhero')
    app.mainloop()
