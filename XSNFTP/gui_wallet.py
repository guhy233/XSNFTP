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

        self.private_key = None
        self.current_password = None
        self.wallet_address = None
        self.current_language = "zh"
        self.translations = {}

        try:
            with open("translations.json", "r", encoding="utf-8") as f:
                self.translations = json.load(f)
        except Exception as e:
            tk.messagebox.showerror("Translation Error", f"An unexpected error occurred while loading translations: {e}")
            sys.exit(1)

        self.title(self._("XSNFTP Wallet"))
        self.geometry("950x750")

        if not os.path.exists(NFT_DOWNLOAD_DIR):
            try:
                os.makedirs(NFT_DOWNLOAD_DIR)
            except OSError as e:
                Messagebox.show_error(self._("Could not create base NFT download directory '{NFT_DOWNLOAD_DIR}': {e}", NFT_DOWNLOAD_DIR=NFT_DOWNLOAD_DIR, e=e), self._("Startup Error"))

        self.setup_initial_screen()

    def _(self, text_key, **kwargs):
        """
        Translates a given text_key using the loaded language dictionary and formats it.
        """
        default_text = text_key
        translated_text = self.translations.get(self.current_language, {}).get(text_key, default_text)
        
        if kwargs:
            try:
                return translated_text.format(**kwargs)
            except (KeyError, ValueError) as e:
                print(f"Translation formatting error for key '{text_key}': {e}. Using default text.")
                return default_text.format(**kwargs)
        return translated_text

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

    def _show_message(self, message, title, level="info"):
        self.log_message(message, level)
        if level == "error":
            Messagebox.show_error(message, title)
        elif level == "warning":
            Messagebox.show_warning(message, title)
        elif level == "success":
            Messagebox.show_info(message, title)
        else:
            Messagebox.show_info(message, title)

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
                    self._show_message(self._("Private key not found in file."), self._("Key Error"), "error")
                    return None
                private_key = self._decrypt_data(encrypted_private_key, password)
                self._show_message(self._("Private key decrypted successfully."), self._("Success"), "success")
                return private_key
            except json.JSONDecodeError:
                self._show_message(self._("Error reading private_key.json. File might be corrupted.", file=PRIVATE_KEY_FILE), self._("File Error"), "error")
                return "Incorrect password"
            except Exception:
                self._show_message(self._("Decryption failed. Likely incorrect password or corrupted data."), self._("Decryption Error"), "error")
                return "Incorrect password"
        else:
            self._show_message(self._("private_key.json not found.", file=PRIVATE_KEY_FILE), self._("Info"), "info")
            return None

    def _save_private_key_to_file(self, private_key, password):
        try:
            encrypted_private_key = self._encrypt_data(private_key, password)
            with open(PRIVATE_KEY_FILE, "w") as file:
                json.dump({"private_key": encrypted_private_key}, file)
            self._show_message(self._("Private key has been encrypted and saved."), self._("Key Saved"), "success")
            self.current_password = password
        except Exception as e:
            self._show_message(self._("Failed to save private key: {error}", error=e), self._("Save Error"), "error")

    def _get_private_key_from_inputs(self, mnemonic=None, private_key_hex=None):
        if mnemonic:
            try:
                pk_bytes = seed_to_private_key(mnemonic)
                return pk_bytes.hex()
            except Exception as e:
                self._show_message(self._("Error generating key from mnemonic: {error}", error=e), self._("Mnemonic Error"), "error")
                return None
        elif private_key_hex:
            if all(c in '0123456789abcdefABCDEF' for c in private_key_hex) and len(private_key_hex) == 64:
                 return private_key_hex
            else:
                self._show_message(self._("Invalid private key format. Must be a 64-character hex string."), self._("Key Format Error"), "error")
                return None
        else:
            self._show_message(self._("You must provide either a mnemonic or private key hex."), self._("Input Error"), "error")
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
            self._show_message(self._("Error deriving address from private key: {error}", error=e), self._("Address Derivation Error"), "error")
            return None

    def _is_valid_xdag_address(self, address):
        if not isinstance(address, str):
            return False
        if not (25 <= len(address) <= 35):
            return False
        valid_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if not all(c in valid_chars for c in address):
            return False
        return True

    def _set_buttons_state(self, state):
        # Disable/Enable buttons for main operations
        if hasattr(self, 'info_get_info_button'):
            self.info_get_info_button.configure(state=state)
        if hasattr(self, 'get_file_button'):
            self.get_file_button.configure(state=state)
        if hasattr(self, 'cast_file_button'):
            self.cast_file_button.configure(state=state)
        if hasattr(self, 'transfer_nft_button'):
            self.transfer_nft_button.configure(state=state)
        if hasattr(self, 'add_nft_button'):
            self.add_nft_button.configure(state=state)
        if hasattr(self, 'refresh_nfts_button'):
            self.refresh_nfts_button.configure(state=state)
        if hasattr(self, 'remove_nft_button'):
            self.remove_nft_button.configure(state=state)

    def change_language(self, event=None):
        new_language = self.language_selection.get()
        if new_language and new_language != self.current_language:
            self.current_language = new_language
            if hasattr(self, 'initial_frame') and self.initial_frame.winfo_exists():
                self.destroy_initial_screen_widgets()
                self.setup_initial_screen()
            elif hasattr(self, 'main_frame') and self.main_frame.winfo_exists():
                self.setup_main_application()

    def setup_initial_screen(self):
        self.title(self._("XSNFTP Wallet"))

        self.initial_frame = tb.Frame(self, padding=20)
        self.initial_frame.pack(expand=True, fill=tk.BOTH)
        
        header_frame = tb.Frame(self.initial_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        tb.Label(header_frame, text=self._("XSNFTP Wallet Setup/Login"), font=("Helvetica", 16, "bold")).pack(side=tk.LEFT)

        language_frame = tb.Frame(header_frame)
        language_frame.pack(side=tk.RIGHT, padx=10)
        tb.Label(language_frame, text=self._("Language:")).pack(side=tk.LEFT)
        self.language_selection = ttk.Combobox(language_frame, values=list(self.translations.keys()), state="readonly", width=8)
        self.language_selection.set(self.current_language)
        self.language_selection.bind("<<ComboboxSelected>>", self.change_language)
        self.language_selection.pack(side=tk.LEFT, padx=5)

        self.log_area_initial = scrolledtext.ScrolledText(self.initial_frame, height=8, width=80, wrap=tk.WORD, state='disabled')
        self.log_area_initial.pack(pady=10, padx=10, fill=tk.X)
        self.log_area_initial.tag_config('error', foreground='red')
        self.log_area_initial.tag_config('success', foreground='green')
        self.log_area_initial.tag_config('warning', foreground='orange')
        self.log_area = self.log_area_initial

        login_frame = tb.Labelframe(self.initial_frame, text=self._("Login with Existing Key"), padding=15)
        login_frame.pack(pady=10, padx=10, fill=tk.X)
        tb.Label(login_frame, text=self._("Enter Password:")).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tb.Entry(login_frame, show="*", width=40)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.password_entry.bind("<Return>", lambda event: self.attempt_login())
        self.login_button = tb.Button(login_frame, text=self._("Login / Load Key"), command=self.attempt_login, style="success.TButton")
        self.login_button.grid(row=0, column=2, padx=10, pady=5)

        self.import_frame = tb.Labelframe(self.initial_frame, text=self._("Import or Setup New Key"), padding=15)
        self.import_frame.pack(pady=10, padx=10, fill=tk.X)
        tb.Label(self.import_frame, text=self._("Mnemonic (leave empty if using private key hex):")).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.mnemonic_entry = tb.Entry(self.import_frame, width=50)
        self.mnemonic_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text=self._("Or Private Key (Hex):")).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.pk_hex_entry = tb.Entry(self.import_frame, width=50)
        self.pk_hex_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text=self._("Set New Password (for this key):")).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.new_password_entry = tb.Entry(self.import_frame, show="*", width=40)
        self.new_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        tb.Label(self.import_frame, text=self._("Confirm New Password:")).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.confirm_password_entry = tb.Entry(self.import_frame, show="*", width=40)
        self.confirm_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.import_button = tb.Button(self.import_frame, text=self._("Import and Save Key"), command=self.import_and_save_key, style="primary.TButton")
        self.import_button.grid(row=4, column=1, pady=10, sticky="e")
        
        self.log_message(self._("Welcome! Enter your password to load an existing key, or import a new one."))
        if not os.path.exists(PRIVATE_KEY_FILE):
            self._show_message(self._("private_key.json not found. Please use the 'Import or Setup New Key' section."), self._("No Key File Found"), "warning")
            self.password_entry.configure(state="disabled")
            self.login_button.configure(state="disabled")

    def attempt_login(self):
        password = self.password_entry.get()
        if not password:
            self._show_message(self._("Password cannot be empty."), self._("Login Warning"), "warning")
            return

        private_key_loaded = self._load_private_key_from_file(password)

        if private_key_loaded and private_key_loaded != "Incorrect password":
            self.private_key = private_key_loaded
            self.current_password = password
            self.wallet_address = self._private_key_to_address(self.private_key)
            if self.wallet_address:
                self._show_message(self._("Login successful! Wallet address derived."), self._("Login Success"), "success")
                self.initial_frame.pack_forget()
                self.destroy_initial_screen_widgets()
                self.setup_main_application()
            else:
                self._show_message(self._("Failed to derive wallet address from loaded key."), self._("Address Derivation Error"), "error")
                self.private_key = None
                self.current_password = None
        elif private_key_loaded == "Incorrect password":
            self._show_message(self._("Incorrect password. Please try again or import key."), self._("Login Failed"), "error")
        else:
             self._show_message(self._("private_key.json not found. Please use the 'Import or Setup New Key' section."), self._("No Key File"), "info")
             self.password_entry.configure(state="disabled")
             self.login_button.configure(state="disabled")

    def import_and_save_key(self):
        mnemonic = self.mnemonic_entry.get().strip()
        pk_hex = self.pk_hex_entry.get().strip()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not (mnemonic or pk_hex):
            self._show_message(self._("Please enter either a mnemonic or a private key hex."), self._("Import Warning"), "warning")
            return
        if mnemonic and pk_hex:
            self._show_message(self._("Please provide EITHER a mnemonic OR a private key, not both."), self._("Input Error"), "warning")
            return
        if not new_password or not confirm_password:
            self._show_message(self._("Please enter and confirm your new password."), self._("Password Warning"), "warning")
            return
        if new_password != confirm_password:
            self._show_message(self._("Passwords do not match."), self._("Password Error"), "error")
            return

        temp_pk = self._get_private_key_from_inputs(mnemonic=mnemonic, private_key_hex=pk_hex)

        if temp_pk:
            self._save_private_key_to_file(temp_pk, new_password)
            self.private_key = temp_pk
            self.current_password = new_password
            self.wallet_address = self._private_key_to_address(self.private_key)
            if self.wallet_address:
                self._show_message(self._("Key imported, saved, and wallet address derived!"), self._("Import Success"), "success")
                self.initial_frame.pack_forget()
                self.destroy_initial_screen_widgets()
                self.setup_main_application()
            else:
                self._show_message(self._("Key imported and saved, but failed to derive wallet address."), self._("Address Derivation Error"), "error")
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
        # Destroy existing main_frame if it exists
        if hasattr(self, 'main_frame') and self.main_frame.winfo_exists():
            self.main_frame.destroy()

        self.title(self._("XSNFTP Wallet")) # Update window title with current language
        main_frame = tb.Frame(self, padding=10)
        main_frame.pack(expand=True, fill=tk.BOTH)
        self.main_frame = main_frame # Store reference to the main_frame

        header_frame = tb.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0,10))
        tb.Label(header_frame, text=self._("XSNFTP Wallet"), font=("Helvetica", 18, "bold")).pack(side=tk.LEFT)
        
        language_frame = tb.Frame(header_frame)
        language_frame.pack(side=tk.RIGHT, padx=10)
        tb.Label(language_frame, text=self._("Language:")).pack(side=tk.LEFT)
        self.language_selection = ttk.Combobox(language_frame, values=list(self.translations.keys()), state="readonly", width=8)
        self.language_selection.set(self.current_language)
        self.language_selection.bind("<<ComboboxSelected>>", self.change_language)
        self.language_selection.pack(side=tk.LEFT, padx=5)

        if self.wallet_address:
            tb.Label(header_frame, text=f"{self._('Your Address:')} {self.wallet_address}", font=("Courier", 10)).pack(side=tk.RIGHT, padx=10)

        log_frame = tb.Labelframe(main_frame, text=self._("Activity Log"), padding=5)
        log_frame.pack(pady=10, padx=5, fill=tk.BOTH, expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10, width=100, wrap=tk.WORD, state='disabled')
        self.log_area.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        self.log_area.tag_config('error', foreground='red')
        self.log_area.tag_config('success', foreground='green')
        self.log_area.tag_config('warning', foreground='orange')

        self.log_message(self._("Wallet loaded. Address: {address}", address=self.wallet_address), "success")

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill='both', pady=10)

        info_tab = tb.Frame(notebook, padding=10)
        notebook.add(info_tab, text=self._('NFT Info'))
        self.setup_info_tab(info_tab)

        get_nft_file_tab = tb.Frame(notebook, padding=10)
        notebook.add(get_nft_file_tab, text=self._('Get a NFT File'))
        self.setup_get_nft_file_tab(get_nft_file_tab)

        cast_nft_file_tab = tb.Frame(notebook, padding=10)
        notebook.add(cast_nft_file_tab, text=self._('Cast a NFT File'))
        self.setup_cast_nft_file_tab(cast_nft_file_tab)

        transfer_tab = tb.Frame(notebook, padding=10)
        notebook.add(transfer_tab, text=self._('Transfer NFT'))
        self.setup_transfer_tab(transfer_tab)

        my_nfts_tab = tb.Frame(notebook, padding=10)
        notebook.add(my_nfts_tab, text=self._('My NFTs'))
        self.setup_my_nfts_tab(my_nfts_tab)

    def setup_info_tab(self, tab):
        tb.Label(tab, text=self._("Get Information about an NFT"), font=("Helvetica", 12)).pack(pady=10)
        entry_frame = tb.Frame(tab)
        entry_frame.pack(pady=5, fill=tk.X)
        tb.Label(entry_frame, text=self._("NFT Address:")).pack(side=tk.LEFT, padx=5)
        self.info_nft_address_entry = tb.Entry(entry_frame, width=60)
        self.info_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.info_get_info_button = tb.Button(tab, text=self._("Get Info"), command=self.gui_get_info, style="primary.TButton")
        self.info_get_info_button.pack(pady=10)

    def gui_get_info(self):
        if not self.private_key:
            self._show_message(self._("Private key not loaded."), self._("Key Error"), "error")
            return

        nft_address = self.info_nft_address_entry.get().strip()
        if not nft_address:
            self._show_message(self._("Please provide the NFT address."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(nft_address):
            self._show_message(self._("Invalid NFT Address format. Please check the address."), self._("Input Error"), "warning")
            return

        self.log_message(f"Executing: get_info {nft_address})")
        self._set_buttons_state("disabled")
        try:
            info = get_info(nft_address)
            if not info or info.get("owner") is None:
                msg = self._("Failed to get NFT info for {address}. The NFT might not exist or there was a network error.", address=nft_address)
                self._show_message(msg, self._("Get Info Failed"), "error")
                return

            owner_str = info["owner"].decode('utf-8', 'replace') if isinstance(info["owner"], bytes) else str(info["owner"])
            user_address_hashed_for_nft_owner_check = sha256_22(self.wallet_address).encode()
            owner_indicator = self._(" (you)") if info["owner"] == user_address_hashed_for_nft_owner_check else ""
            name_str = info["name"].decode('utf-8', 'replace') if isinstance(info["name"], bytes) else str(info["name"])
            
            info_message = self._("Information for NFT: {address}\n------------------------------------------\nOwner: {owner}{owner_indicator}\nName: {name}", address=nft_address, owner=owner_str, owner_indicator=owner_indicator, name=name_str)
            self._show_message(info_message, self._("NFT Information"), "info")

        except Exception as e:
            self._show_message(self._("An error occurred while getting NFT info: {error}", error=e), self._("Get Info Error"), "error")
        finally:
            self._set_buttons_state("enabled")

    def setup_get_nft_file_tab(self, tab):
        tb.Label(tab, text=self._("Download File from NFT"), font=("Helvetica", 11)).pack(pady=10)
        
        gf_nft_frame = tb.Frame(tab)
        gf_nft_frame.pack(pady=5, fill=tk.X)
        tb.Label(gf_nft_frame, text=self._("NFT Address:")).pack(side=tk.LEFT, padx=5)
        self.get_file_nft_address_entry = tb.Entry(gf_nft_frame, width=50)
        self.get_file_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        gf_dir_frame = tb.Frame(tab)
        gf_dir_frame.pack(pady=5, fill=tk.X)
        tb.Label(gf_dir_frame, text=self._("Output Directory:")).pack(side=tk.LEFT, padx=5)
        self.get_file_output_dir_entry = tb.Entry(gf_dir_frame, width=40)
        self.get_file_output_dir_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(gf_dir_frame, text=self._("Browse..."), command=self.browse_output_directory_for_get_file).pack(side=tk.LEFT, padx=5)

        self.get_file_button = tb.Button(tab, text=self._("Get NFT File"), command=self.gui_get_file, style="primary.TButton")
        self.get_file_button.pack(pady=10)

    def setup_cast_nft_file_tab(self, tab):
        tb.Label(tab, text=self._("Publish File to an NFT"), font=("Helvetica", 11)).pack(pady=10)

        cf_file_frame = tb.Frame(tab)
        cf_file_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_file_frame, text=self._("File Path to Cast:")).pack(side=tk.LEFT, padx=5)
        self.cast_file_path_entry = tb.Entry(cf_file_frame, width=40)
        self.cast_file_path_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tb.Button(cf_file_frame, text=self._("Browse..."), command=self.browse_cast_file_path).pack(side=tk.LEFT, padx=5)
        
        cf_nft_addr_frame = tb.Frame(tab)
        cf_nft_addr_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_nft_addr_frame, text=self._("Target NFT Address (New/Existing):")).pack(side=tk.LEFT, padx=5)
        self.cast_file_nft_address_entry = tb.Entry(cf_nft_addr_frame, width=40)
        self.cast_file_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        cf_name_frame = tb.Frame(tab)
        cf_name_frame.pack(pady=5, fill=tk.X)
        tb.Label(cf_name_frame, text=self._("NFT Name (for this file):")).pack(side=tk.LEFT, padx=5)
        self.cast_file_name_entry = tb.Entry(cf_name_frame, width=40)
        self.cast_file_name_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self.cast_file_button = tb.Button(tab, text=self._("Cast NFT File"), command=self.gui_cast_file, style="success.TButton")
        self.cast_file_button.pack(pady=10)

    def browse_output_directory_for_get_file(self):
        directory = filedialog.askdirectory()
        if directory:
            self.get_file_output_dir_entry.delete(0, tk.END)
            self.get_file_output_dir_entry.insert(0, directory)

    def browse_cast_file_path(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.cast_file_path_entry.delete(0, tk.END)
            self.cast_file_path_entry.insert(0, filepath)

    def gui_get_file(self):
        if not self.private_key:
            self._show_message(self._("Private key not loaded."), self._("Key Error"), "error"); return
        nft_address = self.get_file_nft_address_entry.get().strip()
        output_dir = self.get_file_output_dir_entry.get().strip()

        if not nft_address or not output_dir:
            self._show_message(self._("NFT Address and Output Directory are required."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(nft_address):
            self._show_message(self._("Invalid NFT Address format. Please check the address."), self._("Input Error"), "warning")
            return

        self.log_message(self._("Initiating file download for NFT: {address} to {dir}", address=nft_address, dir=output_dir))
        self._set_buttons_state("disabled")
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                self.log_message(self._("Output directory '{dir}' did not exist. Created it.", dir=output_dir), "info")
            except OSError as e:
                self._show_message(self._("Could not create output directory '{dir}': {error}", dir=output_dir, error=e), self._("Directory Error"), "error")
                self._set_buttons_state("enabled")
                return
        
        try:
            success = get_file(nft_address, output_dir)
            if success:
                msg = self._("File(s) for NFT {address} requested/downloaded to {dir}.", address=nft_address, dir=output_dir)
                self._show_message(msg, self._("Download Initiated/Completed"), "success")
            else:
                msg = self._("Failed to get file for NFT {address}. The operation returned failure.", address=nft_address)
                self._show_message(msg, self._("Download Error"), "error")
        except Exception as e:
            self._show_message(self._("An error occurred while getting NFT file: {error}", error=e), self._("Download Error"), "error")
        finally:
            self._set_buttons_state("enabled")

    def gui_cast_file(self):
        if not self.private_key:
            self._show_message("Private key not loaded.", "Key Error", "error"); return
        file_path = self.cast_file_path_entry.get().strip()
        nft_address_cast = self.cast_file_nft_address_entry.get().strip()
        name = self.cast_file_name_entry.get().strip()

        if not file_path or not nft_address_cast or not name:
            self._show_message(self._("File Path, Target NFT Address, and NFT Name are required."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(nft_address_cast):
            self._show_message(self._("Invalid Target NFT Address format. Please check the address."), self._("Input Error"), "warning")
            return
        
        if not os.path.exists(file_path):
            self._show_message(self._("File not found: {path}", path=file_path), self._("File Error"), "error")
            return

        self.log_message(f"Initiating NFT casting for file: {file_path} to NFT: {nft_address_cast} with name: {name}")
        self._set_buttons_state("disabled")
        try:
            current_user_address = self.wallet_address
            success = cast_file(file_path, current_user_address, nft_address_cast, name, self.private_key)

            if success:
                self._show_message(self._("File '{filename}' cast successfully to NFT {nft_address} with name '{name}'!", filename=os.path.basename(file_path), nft_address=nft_address_cast, name=name), self._("Success"), "success")
                self.cast_file_path_entry.delete(0, tk.END)
                self.cast_file_nft_address_entry.delete(0, tk.END)
                self.cast_file_name_entry.delete(0, tk.END)
            else:
                self._show_message(self._("Failed to cast the file. The operation returned failure."), self._("Cast Error"), "error")
        except Exception as e:
            self._show_message(f"An error occurred while casting file: {e}", "Cast Error", "error")
        finally:
            self._set_buttons_state("enabled")

    def setup_transfer_tab(self, tab):
        tb.Label(tab, text=self._("Transfer an NFT to Another Address"), font=("Helvetica", 12)).pack(pady=10)
        nft_addr_frame = tb.Frame(tab)
        nft_addr_frame.pack(pady=5, fill=tk.X)
        tb.Label(nft_addr_frame, text=self._("NFT Address to Transfer:")).pack(side=tk.LEFT, padx=5)
        self.transfer_nft_address_entry = tb.Entry(nft_addr_frame, width=50)
        self.transfer_nft_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        recipient_frame = tb.Frame(tab)
        recipient_frame.pack(pady=5, fill=tk.X)
        tb.Label(recipient_frame, text=self._("Recipient Address:")).pack(side=tk.LEFT, padx=5)
        self.transfer_recipient_address_entry = tb.Entry(recipient_frame, width=50)
        self.transfer_recipient_address_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.transfer_nft_button = tb.Button(tab, text=self._("Transfer NFT"), command=self.gui_transfer_nft, style="warning.TButton")
        self.transfer_nft_button.pack(pady=20)

    def gui_transfer_nft(self):
        if not self.private_key:
            self._show_message(self._("Private key not loaded."), self._("Key Error"), "error"); return

        nft_address_transfer = self.transfer_nft_address_entry.get().strip()
        to_address = self.transfer_recipient_address_entry.get().strip()

        if not nft_address_transfer or not to_address:
            self._show_message(self._("NFT Address to transfer and Recipient Address are required."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(nft_address_transfer):
            self._show_message(self._("Invalid NFT Address to Transfer format. Please check the address."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(to_address):
            self._show_message(self._("Invalid Recipient Address format. Please check the address."), self._("Input Error"), "warning")
            return

        self.log_message(f"Executing: transfer {nft_address_transfer} to {to_address}")
        self._set_buttons_state("disabled")
        try:
            current_user_address = self.wallet_address
            success = transfer_file(current_user_address, self.private_key, to_address, nft_address_transfer)

            if success:
                self._show_message(self._("NFT {nft_address} transferred successfully to {to_address}!", nft_address=nft_address_transfer, to_address=to_address), self._("Success"), "success")
                self.refresh_my_nfts_list()
                self.transfer_nft_address_entry.delete(0, tk.END)
                self.transfer_recipient_address_entry.delete(0, tk.END)
            else:
                self._show_message(self._("Failed to transfer NFT {nft_address}. You might not be the owner or an error occurred.", nft_address=nft_address_transfer), self._("Transfer Error"), "error")
        except Exception as e:
            self._show_message(self._("An error occurred while transferring NFT: {error}", error=e), self._("Transfer Error"), "error")
        finally:
            self._set_buttons_state("enabled")

    def setup_my_nfts_tab(self, tab):
        controls_frame = tb.Frame(tab)
        controls_frame.pack(fill=tk.X, pady=5)

        tb.Label(controls_frame, text=self._("Add NFT you own:"), font=("Helvetica", 10)).pack(side=tk.LEFT, pady=5)
        self.add_nft_address_entry = tb.Entry(controls_frame, width=30) # Adjusted width
        self.add_nft_address_entry.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.add_nft_button = tb.Button(controls_frame, text=self._("Add NFT"), command=self.gui_add_nft, style="info.TButton")
        self.add_nft_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.refresh_nfts_button = tb.Button(controls_frame, text=self._("Refresh List"), command=self.refresh_my_nfts_list, style="secondary.TButton")
        self.refresh_nfts_button.pack(side=tk.LEFT, padx=5, pady=5)
        self.remove_nft_button = tb.Button(controls_frame, text=self._("Remove Selected NFT"), command=self.gui_remove_nft, style="danger.TButton")
        self.remove_nft_button.pack(side=tk.LEFT, padx=5, pady=5)

        columns = ("name", "address", "local_path") # Added local_path
        self.nft_tree = ttk.Treeview(tab, columns=columns, show="headings", bootstyle="primary")
        self.nft_tree.heading("name", text=self._("NFT Name"))
        self.nft_tree.heading("address", text=self._("NFT Address"))
        self.nft_tree.heading("local_path", text=self._("Local Path")) # New heading

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
            self.log_message(self._("Selected '{name}' ({address}). NFT address copied to relevant fields.", name=nft_name, address=nft_address), "info")

    def on_nft_double_click(self, event):
        selected_item_id = self.nft_tree.focus()
        if not selected_item_id: return

        item_values = self.nft_tree.item(selected_item_id, "values")
        if item_values and len(item_values) == 3:
            local_path = item_values[2]
            if local_path and local_path != "N/A" and os.path.exists(local_path):
                try:
                    self.log_message(self._("Opening local path: {path}", path=local_path), "info")
                    if sys.platform == "win32":
                        os.startfile(os.path.realpath(local_path))
                    elif sys.platform == "darwin":
                        subprocess.call(['open', os.path.realpath(local_path)])
                    else: # Assume Linux or other Unix-like system
                        subprocess.call(['xdg-open', os.path.realpath(local_path)])
                except Exception as e:
                    self._show_message(self._("Failed to open path {path}: {error}", path=local_path, error=e), self._("File Open Error"), "error")
            elif local_path and local_path != "N/A":
                self._show_message(self._("The path '{path}' does not exist or could not be accessed.", path=local_path), self._("Path Not Found"), "warning")
            else:
                self._show_message(self._("No local path is stored for the selected NFT."), self._("No Local Path"), "info")


    def _load_nft_storage(self):
        if os.path.exists(NFT_STORAGE_FILE):
            try:
                with open(NFT_STORAGE_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self._show_message(self._("Error decoding {file}. Starting with empty storage.", file=NFT_STORAGE_FILE), self._("File Error"), "error")
                return {}
        return {}

    def _save_nft_storage(self, nft_storage_data):
        try:
            with open(NFT_STORAGE_FILE, "w") as f:
                json.dump(nft_storage_data, f, indent=4)
        except Exception as e:
            self._show_message(self._("Error saving NFT storage: {error}", error=e), self._("Storage Save Error"), "error")


    def gui_add_nft(self):
        if not self.private_key or not self.wallet_address:
            self._show_message(self._("Private key or wallet address not loaded."), self._("Key Error"), "error"); return

        nft_address_to_add = self.add_nft_address_entry.get().strip()
        if not nft_address_to_add:
            self._show_message(self._("Please provide the NFT address to add."), self._("Input Error"), "warning")
            return
        if not self._is_valid_xdag_address(nft_address_to_add):
            self._show_message(self._("Invalid NFT Address format. Please check the address."), self._("Input Error"), "warning")
            return

        self.log_message(self._("Attempting to add NFT: {address}", address=nft_address_to_add))
        self._set_buttons_state("disabled")
        try:
            info = get_info(nft_address_to_add)
            if not info or info.get("owner") is None:
                msg = self._("Failed to get info for NFT {address}. Cannot verify ownership.", address=nft_address_to_add)
                self._show_message(msg, self._("Add NFT Error"), "error")
                return

            user_owner_hash_expected = sha256_22(self.wallet_address).encode()
            if info["owner"] != user_owner_hash_expected:
                msg = self._("You are not the owner of NFT {address}. Cannot add.", address=nft_address_to_add)
                self._show_message(msg, self._("Ownership Error"), "error")
                return

            nft_storage = self._load_nft_storage()
            my_nfts_list = nft_storage.get(self.wallet_address, [])
            for nft_entry in my_nfts_list:
                if nft_entry.get("address") == nft_address_to_add:
                    self._show_message(self._("NFT {address} is already in your collection.", address=nft_address_to_add), self._("Already Added"), "info")
                    return
            
            nft_local_storage_path = os.path.join(NFT_DOWNLOAD_DIR, nft_address_to_add)
            download_message_suffix = ""
            try:
                if not os.path.exists(nft_local_storage_path):
                    os.makedirs(nft_local_storage_path)
                
                self.log_message(self._("Downloading file(s) for NFT {address} to {path}...", address=nft_address_to_add, path=nft_local_storage_path))
                get_file(nft_address_to_add, nft_local_storage_path)
                self.log_message(self._("File(s) for NFT {address} downloaded to {path}.", address=nft_address_to_add, path=nft_local_storage_path), "success")
                download_message_suffix = self._("\nFile(s) downloaded to: {path}", path=nft_local_storage_path)
                stored_path_for_json = nft_local_storage_path
            except Exception as e:
                self._show_message(self._("Error during file download for NFT {address}: {error}", address=nft_address_to_add, error=e), self._("Download Error"), "error")
                download_message_suffix = self._("\nError during file download: {error}", error=e)
                stored_path_for_json = "Download Error"


            nft_name = info["name"].decode('utf-8', 'replace') if isinstance(info["name"], bytes) else str(info["name"])
            new_entry = {"name": nft_name, "address": nft_address_to_add, "file_path": stored_path_for_json}
            my_nfts_list.append(new_entry)
            nft_storage[self.wallet_address] = my_nfts_list
            self._save_nft_storage(nft_storage)

            final_msg = self._("NFT '{name}' ({address}) added to your collection!{suffix}", name=nft_name, address=nft_address_to_add, suffix=download_message_suffix)
            self._show_message(final_msg, self._("NFT Added"), "success")
            self.refresh_my_nfts_list()
            self.add_nft_address_entry.delete(0, tk.END)
            try:
                self.log_message(self._("Opening local path: {path}", path=nft_local_storage_path), "info")
                if sys.platform == "win32":
                    os.startfile(os.path.realpath(nft_local_storage_path))
                elif sys.platform == "darwin":
                    subprocess.call(['open', os.path.realpath(nft_local_storage_path)])
                else:
                    subprocess.call(['xdg-open', os.path.realpath(nft_local_storage_path)])
            except Exception as e:
                self._show_message(self._("Failed to open path {path}: {error}", path=nft_local_storage_path, error=e), self._("File Open Error"), "error")

        except Exception as e:
            self._show_message(self._("An error occurred while adding NFT: {error}", error=e), self._("Add NFT Error"), "error")
        finally:
            self._set_buttons_state("enabled")

    def gui_remove_nft(self):
        selected_item_id = self.nft_tree.focus()
        if not selected_item_id:
            self._show_message(self._("Please select an NFT to remove."), self._("No NFT Selected"), "warning")
            return

        item_values = self.nft_tree.item(selected_item_id, "values")
        nft_address_to_remove = item_values[1]
        nft_name_to_remove = item_values[0]

        confirm = Messagebox.yesno(
            self._("Are you sure you want to remove '{name}' ({address}) from your local collection? This does NOT affect ownership on the blockchain.", name=nft_name_to_remove, address=nft_address_to_remove),
            self._("Confirm Removal")
        )
        if not confirm:
            return

        self._set_buttons_state("disabled")
        try:
            nft_storage = self._load_nft_storage()
            my_nfts_list = nft_storage.get(self.wallet_address, [])
            
            updated_nfts_list = [nft for nft in my_nfts_list if nft.get("address") != nft_address_to_remove]
            
            nft_storage[self.wallet_address] = updated_nfts_list
            self._save_nft_storage(nft_storage)
            self.refresh_my_nfts_list()
            self._show_message(self._("NFT '{name}' ({address}) removed from local collection.", name=nft_name_to_remove, address=nft_address_to_remove), self._("NFT Removed"), "success")
        except Exception as e:
            self._show_message(self._("Error removing NFT from local collection: {error}", error=e), self._("Removal Error"), "error")
        finally:
            self._set_buttons_state("enabled")

    def refresh_my_nfts_list(self):
        if not hasattr(self, 'nft_tree') or not self.wallet_address:
            return

        for item in self.nft_tree.get_children():
            self.nft_tree.delete(item)

        nft_storage = self._load_nft_storage()
        my_nfts_list = nft_storage.get(self.wallet_address, [])

        if not my_nfts_list:
            self.log_message(self._("No NFTs found in your local collection for this address."), "info")
            return
        
        for nft_entry in my_nfts_list:
            name = nft_entry.get("name", "N/A")
            address = nft_entry.get("address", "N/A")
            file_path = nft_entry.get("file_path", "N/A")
            self.nft_tree.insert("", tk.END, values=(name, address, file_path))


if __name__ == "__main__":
    app = XSNFTP_GUI(theme='superhero')
    app.mainloop()
