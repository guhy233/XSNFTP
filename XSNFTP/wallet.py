import os
import json
from seed2privatekey import seed_to_private_key
from XSNFTP import get_info, get_file, cast_file, transfer_file
from sha256_22 import sha256_22
import ecdsa
import hashlib
import base58
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PRIVATE_KEY_FILE = "private_key.json"
NFT_STORAGE_FILE = "my_nfts.json"
KEY_SIZE = 32  # AES-256

def encrypt_data(data, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base58.b58encode(cipher.iv + ct_bytes).decode()


def decrypt_data(encrypted_data, password):
    key = hashlib.sha256(password.encode()).digest()
    encrypted_data = base58.b58decode(encrypted_data.encode())
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


def get_private_key(mnemonic=None, private_key=None):
    if mnemonic:
        return seed_to_private_key(mnemonic).hex()
    elif private_key:
        return private_key
    else:
        print("Error: You must provide either a mnemonic or private key.")
        return None


def load_private_key_from_file(password):
    if os.path.exists(PRIVATE_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "r") as file:
            data = json.load(file)
            encrypted_private_key = data.get("private_key")
            try:
                private_key = decrypt_data(encrypted_private_key, password)
                print(private_key)
                return private_key
            except (ValueError, KeyError):
                return "Incorrect password"
    else:
        return None


def save_private_key_to_file(private_key, password):
    encrypted_private_key = encrypt_data(private_key, password)
    with open(PRIVATE_KEY_FILE, "w") as file:
        json.dump({"private_key": encrypted_private_key}, file)


def private_key_to_address(private_key):
    private_key_obj = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
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
    address_str = base58.b58encode(address_bin).decode()
    return address_str


def execute_command(command, private_key):
    command_parts = command.split()

    if len(command_parts) == 0:
        print("Error: No command provided.")
        return

    action = command_parts[0].lower()

    if action == "get_info":
        if len(command_parts) != 2:
            print("Error: Please provide the NFT address for 'get_info'.")
            return
        nft_address = command_parts[1]
        info = get_info(nft_address)
        if not info["owner"]:
            print("Error: Failed to get NFT info.")
            return
        print("address:", nft_address)
        # 判断当前用户是否为 NFT 的 owner（对比 sha256_22(private_key_to_address) 后的值）
        owner_indicator = " (you)" if info["owner"] == sha256_22(private_key_to_address(private_key)).encode() else ""
        print("owner:", info["owner"], owner_indicator)
        print("name:" , info["name"].decode())

    elif action == "get_file":
        if len(command_parts) != 3:
            print("Error: Please provide the NFT address and output directory for 'get_file'.")
            return
        nft_address = command_parts[1]
        output_dir = command_parts[2]
        if not os.path.exists(output_dir):
            print("The specified output directory does not exist. Creating it.")
            os.makedirs(output_dir)
        get_file(nft_address, output_dir)
        print(f"File has been downloaded to {output_dir}")

    elif action == "cast_file":
        if len(command_parts) != 4:
            print("Error: Please provide the file path, NFT address, and name for 'cast_file'.")
            return
        file_path = command_parts[1]
        nft_address = command_parts[2]
        name = command_parts[3]

        address = private_key_to_address(private_key)

        success = cast_file(file_path, address, nft_address, name, private_key)
        if success:
            print("File casted successfully!")
        else:
            print("Failed to cast the file.")

    elif action == "transfer":
        if len(command_parts) != 3:
            print("Error: Please provide the NFT address and recipient address for 'transfer'.")
            return
        nft_address = command_parts[1]
        to_address  = command_parts[2]
        address = private_key_to_address(private_key)
        success = transfer_file(address, private_key, to_address, nft_address)
        if success:
            print("NFT transfer successful!")
        else:
            print("Failed to transfer NFT.")

    elif action == "add_nft":
        if len(command_parts) != 2:
            print("Error: Please provide the NFT address for 'add_nft'.")
            return
        nft_address = command_parts[1]
        info = get_info(nft_address)
        if not info.get("owner"):
            print("Error: Failed to get NFT info.")
            return
        user_owner_hash = sha256_22(private_key_to_address(private_key)).encode()
        if info["owner"] != user_owner_hash:
            print("Error: You are not the owner of this NFT, cannot add it.")
            return
        nft_storage = {}
        if os.path.exists(NFT_STORAGE_FILE):
            with open(NFT_STORAGE_FILE, "r") as f:
                nft_storage = json.load(f)
        my_address = private_key_to_address(private_key)
        if my_address not in nft_storage:
            nft_storage[my_address] = []
        for nft in nft_storage[my_address]:
            if nft["address"] == nft_address:
                print("This NFT is already added.")
                return
        nft_entry = {"name": info["name"].decode(), "address": nft_address}
        nft_storage[my_address].append(nft_entry)
        with open(NFT_STORAGE_FILE, "w") as f:
            json.dump(nft_storage, f, indent=4)
        print("NFT added successfully!")

    elif action == "show_nfts":
        my_address = private_key_to_address(private_key)
        if not os.path.exists(NFT_STORAGE_FILE):
            print("No NFTs added.")
            return
        with open(NFT_STORAGE_FILE, "r") as f:
            nft_storage = json.load(f)
        if my_address not in nft_storage or len(nft_storage[my_address]) == 0:
            print("No NFTs added.")
            return
        print("Your NFTs:")
        for nft in nft_storage[my_address]:
            print(f"Name: {nft['name']}, Address: {nft['address']}")

    else:
        print(f"Error: Unknown command '{action}'.")


def main():
    print("Welcome to the XSNFTP Wallet.")

    password = input("Enter your password: ").strip()
    private_key = load_private_key_from_file(password)

    while private_key == "Incorrect password":
        print("Incorrect password. Please try again.")
        password = input("Enter your password: ").strip()
        private_key = load_private_key_from_file(password)

    if not private_key:
        print("No private key found. Please provide your mnemonic or private key to get started.")
        
        mnemonic = input("Mnemonic (leave empty if you have private key): ").strip()
        if mnemonic:
            private_key = get_private_key(mnemonic=mnemonic)
        else:
            private_key_input = input("Private key: ").strip()
            if private_key_input:
                private_key = get_private_key(private_key=private_key_input)
            else:
                print("Error: You must provide either a mnemonic or private key.")
                return
        
        save_private_key_to_file(private_key, password)
        print("Private key has been saved.")

    print("\nYour private key has been loaded successfully.")
    print("You can now use the following commands:")
    print("1. get_info <nft_address>                - Retrieve information about the specified NFT")
    print("2. get_file <nft_address> <output_directory> - Download the file associated with the NFT to the specified directory")
    print("3. cast_file <file_path> <nft_address> <nft_name> - Publish a file to an NFT with the given name")
    print("4. transfer <nft_address> <to_address>     - Transfer the specified NFT to another address")
    print("5. add_nft <nft_address>                   - Add the NFT to your collection (only if you are the owner)")
    print("6. show_nfts                             - Display all NFTs in your collection")
    print("Type 'exit' to quit the application.")

    while True:
        command = input("\nXSNFTP Wallet> ").strip()
        if command.lower() == 'exit':
            break
        execute_command(command, private_key)
        

if __name__ == "__main__":
    main()
