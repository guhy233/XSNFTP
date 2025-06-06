from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip32KeyIndex,
    Bip32Slip10Secp256k1,
    Secp256k1PrivateKey,
)
from typing import Optional

HARDENED_BIT = 0x80000000
XDAG_BIP44_COIN_TYPE = 586 # what a fucking magic number
MNEMONIC_PASS_PHRASE = ""

def seed_to_private_key(mnemonic: str, account_index: int = 0) -> Optional[bytes]:
    """将助记词转换为 BIP44 派生私钥 (m/44'/coin_type'/0'/0/{account_index})"""
    try:
        Bip39MnemonicValidator().Validate(mnemonic)
        
        seed = Bip39SeedGenerator(mnemonic).Generate(MNEMONIC_PASS_PHRASE)
        
        master_key = Bip32Slip10Secp256k1.FromSeed(seed)
        
        path_indices = [
            Bip32KeyIndex.HardenIndex(44),                # 44'  hardened
            Bip32KeyIndex.HardenIndex(XDAG_BIP44_COIN_TYPE), # coin_type' hardened
            Bip32KeyIndex.HardenIndex(0),                 # 0'   hardened
            Bip32KeyIndex(0),                             # 0    non-hardened
            Bip32KeyIndex(account_index)                  # index non-hardened
        ]
        
        derived_key = master_key
        for index in path_indices:
            derived_key = derived_key.ChildKey(index)
        
        priv_key_bytes = derived_key.PrivateKey().Raw().ToBytes()
        return priv_key_bytes
    
    except (ValueError, TypeError) as e:
        return None
