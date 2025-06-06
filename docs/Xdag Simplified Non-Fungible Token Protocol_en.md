# Xdag Simplified Non-Fungible Token Protocol (XSNFTP)

## 1. Overview

XSNFTP is a protocol that mints files as NFTs on the Xdag chain by embedding specific content in the transaction remarks. The receiving address of a transaction containing such a remark serves as the address of the NFT. An NFT address may receive multiple transactions with different remarks, categorized into four types:

1. **Minting Header Declaration**: Contains the hash of the NFT minter's address. All NFT-related operations are valid only after this declaration. If multiple headers exist, only the first one is valid.

2. **Minting Content Summary**: Includes the total character count of the file (in hexadecimal) and the NFT name. If multiple summaries exist, only the first one is valid.

3. **Minting Page Declaration**: Specifies the page number and the corresponding file content. If multiple declarations exist for the same page number, only the first one is valid.

4. **Transfer**: Contains the recipient's address hash.

Important notes (as implemented in the `decode_all_remarks()` function in `decoder.py`):

1. Any operations before the Minting Header Declaration are invalid.
2. Only the minter can issue Minting Content Summaries and Minting Page Declarations.
3. The sequence of Minting Content Summaries and Minting Page Declarations is not fixed. A page declaration can precede a content summary, and page numbers do not need to be in ascending order.
4. Transfers are only valid when initiated by the owner.
5. Once the Minting Header Declaration is made, transfers become valid. However, the original minter can still continue minting after a transfer.

## 2. Implementation Details

A valid XSNFTP remark consists of a 64-character base64-encoded string, which, when decoded, results in 24 hexadecimal bytes.

### 1. Minting Header Declaration

| XSNFTP Identifier | Opcode: Minting Header Declaration | 22-byte Minter Address Hash [Example] |
|:----------------:|:----------------------:|------------------------------------------|
| 0 | 0 | 14 66 6c 6f 77 65 72 2e 70 6e 67 00 08 2e 70 6e 67 89 50 4e 47 0d 0a |

The hash generation code is available in `./sha256_22`.

### 2. Minting Content Summary

| XSNFTP Identifier | Opcode: Minting Content Summary | File Total Character Count (Hex) [Example] | NFT Name (32 bytes, zero-padded if necessary) [Example] |
|:----------------:|:----------------------:|:-----------------:|------------------------------------------|
| 0 | 1 | 0000ab | 74 65 73 74 00 00 00 00 00 00 00 00 00 00 00 00 |

### 3. Minting Page Declaration

| XSNFTP Identifier | Opcode: Minting Page Declaration | Page Number [Example] | Content (Encoded and Sliced File Content) [Example] |
|:----------------:|:----------------------:|:------:|------------------------------------------|
| 0 | 2 | 0000 | 14 66 6c 6f 77 65 72 2e 70 6e 67 00 08 2e 70 6e 67 89 50 4e 47 0d 0a |

### 4. Transfer

| XSNFTP Identifier | Opcode: Transfer | Recipient Address Hash [Example] |
|:----------------:|:------:|------------------------------------------|
| 0 | 3 | 14 66 6c 6f 77 65 72 2e 70 6e 67 00 08 2e 70 6e 67 89 50 4e 47 0d 0a |

## 3. File Encoding

The file encoding process is implemented in `encoder.py` as follows:

```python
import os
import binascii

def file_to_hex(file_path):
    # Get file name and extension
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1]  # Extract file extension

    with open(file_path, 'rb') as file:
        file_content = file.read()

    hex_file_name = binascii.hexlify(file_name.encode()).decode()
    hex_file_extension = binascii.hexlify(file_extension.encode()).decode()
    hex_file_content = binascii.hexlify(file_content).decode()

    # Combine into a complete hexadecimal string
    # Format: File name length + File name + Extension length + Extension + File content
    hex_string = f"{len(hex_file_name):04X}{hex_file_name}{len(hex_file_extension):04X}{hex_file_extension}{hex_file_content}"
    return hex_string
```

