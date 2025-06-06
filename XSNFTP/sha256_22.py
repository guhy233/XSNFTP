import hashlib

def sha256_22(input_str):
    if not isinstance(input_str, bytes):
        input_str = input_str.encode('utf-8')
    h1 = hashlib.sha256(input_str).digest()
    h2 = hashlib.sha256(h1).digest()
    combined = h1 + h2 
    
    binary_str = ''.join(format(byte, '08b') for byte in combined)
    
    truncated = binary_str[:154] 
    
    result = []
    for i in range(0, 154, 7):
        chunk = truncated[i:i+7]
        char_code = int(chunk.ljust(7, '0')[:7], 2)
        result.append(chr(char_code))
    
    return ''.join(result)
