import time
import struct
import binascii
import requests
import hashlib
from ecdsa import SECP256k1, SigningKey
import base58  

XDAG_FIELD_SIZE = 32
FEE = 0.1
TEST_NODE = "https://testnet-rpc.xdagj.org"
NODE_RPC = "https://mainnet-rpc.xdagj.org"


def check_base58_address(address: str) -> bytes:
    try:
        payload = base58.b58decode_check(address)
    except Exception as e:
        raise ValueError(f"Invalid Base58Check address: {e}")

    return payload[::-1]


def xdag2amount(value: float) -> int:
    return int(value * (1 << 32))


def get_current_timestamp() -> int:
    t_ns = time.time_ns() + 64 # 我也不知道为什么要加这个64，但是不加交易就没法成功
    sec = t_ns // 1_000_000_000
    usec = (t_ns - sec * 1_000_000_000) // 1_000
    xmsec = (usec << 10) // 1_000_000
    return (sec << 10) | xmsec


def get_fields_type(has_remark: bool, pub_key_even: bool) -> int:
    fields = 0xdce1
    keys = 0x550
    if pub_key_even:
        keys |= 0x06
    else:
        keys |= 0x07
    keys <<= 16

    if has_remark:
        keys <<= 4
        fields |= 0x90000

    fields |= keys
    return fields # 这是一个 64-bit 整数


def transaction_sign(block_buf: bytearray, key: SigningKey) -> tuple[bytes, bytes]:
    compressed_pub = key.verifying_key.to_string("compressed")
    v = bytes(block_buf) + compressed_pub

    first_hash = hashlib.sha256(v).digest()
    second_hash = hashlib.sha256(first_hash).digest()

    signature = key.sign_digest(second_hash)
    r = signature[:32]
    s = signature[32:]
    return r, s # 返回二进制格式 r(32B), s(32B)


def transaction_block(
    is_test_net: bool,
    amount: float,
    from_addr: str,
    to_addr: str,
    remark: str,
    key: SigningKey,
    nonce: int
) -> str:
    if amount < FEE:
        raise ValueError("LessThanFeeError: amount is less than fee")

    try:
        from_bytes = check_base58_address(from_addr)
    except ValueError as e:
        raise ValueError(f"Invalid sender address: {e}")
    try:
        to_bytes = check_base58_address(to_addr)
    except ValueError as e:
        raise ValueError(f"Invalid recipient address: {e}")

    if remark:
        if not remark.isascii() or len(remark) >= 33:
            raise ValueError("RemarkFormatError: remark must be ASCII and length < 33")

    buf = bytearray(512)

    compressed_pub = key.verifying_key.to_string("compressed")
    pub_key_even = (compressed_pub[0] == 0x02)
    fields = get_fields_type(bool(remark), pub_key_even)
    struct.pack_into("<Q", buf, 8, fields)

    ts = get_current_timestamp()
    struct.pack_into("<Q", buf, 16, ts)

    struct.pack_into("<Q", buf, 56, nonce)

    struct.pack_into("<I", buf, 64, 0)
    buf[68: 68 + len(from_bytes)] = from_bytes
    iv_offset = 68 + len(from_bytes)
    value_u64 = xdag2amount(amount)
    struct.pack_into("<Q", buf, iv_offset, value_u64)

    of_offset = iv_offset + 8
    struct.pack_into("<I", buf, of_offset, 0)
    tb_offset = of_offset + 4
    buf[tb_offset: tb_offset + len(to_bytes)] = to_bytes
    ov_offset = tb_offset + len(to_bytes)
    struct.pack_into("<Q", buf, ov_offset, value_u64)

    if remark:
        remark_offset = ov_offset + 8
        buf[remark_offset: remark_offset + len(remark)] = remark.encode()

    pub_offset = 160
    buf[pub_offset: pub_offset + 32] = compressed_pub[1:33]

    r_bytes, s_bytes = transaction_sign(buf, key)
    sig_offset = pub_offset + 32
    buf[sig_offset: sig_offset + 32] = r_bytes
    buf[sig_offset + 32: sig_offset + 64] = s_bytes

    return buf.hex()


def get_tranx_nonce(uri: str, address: str) -> int:
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "method": "xdag_getTransactionNonce",
        "params": [address],
        "id": 1
    }
    resp = requests.post(uri, json=payload, headers=headers, timeout=18)
    resp_json = resp.json()
    if "error" in resp_json:
        raise ValueError(f"RPC Error getTransactionNonce: {resp_json['error']}")
    nonce_str = resp_json.get("result")
    try:
        return int(nonce_str)
    except:
        raise ValueError(f"Invalid nonce returned: {nonce_str}")


def send_transaction(uri: str, block_hex: str) -> str:
    headers = {"Content-Type": "application/json"}
    payload = {
        "jsonrpc": "2.0",
        "method": "xdag_sendRawTransaction",
        "params": [block_hex],
        "id": 1
    }
    resp = requests.post(uri, json=payload, headers=headers, timeout=18)
    resp_json = resp.json()
    if "error" in resp_json:
        raise ValueError(f"RPC Error sendRawTransaction: {resp_json['error']}")
    return resp_json.get("result")


def send_xdag(
    is_test_net: bool,
    private_key_hex: str,
    from_addr: str,
    to_addr: str,
    amount: float,
    remark: str
) -> str:
    uri = TEST_NODE if is_test_net else NODE_RPC
    nonce = get_tranx_nonce(uri, from_addr)

    try:
        priv_key_bytes = binascii.unhexlify(private_key_hex)
    except Exception as e:
        raise ValueError(f"Invalid private key hex: {e}")

    key = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)
    block_hex = transaction_block(is_test_net, amount, from_addr, to_addr, remark, key, nonce)
    res = send_transaction(uri, block_hex)
    if not isinstance(res, str) or len(res) != 32:
        raise ValueError(f"RpcError: {res}")
    return res


def attempt_make_trans(
    is_test_net: bool,
    private_key_hex: str,
    from_addr: str,
    to_addr: str,
    amount: float,
    remark: str
) -> bool:
    res = ""
    try:
        res = send_xdag(is_test_net, private_key_hex, from_addr, to_addr, amount, remark)
        if isinstance(res, str) and len(res) == 32:
            return True
    except Exception:
        pass

    for _ in range(16):
        try:
            res = send_xdag(is_test_net, private_key_hex, from_addr, to_addr, amount, remark)
            print(res)
        except Exception as e:
            print(f"Attempt failed: {e}")
            res = ""
        if isinstance(res, str) and len(res) == 32:
            return True

    return False
