import binascii
import os
import base64
from sha256_22 import sha256_22


def hex_to_file(hex_string, output_dir):

    file_name_length = int(hex_string[:4], 16)
    hex_string = hex_string[4:]

    hex_file_name = hex_string[:file_name_length]
    file_name = binascii.unhexlify(hex_file_name).decode('utf-8')
    hex_string = hex_string[file_name_length:]

    file_extension_length = int(hex_string[:4], 16)
    hex_string = hex_string[4:]

    hex_string = hex_string[file_extension_length:]

    file_content = binascii.unhexlify(hex_string)
    output_path = os.path.join(output_dir, file_name)

    with open(output_path, 'wb') as file:
        file.write(file_content)


def decode_remark(remark):
    try:
        remark = base64.b64decode(remark)
        id = remark[:1]
        if id != b"0":
            return None
        op = remark[1:2]
        if op == b"0":
            # 铸造者地址
            return ("cast_header", remark[2:48])
        elif op == b"1":
            # 总字符数 + 名称
            return ("cast_abstract", int(remark[2:8], 16), remark[8:48])
        elif op == b"2":
            # 页数 + 内容
            return ("cast_page", int(remark[2:6], 16), remark[6:48])
        elif op == b"3":
            # 转让者地址
            return ("transfer", remark[2:48])
    except Exception:
        return None


def decode_all_remarks(all_remarks):
    castings = []
    abstract = None
    owner = None
    caster = None
    for remark in all_remarks:
        decoded = decode_remark(remark["remark"])
        if decoded:
            if decoded[0] == "cast_header" and caster is None:
                if sha256_22(remark["sender"]).encode() == decoded[1]:
                    caster = decoded[1]
                    owner = caster
            if decoded[0] == "cast_abstract" and caster:
                if abstract is None and sha256_22(remark["sender"]).encode() == caster:
                    abstract = (decoded[1], decoded[2])
            if decoded[0] == "cast_page" and caster:
                if sha256_22(remark["sender"]).encode() == caster:
                    castings.append((decoded[1], decoded[2]))
            if decoded[0] == "transfer" and caster:
                if sha256_22(remark["sender"]).encode() == owner:
                    owner = decoded[1]
    # 所有者地址, 总字符数、铸造内容、备注
    try:
        return owner, abstract[0], castings, abstract[1]
    except Exception:
        return None, None, None, None


def decode_file(length, castings, output_dir):
    castings = sorted(castings, key=lambda x: x[0])
    content = b""
    last_casting = -1
    for casting in castings:
        if last_casting == casting[0]:
            continue
        content += casting[1]
        last_casting = casting[0]
    content = content[:length]
    hex_to_file(binascii.hexlify(content).decode(), output_dir)
