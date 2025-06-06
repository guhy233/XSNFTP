import binascii
import os
import base64
from sha256_22 import sha256_22


def file_to_hex(file_path):

    # 获取文件名和扩展名
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1]  # 获取文件扩展名

    with open(file_path, 'rb') as file:
        file_content = file.read()

    hex_file_name = binascii.hexlify(file_name.encode()).decode()
    hex_file_extension = binascii.hexlify(file_extension.encode()).decode()
    hex_file_content = binascii.hexlify(file_content).decode()

    # 组合成一个完整的16进制字符串，格式为：文件名长度 + 文件名 + 扩展名长度 + 扩展名 + 文件内容
    hex_string = f"{len(hex_file_name):04X}{hex_file_name}{len(hex_file_extension):04X}{hex_file_extension}{hex_file_content}"
    return hex_string


def build_cast_header(address):
    cast_header = "00"
    address_sha256 = sha256_22(address)

    cast_header += address_sha256
    
    return base64.b64encode(cast_header.encode()).decode()


def build_cast_abstract(hex_content, name):
    cast_abstract = "01"
    tothex = f"{len(hex_content):06X}"
    name = binascii.hexlify(name.encode()).decode()
    if len(name) > 32:
        name = name[:32]
        print("name is too long, only the first 32 characters will be used.")
    while len(name) < 32:
        name += "0"
    return base64.b64encode(f"{cast_abstract}{tothex}{bytes.fromhex(name).decode()}".encode()).decode()


def build_cast_page(hex_content):
    pages = [hex_content[i:i+36] for i in range(0, len(hex_content), 36)]
    while len(pages[-1]) < 36:
        pages[-1] += "0"
    cast_pages = []
    for i, page in enumerate(pages):
        page_bytes = bytes.fromhex(page)
        cast_pages.append(base64.b64encode(f"02{i:04X}".encode() + page_bytes).decode())
    return cast_pages

def build_all(file_path, address, remark):
    content = file_to_hex(file_path)
    cast_header = build_cast_header(address)
    cast_abstract = build_cast_abstract(content, remark)
    cast_pages = build_cast_page(content)
    return cast_header, cast_abstract, cast_pages


def build_transfer(address):
    return base64.b64encode(f"03{sha256_22(address.encode())}".encode()).decode()


