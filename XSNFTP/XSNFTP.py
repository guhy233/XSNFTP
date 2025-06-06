import encoder
import decoder
import crawler
import trans

MOUNT = 0.1

def get_info(nft_address):
    remarks = crawler.get_data(nft_address)
    decoded = decoder.decode_all_remarks(remarks)
    res = {
        "owner": decoded[0],
        "length": decoded[1],
        "name": decoded[3]
    }
    return res


def get_file(nft_address, output_dir):
    remarks = crawler.get_data(nft_address)
    decoded = decoder.decode_all_remarks(remarks)
    decoder.decode_file(decoded[1], decoded[2], output_dir)


def cast_file(file_path, address, nft_address, name, private_key_hex):
    hex_content = encoder.file_to_hex(file_path)
    cast_header = encoder.build_cast_header(address)
    cast_abstract = encoder.build_cast_abstract(hex_content, name)
    cast_pages = encoder.build_cast_page(hex_content)
    if not trans.attempt_make_trans(False, private_key_hex, address, nft_address, MOUNT, cast_header):
        return False
    if not trans.attempt_make_trans(False, private_key_hex, address, nft_address, MOUNT, cast_abstract):
        return False
    for page in cast_pages:
        if not trans.attempt_make_trans(False, private_key_hex, address, nft_address, MOUNT, page):
            return False
    return True


def transfer_file(address, private_key_hex, to_address, nft_address):
    transfer = encoder.build_transfer(to_address)
    if not trans.attempt_make_trans(False, private_key_hex, address, nft_address, MOUNT, transfer):
        return False
    return True
