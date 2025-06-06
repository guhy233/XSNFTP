import requests
import json

NODE_RPC = "https://mainnet-rpc.xdagj.org"

def get_all_trans(address):
    page_size = 100
    current_page = 1
    all_transactions = []
    total_page = 1
    block_info = None

    while current_page <= total_page:
        params = [address, str(current_page), str(page_size)]
        payload = {
            "jsonrpc": "2.0",
            "method": "xdag_getBlockByHash",
            "params": params,
            "id": 1
        }
        headers = {'Content-Type': 'application/json'}

        response = requests.post(NODE_RPC, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        data = response.json()

        if 'error' in data:
            print(f"err: {data['error']}")
            return None

        result = data.get('result', {})
        if not block_info:
            # 保存首次请求的区块信息（排除交易）
            block_info = {k: v for k, v in result.items() if k != 'transactions'}

        # 合并交易记录
        transactions = result.get('transactions', [])
        all_transactions.extend(transactions)

        # 更新总页数
        total_page = int(result.get('totalPage', 1))
        current_page += 1

    if block_info is not None:
        block_info['transactions'] = all_transactions
        block_info['totalPage'] = total_page

    return block_info['transactions']


def get_remark(all_trans):
    res = []
    for trans in all_trans:
        if trans["direction"] == 0:
            params = [trans["address"], "1", "1"]
            payload = {
                "jsonrpc": "2.0",
                "method": "xdag_getBlockByHash",
                "params": params,
                "id": 1
            }
            headers = {'Content-Type': 'application/json'}

            response = requests.post(NODE_RPC, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            refs = response.json()["result"]["refs"]
            for ref in refs:
                if ref["direction"] == 0:
                    res.append({"sender": ref["address"], "remark": trans["remark"]})
                    break
    return res


def get_data(address):
    return get_remark(get_all_trans(address))[::-1]
