from eth_account.messages import encode_defunct
from web3 import Web3

def verify_signature(address, signature, message="Login to Celo Protected App"):
    message_encoded = encode_defunct(text=message)
    recovered_address = Web3().eth.account.recover_message(message_encoded, signature=signature)
    return recovered_address.lower() == address.lower()
