import asyncio
import random
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
import json

async def start_p2p_server(blockchain):
    node = P2PNode(blockchain)
    await node.start()
    await node.sync_blocks()

def process_transaction(sender, recipient, amount, blockchain):
    if amount <= 0:
        print(f"Invalid transaction amount: {amount} must be positive.")
        return False
    if blockchain.get_balance(sender) < amount:
        print(f"Transaction failed: {sender} has insufficient funds.")
        return False
    transaction = Transaction(sender, recipient, amount, "Transfer")
    sender_node = blockchain.get_node_by_address(sender)
    if not sender_node:
        print(f"No node found for address {sender}.")
        return False
    sender_node.sign_transaction(transaction)
    blockchain.new_transaction(transaction)
    print(f"Transaction processed: {amount} from {sender} to {recipient}.")
    return True

def _verify_signature(public_key, signature, data):
    """Verify the signature with the given public key and data."""
    try:
        public_key.verify(signature, data.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False