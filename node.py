from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

class Node:
    def __init__(self, address=None):
        self.address = address if address else str(uuid.uuid4())
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, message, signature):
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class NodeValidator:
    def __init__(self):
        self.confirmations_needed = 20

    def validate_block(self, block, nodes):
        confirmations = 0
        for node in nodes:
            if self.is_block_approved_by_node(block, node):
                confirmations += 1
            if confirmations >= self.confirmations_needed:
                return True
        return False

    def is_block_approved_by_node(self, block, node):
        try:
            node.verify(block.hash_block().encode(), block.signature)
            return True
        except Exception:
            return False
