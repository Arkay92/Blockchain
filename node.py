from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

class Node:
    def __init__(self, address=None):
        self.address = address if address else str(uuid.uuid4())
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        signature = self.private_key.sign(
            digest.finalize(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify(self, message, signature):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        try:
            self.public_key.verify(
                signature,
                digest.finalize(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
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
