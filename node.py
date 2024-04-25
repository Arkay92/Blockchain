from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, secrets

class Node:
    def __init__(self, address=None):
        self.address = address if address else str(uuid.uuid4())
        self.private_key, self.public_key = self.generate_keys_using_penrose()

    def generate_keys_using_penrose(self):
        seed = self.generate_entropy_based_seed()
        private_key = ec.derive_private_key(int.from_bytes(seed, 'big'), ec.SECP256R1(), default_backend())
        return private_key, private_key.public_key()

    def generate_entropy_based_seed(self):
        """Generate seed based on Penrose tiling entropy."""
        # Simplified Penrose tiling logic for demonstration
        choices = ''.join(secrets.choice(['A', 'B']) for _ in range(256))
        return hashlib.sha256(choices.encode()).digest()

    def sign_transaction(self, transaction_data):
        """Sign a transaction using the private key."""
        return self.private_key.sign(
            transaction_data,
            ec.ECDSA(hashes.SHA256())
        )

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
