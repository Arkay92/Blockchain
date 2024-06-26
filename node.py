from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import hashlib, secrets, base58
from transaction import TransactionPool

class Node:
    def __init__(self, address=None):
        self.private_key, self.public_key = self.generate_keys_using_penrose()
        self.address = self.generate_address(self.public_key) if not address else address
        self.neighbors = []
        self.transaction_pool = TransactionPool()  # Initialize the transaction pool

    def generate_address(self, public_key):
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256_bpk = hashlib.sha256(serialized_public).digest()
        ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
        raw_address = b"\x00" + ripemd160_bpk  # Adding a version byte (0x00 for Bitcoin)
        checksum = hashlib.sha256(hashlib.sha256(raw_address).digest()).digest()[:4]
        return base58.b58encode(raw_address + checksum).decode('utf-8')

    def generate_keys_using_penrose(self):
        """Generate ECDSA key pair using Penrose tiling entropy."""
        try:
            seed = self.generate_entropy_based_seed()
            private_key = ec.derive_private_key(int.from_bytes(seed, 'big'), ec.SECP256R1(), default_backend())
            return private_key, private_key.public_key()
        except Exception as e:
            raise ValueError("Failed to generate keys: " + str(e))

    def generate_entropy_based_seed(self):
        """Generate seed based on Penrose tiling entropy."""
        # Simplified Penrose tiling logic for demonstration
        choices = ''.join(secrets.choice(['A', 'B']) for _ in range(256))
        return hashlib.sha256(choices.encode()).digest()

    def sign_transaction(self, transaction):
        transaction_data = transaction.to_string().encode()
        transaction.signature = self.private_key.sign(
            transaction_data,
            ec.ECDSA(hashes.SHA256())
        )

    def get_public_key_serialized(self):
        """Serialize the public key for network transmission or verification."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def add_transaction_to_pool(self, transaction):
        if transaction.is_valid(self.get_balance, self.check_double_spending):
            self.transaction_pool.add_transaction(transaction)
            self.broadcast_transaction(transaction)
        
    def audit_transaction(self, transaction):
        """Placeholder for auditing logic; in real-world, include compliance checks."""
        if transaction.amount < 0:
            raise ValueError("Invalid transaction amount: cannot be negative.")
        print("Transaction audited and approved.")
    
    def sync_with_network(self):
        for node in self.neighbors:
            # Assuming a method to fetch the chain from a neighbor
            node_chain = node.blockchain.chain
            if len(node_chain) > len(self.blockchain.chain) and self.validate_chain(node_chain):
                self.blockchain.chain = node_chain.copy()

    def validate_chain(self, chain):
        # Validate the entire blockchain
        for i in range(1, len(chain)):
            if chain[i].previous_hash != chain[i-1].calculate_hash():
                return False
            if not self.blockchain.is_valid_proof(chain[i-1], chain[i].nonce):
                return False
        return True

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
            # Assume block.signature and block.hash_block() are correctly formatted
            return node.public_key.verify(
                block.signature, 
                block.hash_block().encode(),
                ec.ECDSA(hashes.SHA256())
            )
        except Exception:
            return False