from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from collections import namedtuple
import heapq, json, time

TransactionEntry = namedtuple('TransactionEntry', ['fee', 'timestamp', 'transaction'])

# Transaction Pool to hold unconfirmed transactions
class TransactionPool:
    def __init__(self):
        self.transactions = []  # Use a list for the heap
        self.transaction_map = {}  # Use a dictionary for quick lookup

    def add_transaction(self, transaction):
        tx_hash = transaction.hash()
        if tx_hash not in self.transaction_map:
            entry = (-transaction.fee, transaction.timestamp, transaction)
            heapq.heappush(self.transactions, entry)
            self.transaction_map[tx_hash] = entry
            return True
        return False

    def remove_transactions(self, transactions):
        for transaction in transactions:
            tx_hash = transaction.hash()
            if tx_hash in self.transaction_map:
                self.transaction_map.pop(tx_hash)
        # Rebuild the heap since removal could disrupt the heap property
        self.transactions = [self.transaction_map[tx_hash] for tx_hash in self.transaction_map]
        heapq.heapify(self.transactions)

    def pick_transaction(self):
        while self.transactions:
            _, _, transaction = heapq.heappop(self.transactions)
            tx_hash = transaction.hash()
            if tx_hash in self.transaction_map:
                self.transaction_map.pop(tx_hash)
                return transaction
        return None

class Transaction:
    def __init__(self, sender, recipient, amount, description, fee, data="", contract_code="", sender_private_key=None, sender_public_key=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.description = description
        self.fee = fee
        self.data = data
        self.contract_code = contract_code
        self.timestamp = time.time()
        self.sender_public_key = sender_public_key  # Public key should be serialized if it's being passed around
        self.signature = None
        if sender_private_key:
            self.sign(sender_private_key)

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature.hex() if self.signature else None,
            'description': self.description,
            'timestamp': self.timestamp,
            'fee': self.fee,
            'data': self.data,
            'contract_code': self.contract_code
        }

    def sign(self, private_key):
        """Sign the transaction with sender's private key."""
        transaction_data = self.to_string().encode()
        self.signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))

    def to_string(self):
        """Return a string representation of the transaction used for signing."""
        return f"{self.sender}{self.recipient}{self.amount}{self.timestamp}{self.description}{self.fee}{self.data}{self.contract_code}"

    def verify_signature(self):
        """Verify the signature of the transaction using the sender's public key."""
        if self.signature and self.sender_public_key:
            transaction_data = self.to_string().encode()
            try:
                self.sender_public_key.verify(
                    self.signature,
                    transaction_data,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            except Exception as e:
                logging.error(f"Signature verification failed: {str(e)}")
        return False

    def hash(self):
        """Return the SHA-256 hash of the transaction."""
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        return sha256(transaction_str.encode()).hexdigest()

    def is_valid(self, get_balance, check_double_spending):
        """Validate the transaction against several checks."""
        if self.amount <= 0:
            logging.error("Transaction amount must be positive")
            return False
        if self.sender == self.recipient:
            logging.error("Sender and recipient cannot be the same")
            return False
        if not self.verify_signature():
            logging.error("Invalid signature")
            return False
        if get_balance(self.sender) < self.amount:
            logging.error("Insufficient funds")
            return False
        if check_double_spending(self):
            logging.error("Double spending detected")
            return False
        return True