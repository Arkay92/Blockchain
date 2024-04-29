from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from collections import namedtuple
import heapq, json, time

TransactionEntry = namedtuple('TransactionEntry', ['fee', 'timestamp', 'transaction'])

# Transaction Pool to hold unconfirmed transactions
class TransactionPool:
    def __init__(self):
        self.transactions = {}
        self.transaction_map = {}

    def add_transaction(self, transaction):
        tx_hash = transaction.hash()
        if tx_hash not in self.transactions:
            entry = (-transaction.fee, transaction.timestamp, transaction)
            self.transactions[tx_hash] = transaction
            self.transaction_map[transaction.hash()] = transaction
            heapq.heappush(self.transactions, entry)
            return True
        return False

    def remove_transactions(self, transactions):
        for transaction in transactions:
            tx_hash = transaction.hash()
            if tx_hash in self.transactions:
                del self.transactions[tx_hash]

    def pick_transaction(self):
        while self.transactions:
            entry = heapq.heappop(self.transactions)
            if entry.transaction.hash() in self.transaction_map:
                del self.transaction_map[entry.transaction.hash()]
                return entry.transaction
        return None

    def get_transactions(self):
        return list(self.transactions.values())

class Transaction:
    def __init__(self, sender, recipient, amount, description, fee, data="", contract_code="", sender_private_key=None, sender_public_key=None, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature 
        self.description = description
        self.sender_public_key = sender_public_key  # Public key is passed during transaction creation
        self.timestamp = time.time()
        self.fee = fee
        self.data = data
        self.contract_code = contract_code
        if sender_private_key:
            self.sign(sender_private_key)

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            "signature": self.signature.hex() if self.signature else None,
            "description": self.description,
        }

    def sign(self, private_key):
        """Sign the transaction with sender's private key."""
        transaction_data = self.to_string().encode()
        self.signature = private_key.sign(transaction_data, ec.ECDSA(hashes.SHA256()))

    def to_string(self):
        return f"{self.sender}{self.recipient}{self.amount}{self.description}"

    def verify_signature(self):
        if self.sender_public_key is None:
            return False
        try:
            self.sender_public_key.verify(self.signature, self.to_string().encode(), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            logging.error("Failed to verify signature: %s", str(e))
            return False

    def hash(self):
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        return sha256(transaction_str.encode()).hexdigest()
    
    def is_valid(self, get_balance, check_double_spending):
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