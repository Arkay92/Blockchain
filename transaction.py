from hashlib import sha256

class Transaction:
    def __init__(self, sender, recipient, amount, data, signature=None, sender_public_key=None):
        if any(param is None for param in [sender, recipient, amount, data]):
            raise ValueError("Invalid transaction parameters")
        self.sender = sender
        self.recipient = recipient
        self.amount = float(amount)
        self.data = data
        self.signature = signature
        self.sender_public_key = sender_public_key  # Public key is now part of the transaction

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "data": self.data,
            "signature": self.signature.hex() if self.signature else None,
        }

    def sign(self, private_key):
        transaction_hash = self.hash_transaction()
        self.signature = private_key.sign(
            transaction_hash.encode(),
            ec.ECDSA(hashes.SHA256())
        )

    def verify(self):
        if not self.sender_public_key:
            raise ValueError("Sender public key not provided.")
        transaction_hash = self.hash_transaction()
        return self.sender_public_key.verify(
            self.signature,
            transaction_hash.encode(),
            ec.ECDSA(hashes.SHA256())
        )

    def hash_transaction(self):
        # Create a unique hash for a transaction
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        return sha256(transaction_str.encode()).hexdigest()
