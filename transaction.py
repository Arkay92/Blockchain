from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
import json, base64

class Transaction:
    def __init__(self, sender, recipient, amount, description, sender_private_key=None, sender_public_key=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = None 
        self.description = description
        self.sender_public_key = sender_public_key  # Public key is passed during transaction creation
        if sender_private_key:
            self.sign(sender_private_key)

    def to_string(self):
        # Create a string representation of the transaction, excluding the signature
        return f"{self.sender}{self.recipient}{self.amount}{self.description}"

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': base64.b64encode(self.signature).decode('utf-8') if self.signature else None,
            "description": self.description,
        }

    def sign(self, private_key):
        """Sign the transaction with sender's private key."""
        transaction_data = str(self.sender) + str(self.recipient) + str(self.amount) + self.description
        self.signature = private_key.sign_transaction(transaction_data.encode())

    def verify_signature(self):
        """Verify the transaction signature with the sender's public key."""
        transaction_data = str(self.sender) + str(self.recipient) + str(self.amount) + self.description
        try:
            self.sender_public_key.verify(
                self.signature,
                transaction_data.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def hash(self):
        transaction_str = json.dumps(self.to_dict(), sort_keys=True)
        return sha256(transaction_str.encode()).hexdigest()