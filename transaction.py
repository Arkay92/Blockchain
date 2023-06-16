class Transaction:
    def __init__(self, sender, recipient, amount, data, signature=None, miner_node=None):
        if sender is None or recipient is None or amount is None or data is None:
            raise ValueError("Invalid transaction parameters")
        self.sender = sender
        self.recipient = recipient
        self.amount = float(amount)
        self.data = data
        self.signature = signature if signature else b''
        self.miner_node = miner_node if miner_node else None

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "data": self.data,
            "signature": self.signature.hex() if self.signature else None,
        }

    def sign(self):
        sender_bytes = self.sender if isinstance(self.sender, bytes) else self.sender.encode()
        recipient_bytes = self.recipient if isinstance(self.recipient, bytes) else self.recipient.encode()
        amount_bytes = str(self.amount).encode()
        data_bytes = self.data if isinstance(self.data, bytes) else self.data.encode()

        message = sender_bytes + recipient_bytes + amount_bytes + data_bytes
        self.signature = self.miner_node.sign(message)

    def verify(self):
        sender_bytes = self.sender if isinstance(self.sender, bytes) else self.sender.encode()
        recipient_bytes = self.recipient if isinstance(self.recipient, bytes) else self.recipient.encode()
        amount_bytes = str(self.amount).encode()
        data_bytes = self.data if isinstance(self.data, bytes) else self.data.encode()

        message = sender_bytes + recipient_bytes + amount_bytes + data_bytes
        return self.miner_node.verify(message, self.signature)
