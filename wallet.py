from transaction import TransactionPool

class Wallet:
    def __init__(self, node=None):
        self.node = node if node else Node()  # Pass an existing node or create a new one

    def get_balance(self, blockchain):
        return blockchain.get_balance(self.node.address)

    def send_money(self, recipient_address, amount, blockchain):
        transaction = Transaction(self.node.address, recipient_address, amount, "Transfer", fee=1)
        if self.node.sign_transaction(transaction):  # Assuming a method to sign a transaction
            if blockchain.add_transaction(transaction):
                print("Transaction successfully added to blockchain.")
            else:
                print("Failed to add transaction.")
        else:
            print("Failed to sign transaction.")

    def get_address(self):
        return self.node.address