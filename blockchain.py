import time
import json
import socket
import requests
import sys
import uuid
import traceback
from node import NodeValidator, Node
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from transaction import Transaction

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce, validations=None, signature=None):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.validations = validations if validations else []
        self.signature = signature if signature else b''

    def hash_block(self):
        block_str = json.dumps(self.to_dict(), sort_keys=True)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(block_str.encode())
        return digest.finalize().hex()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [transaction.to_dict() for transaction in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "validations": self.validations,
            "signature": self.signature.hex() if self.signature else None
        }

class Blockchain:
    BASE_REWARD = 50
    BASE_YEAR = 2023
    HALVING_FREQUENCY = 4
    DIFFICULTY = 1

    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.transactions = []
        self.node_validator = NodeValidator()
        self.nodes = []
        self.miner_node = Node(self.add_node())

    def calculate_reward(self):
        current_year = datetime.now().year
        elapsed_years = current_year - self.BASE_YEAR
        return self.BASE_REWARD / (2 ** (elapsed_years // self.HALVING_FREQUENCY))

    def create_genesis_block(self):
        return Block(0, time.time(), [], "0", 0)

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

        sender = transaction.sender
        recipient = transaction.recipient
        amount = transaction.amount

        sender_balance = getattr(self.get_node_by_address(sender), 'balance', 0)
        recipient_balance = getattr(self.get_node_by_address(recipient), 'balance', 0)

        setattr(self.get_node_by_address(sender), 'balance', sender_balance - amount)
        setattr(self.get_node_by_address(recipient), 'balance', recipient_balance + amount)

        return len(self.chain) + 1

    def new_transaction(self, transaction):
        self.transactions.append(transaction)
        return len(self.chain) - 1

    def add_node(self, address=None):
        if address is None:
            node = Node(str(uuid.uuid4()))
            self.miner_node = node
            self.nodes.append(node)
            self.update_balances()  # Update balances after adding a new node
            return node.address
        else:
            node = self.get_node_by_address(address)
            if node is None:
                node = Node(address)
                self.miner_node = node
                self.nodes.append(node)
                self.update_balances()  # Update balances after adding a new node
                return node.address
            else:
                return node.address

    def get_balances(self):
        balances = {}
        for block in self.chain:
            for transaction in block.transactions:
                sender = transaction.sender
                recipient = transaction.recipient
                amount = transaction.amount

                balances[sender] = balances.get(sender, 0) - amount
                balances[recipient] = balances.get(recipient, 0) + amount

        # Update balances based on pending transactions
        for transaction in self.transactions:
            sender = transaction.sender
            recipient = transaction.recipient
            amount = transaction.amount

            balances[sender] = balances.get(sender, 0) - amount
            balances[recipient] = balances.get(recipient, 0) + amount

        return balances

    def update_balances(self):
        balances = self.get_balances()
        for node in self.nodes:
            address = node.address
            balance = balances.get(address, 0)
            setattr(node, 'balance', balance)

    def mine_block(self):
        try:
            last_block = self.chain[-1]
            index = last_block.index + 1
            timestamp = time.time()
            transactions = self.transactions.copy()
            reward = self.calculate_reward()

            transactions.append(Transaction(self.miner_node.address, self.miner_node.address, reward, "reward", miner_node=self.miner_node))
            previous_hash = last_block.hash_block()

            max_attempts = 1000
            nonce = 0
            while nonce < max_attempts:
                block = Block(index, timestamp, transactions, previous_hash, nonce)
                block_hash = block.hash_block()
                if block_hash[:self.DIFFICULTY] == '0' * self.DIFFICULTY and self.node_validator.validate_block(block, self.nodes):
                    self.chain.append(block)
                    self.transactions = []
                    return block
                nonce += 1

            return None

        except Exception as e:
            print("An error occurred while mining a new block:")
            print(str(e))
            traceback.print_exc()
        return None

    def get_node_by_address(self, address):
        for node in self.nodes:
            if node.address == address:
                return node
        return None

    def resolve_conflicts(self):
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            response = requests.get(f'http://{node.address}/blocks')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.is_valid(chain):
                    max_length = length
                    longest_chain = chain

        if longest_chain:
            self.chain = longest_chain
            return True

        return False

    def is_valid(self, chain=None):
        if chain is None:
            chain = self.chain

        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            if current_block.previous_hash != previous_block.hash_block():
                return False
        return True

    def __str__(self):
        return json.dumps([block.to_dict() for block in self.chain], indent=2)
