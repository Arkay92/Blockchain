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
from hashlib import sha256
import logging
from threading import Lock

logging.basicConfig(level=logging.DEBUG)

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_tree = MerkleTree(transactions)
        self.previous_hash = previous_hash
        self.nonce = nonce

    def hash_block(self):
        block_str = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_tree.get_root(),
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return sha256(block_str.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [transaction.to_dict() for transaction in self.get_next_transactions_for_block()],
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
        self.pending_transactions = []
        self.transaction_queue = []  # Initializing the transaction queue
        self.node_validator = NodeValidator()
        self.nodes = []
        self.miner_node = Node(self.add_node())

    def add_to_transaction_queue(self, transaction):
        from heapq import heappush
        # Assuming transaction fee is a property of transaction. Adjust accordingly.
        heappush(self.transaction_queue, (-transaction.fee, transaction))

    def get_next_transactions_for_block(self):
        from heapq import heappop
        transactions_for_block = []
        while self.transaction_queue and len(transactions_for_block) < 10:  # Example limit for block size
            _, transaction = heappop(self.transaction_queue)
            transactions_for_block.append(transaction)
        return transactions_for_block

    def calculate_reward(self):
        current_year = datetime.now().year
        elapsed_years = current_year - self.BASE_YEAR
        return self.BASE_REWARD / (2 ** (elapsed_years // self.HALVING_FREQUENCY))

    def create_genesis_block(self):
        return Block(0, time.time(), [], "0", 0)
        
    def is_transaction_valid(self, transaction):
            if transaction.amount <= 0:
                logging.error("Transaction amount must be positive")
                return False
            if transaction.sender == transaction.recipient:
                logging.error("Sender and recipient cannot be the same")
                return False
            return True

    def add_transaction(self, transaction):
        # Perform thorough validation beyond just signature verification
        if not self.is_transaction_valid(transaction):
            logging.error("Invalid transaction rejected")
            return None
        if transaction.verify_signature():
            with self.chain_lock:
                self.transactions.append(transaction)
                self.add_to_transaction_queue(transaction)
                logging.info("Transaction added to the queue")
        else:
            logging.error("Failed to verify transaction signature")
            return None

        # Adjusting balances after validating the transaction
        sender = transaction.sender
        recipient = transaction.recipient
        amount = transaction.amount

        sender_balance = getattr(self.get_node_by_address(sender), 'balance', 0)
        recipient_balance = getattr(self.get_node_by_address(recipient), 'balance', 0)

        setattr(self.get_node_by_address(sender), 'balance', sender_balance - amount)
        setattr(self.get_node_by_address(recipient), 'balance', recipient_balance + amount)

        return len(self.chain) + 1

    def verify_transaction_signature(self, transaction):public_key = transaction.sender_public_key
        transaction_data = transaction.to_string()
        signature = transaction.signature
        try:
            return public_key.verify(signature, transaction_data.encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return None

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
    
    def create_block(self, nonce, previous_hash):
        """Create a new block using Penrose tiling entropy for additional security in block hash."""
        entropy_seed = Node().generate_entropy_based_seed()  # Assuming Node class has this method
        block_data = {
            "nonce": nonce,
            "previous_hash": previous_hash,
            "transactions": [tx.to_dict() for tx in self.get_next_transactions_for_block()],
            "entropy_seed": entropy_seed.hex()  # Including entropy in the block
        }
        block_str = json.dumps(block_data, sort_keys=True)
        block_hash = sha256(block_str.encode()).hexdigest()
        return Block(len(self.chain), time.time(), self.transactions.copy(), previous_hash, nonce, block_hash)

    def validate_block(self, block):
        # Implement basic validation: checking hash and if block is linked correctly
        expected_difficulty = '0' * self.DIFFICULTY
        return (block.hash_block()[:self.DIFFICULTY] == expected_difficulty and
                block.previous_hash == self.chain[-1].hash_block())

    def adjust_difficulty(self, last_block, current_time):
        expected_time = 10 * 60  # 10 minutes
        actual_time = current_time - last_block.timestamp
        if actual_time < expected_time / 2:
            self.DIFFICULTY += 1
        elif actual_time > expected_time * 2:
            self.DIFFICULTY = max(1, self.DIFFICULTY - 1)

    def mine_block(self):
        if not self.pending_transactions:
            logging.error("No transactions to mine.")
            return None
        last_block = self.chain[-1]
        nonce = 0
        current_time = time.time()
        self.adjust_difficulty(last_block, current_time)  # Adjust difficulty based on time to mine the last block

        while nonce < 1000:  # Limiting the nonce iterations for demonstration; adjust as necessary for production
            new_block = self.create_block(nonce, last_block.hash_block())
            if self.validate_block(new_block, self.DIFFICULTY):  # Validation includes checking the difficulty level
                self.chain.append(new_block)
                self.transactions = []  # Clear the list of transactions after they are added to a block
                logging.info(f"Block mined successfully: {new_block.hash_block()}")
                return new_block
            nonce += 1
        logging.error("Failed to mine a new block.")
        return None

    def valid_proof(self, last_hash, nonce, difficulty=None):
        """Validates the proof by checking if the hash of the last hash and nonce has the correct number of leading zeros."""
        difficulty = difficulty or self.DIFFICULTY
        guess = f'{last_hash}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def validate_block(self, block, difficulty):
        """Validates the block by confirming if it meets the difficulty requirements."""
        guess = f'{block.previous_hash}{block.nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def adjust_difficulty(self, last_block, current_time):
        """Adjusts the mining difficulty based on the rate at which the previous block was mined."""
        expected_time = 10 * 60  # Target time to mine a block is 10 minutes
        actual_time = current_time - last_block.timestamp
        if actual_time < expected_time / 2:
            self.DIFFICULTY += 1  # Increase difficulty if block was mined too quickly
        elif actual_time > expected_time * 2:
            self.DIFFICULTY = max(1, self.DIFFICULTY - 1)  # Decrease difficulty if block took too long to mine
        logging.info(f"Difficulty adjusted to {self.DIFFICULTY}")

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

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_merkle_tree(transactions)
    
    def build_merkle_tree(self, items):
        # Handling building of Merkle tree even when the number of items is odd
        if len(items) == 1:
            return items[0]
        new_level = []
        for i in range(0, len(items) - 1, 2):
            combined_hash = sha256((items[i] + items[i+1]).encode()).hexdigest()
            new_level.append(combined_hash)
        if len(items) % 2 == 1:
            new_level.append(items[-1])  # Append the last hash if odd number of hashes
        return self.build_merkle_tree(new_level)
    
    def get_root(self):
        return self.root