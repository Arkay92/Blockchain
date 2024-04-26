import time
import json
import socket
import requests
import sys
import uuid
import traceback
import threading
from node import NodeValidator, Node
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from transaction import Transaction
from hashlib import sha256
import logging
from threading import Lock
import hashlib, secrets

logging.basicConfig(level=logging.DEBUG)

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_tree = MerkleTree(transactions)
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.hash_block()  # This properly calls the method to initialize the hash

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
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash  # Use the hash attribute, not the hash_block method
        }

class Blockchain:
    BASE_REWARD = 50
    BASE_YEAR = 2023
    HALVING_FREQUENCY = 4
    DIFFICULTY = 2

    def __init__(self):
        self.node_validator = NodeValidator()
        self.nodes = []
        self.current_transactions = []
        self.transactions = []
        self.pending_transactions = []
        self.transaction_queue = []  # Initializing the transaction queue
        self.balances = {}  # Stores the balance for each node address
        self.balances_lock = threading.Lock()
        self.transactions_lock = threading.Lock()
        
        # Initialize the miner node first
        self.miner_node = Node(str(uuid.uuid4()))  # or some other unique identifier
        self.nodes.append(self.miner_node)  # Add the miner node to the list of nodes
        
        # Now that we have the miner node, we can create the genesis block
        self.chain = [self.create_genesis_block()]

    def get_balance(self, address):
        return self.balances.get(address, 0)

    def is_valid_chain(self, chain):
        if not chain:
            return False
        for i in range(1, len(chain)):
            if not self.is_valid_proof(chain[i-1], chain[i].nonce) or \
            chain[i].previous_hash != chain[i-1].hash:
                return False
        return True

    def check_double_spending(self, transaction):
        # Check if transaction is already in the current transactions
        for tx in self.current_transactions:
            if tx.sender == transaction.sender and tx.recipient == transaction.recipient and tx.amount == transaction.amount:
                return True
        return False

    def proof_of_work(self, last_block):
        nonce = 0
        while not self.is_valid_proof(last_block, nonce):
            nonce += 1
        return nonce
    
    def is_valid_proof(self, last_block, nonce):
        guess_hash = sha256(f'{last_block.hash}{nonce}'.encode()).hexdigest()
        return guess_hash[:self.difficulty] == '0' * self.difficulty

    def add_block(self, block):
        with self.chain_lock:
            if block.previous_hash != self.chain[-1].calculate_hash():
                return False
            if not self.is_valid_proof(block, block.nonce):
                return False
            self.chain.append(block)
            self.current_transactions = []
            return True

    def set_balance(self, address, amount):
        with self.balances_lock:
            self.balances[address] = amount

    def adjust_balance(self, address, amount):
        with self.balances_lock:
            if address in self.balances:
                self.balances[address] = self.balances.get(address, 0) + amount
            else:
                self.balances[address] = amount

    def get_node_by_address(self, address):
        return self.nodes.get(address)

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

    def distribute_initial_funds(self, amount_per_node):
        miner_balance = self.get_balance(self.miner_node.address)
        if miner_balance < amount_per_node * len(self.nodes):
            print("Not enough balance to distribute")
            return False
        for node in self.nodes:
            if node.address != self.miner_node.address:
                transaction = Transaction(self.miner_node.address, node.address, amount_per_node, "Initial Distribution")
                self.process_transaction(transaction)
        return True

    def create_genesis_block(self):
        # Creating initial transactions distributing funds to a central account
        initial_transactions = [Transaction("system", self.miner_node.address, 10000, "Genesis Block Reward")]
        return Block(0, time.time(), initial_transactions, "0", 0)
        
    def is_transaction_valid(self, transaction):
            if transaction.amount <= 0:
                logging.error("Transaction amount must be positive")
                return False
            if transaction.sender == transaction.recipient:
                logging.error("Sender and recipient cannot be the same")
                return False
            return True

    def add_transaction(self, transaction):
        """Add a new transaction to the blockchain after validation."""
        if not self.is_transaction_valid(transaction):
            logging.error(f"Invalid transaction: {transaction}")
            return None
        
        if not self.verify_transaction_signature(transaction):
            logging.error(f"Failed to verify transaction signature: {transaction}")
            return None

        with self.transactions_lock:
            self.transactions.append(transaction)
            self.current_transactions.append(transaction)
            self.add_to_transaction_queue(transaction)
            self.adjust_balances(transaction)
        
        logging.info(f"Transaction added to the queue: {transaction}")
        return len(self.chain) + 1

    def adjust_balances(self, transaction):
        # Adjust sender and recipient balances
        sender = transaction.sender
        recipient = transaction.recipient
        amount = transaction.amount

        sender_balance = getattr(self.get_node_by_address(sender), 'balance', 0)
        recipient_balance = getattr(self.get_node_by_address(recipient), 'balance', 0)

        setattr(self.get_node_by_address(sender), 'balance', sender_balance - amount)
        setattr(self.get_node_by_address(recipient), 'balance', recipient_balance + amount)

    def verify_transaction_signature(self, transaction):
        """Verify the signature of the transaction."""
        try:
            transaction.sender_public_key.verify(
                transaction.signature,
                transaction.to_string().encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            logging.error("Signature verification failed")
            return False
        except Exception as e:
            logging.error(f"Unexpected error during signature verification: {str(e)}")
            return False

    def new_transaction(self, transaction):
        if self.is_transaction_valid(transaction):
            self.transactions.append(transaction)
            self.adjust_balance(transaction.sender, -transaction.amount)
            self.adjust_balance(transaction.recipient, transaction.amount)
            return len(self.chain) + 1
        else:
            logging.error("Failed to add invalid transaction.")
            return None

    def mine(self):
        last_block = self.chain[-1]
        nonce = self.proof_of_work(last_block)
        new_block = Block(len(self.chain), time.time(), self.current_transactions, last_block.hash, nonce)
        return self.add_block(new_block)

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
        return Block(len(self.chain), time.time(), self.transactions.copy(), previous_hash, nonce)

    def valid_proof(self, last_hash, nonce, difficulty=None):
        """Validates the proof by checking if the hash of the last hash and nonce has the correct number of leading zeros."""
        difficulty = difficulty or self.DIFFICULTY
        guess = f'{last_hash}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def validate_block(self, block):
        """Validates the block by confirming if it meets the difficulty requirements."""
        return self.valid_proof(block.previous_hash, block.nonce, self.DIFFICULTY)

    def process_transaction(self, transaction):
        if not self.is_transaction_valid(transaction):
            return False
        self.adjust_balance(transaction.sender, -transaction.amount)
        self.adjust_balance(transaction.recipient, transaction.amount)
        self.transactions.append(transaction)
        return True

    def mine_block(self):
        if not self.transactions:
            logging.error("No transactions to mine.")
            return None
        last_block = self.chain[-1]
        nonce = 0
        while nonce < 1000:
            new_block = self.create_block(nonce, last_block.hash_block())
            if self.validate_block(new_block):
                self.chain.append(new_block)
                self.set_balance(self.miner_node.address, self.calculate_reward())  # Reward the miner
                self.transactions = []
                logging.info(f"Block mined successfully: {new_block.hash_block()}")
                return new_block
            nonce += 1
        logging.error("Failed to mine a new block.")
        return None

    def start_blockchain(self):
        # Create genesis block with initial funds
        self.chain.append(self.create_genesis_block())
        # Mine some initial blocks to build up additional rewards
        for _ in range(10):  # Mines 10 blocks
            self.mine_block()
        # Distribute funds from miner to other nodes
        self.distribute_initial_funds(100)  # Example: distribute 100 units to each node

    def save_to_disk(self, filename='blockchain.json'):
        with open(filename, 'w') as file:
            json.dump([block.to_dict() for block in self.chain], file)

    def load_from_disk(self, filename='blockchain.json'):
        try:
            with open(filename, 'r') as file:
                blockchain_data = json.load(file)
                # Load blockchain state from the file
        except FileNotFoundError:
            logging.warning("Blockchain file not found. Creating a new blockchain.")
            start_blockchain()
        except Exception as e:
            logging.error("An error occurred while loading blockchain from disk: %s", e)

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
        """
        Resolves conflicts by replacing the chain with the longest one in the network.
        """
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            try:
                response = requests.get(f'http://{node.address}/blocks')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Only replace if the new chain is longer and valid
                    if length > max_length and self.is_valid(chain):
                        max_length = length
                        longest_chain = chain
            except requests.RequestException as e:
                logging.error(f"Network error when contacting node {node.address}: {str(e)}")

        if longest_chain:
            self.chain = longest_chain
            logging.info("Blockchain replaced by a longer chain")
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

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_merkle_tree([tx.hash() for tx in transactions])  # Assuming Transaction objects have a hash method
    
    def build_merkle_tree(self, items):
        if not items:
            return None
        while len(items) > 1:
            new_level = []
            for i in range(0, len(items) - 1, 2):
                combined_hash = sha256((items[i] + items[i+1]).encode()).hexdigest()
                new_level.append(combined_hash)
            if len(items) % 2 == 1:
                new_level.append(items[-1])
            items = new_level
        return items[0]

    def get_root(self):
        return self.root