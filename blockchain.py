import time, json, requests, sys, uuid, traceback, threading, sqlite3, aiosqlite, base58
from node import NodeValidator, Node
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from transaction import Transaction
from hashlib import sha256
import logging
from threading import Lock
from transaction import TransactionPool
from smart_contract import SmartContract
import hashlib, secrets
from requests.exceptions import RequestException, HTTPError
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from wallet import Wallet

logging.basicConfig(level=logging.DEBUG)

class BlockchainDB:
    def __init__(self, db_path='blockchain.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
        
    async def create_tables(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('CREATE TABLE IF NOT EXISTS blocks (index INT, hash TEXT, ...)')
            await db.execute('CREATE TABLE IF NOT EXISTS transactions (hash TEXT, block_index INT, ...)')
            await db.commit()

    async def add_block(self, block):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('INSERT INTO blocks (index, hash, ...) VALUES (?, ?, ...)', (block.index, block.hash))
            for tx in block.transactions:
                await db.execute('INSERT INTO transactions (hash, block_index, ...) VALUES (?, ?, ...)', (tx.hash(), block.index))
            await db.commit()

    def get_blockchain(self):
        cursor = self.conn.execute('SELECT * FROM blocks')
        blocks = cursor.fetchall()
        return blocks

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
    chain_lock = Lock()

    def __init__(self):
        self.node_validator = NodeValidator()
        self.nodes = []
        self.current_transactions = []
        self.transactions = []
        self.pending_transactions = []
        self.transaction_queue = [] 
        self.balances = {} 
        self.balances_lock = threading.Lock()
        self.transactions_lock = threading.Lock()
        self.transaction_pool = TransactionPool() 
        self.max_block_size = 1_000_000  
        self.wallets = {node.address: Wallet(node) for node in self.nodes}  
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.miner_node = Node(self.generate_address(self.public_key)) 
        self.nodes.append(self.miner_node) 
        self.wallets = {node.address: Wallet(node) for node in self.nodes}
        self.chain = [self.create_genesis_block()]
        self.smart_contracts = {}

    def generate_address(self, public_key):
        """Generate a blockchain address from a public key using SHA-256 and RIPEMD-160 hashing."""
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256_bpk = hashlib.sha256(serialized_public).digest()
        ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
        raw_address = b"\x00" + ripemd160_bpk  # Adding a version byte (0x00 for Bitcoin)
        checksum = hashlib.sha256(hashlib.sha256(raw_address).digest()).digest()[:4]
        return base58.b58encode(raw_address + checksum).decode('utf-8')

    def deploy_contract(self, code):
        contract = SmartContract(code, self)
        self.smart_contracts[contract.address] = contract
        print(f"Deployed contract at address {contract.address}")
        return contract.address

    def get_contract_by_address(self, address):
        return self.smart_contracts.get(address)

    def add_node(self, public_key):
        """Add a new node with a unique address to the blockchain."""
        address = self.generate_address(public_key)
        self.nodes.append(Node(address, public_key))  # Assuming Node constructor takes address and public key
        self.wallets[address] = Wallet(Node(address, public_key))

    def execute_contract(self, transaction):
        # Convert JSON string back to dictionary if needed
        data = json.loads(transaction.data) if transaction.data else {}
        context = {
            'sender': transaction.sender,
            'recipient': transaction.recipient,
            'amount': transaction.amount,
            'data': data  # Passing additional data to the contract
        }

        # Assuming the contract code defines a function called `contract_logic`
        local_context = {}
        exec(transaction.contract_code, globals(), local_context)
        contract_function = local_context['contract_logic']

        # Execute the contract logic function
        result = contract_function(context)

        # Update the transaction with the new amount after contract execution
        transaction.amount = result['amount']
        print(f"Contract executed. New transaction amount: {transaction.amount}")

    def get_next_transactions_for_block(self):
        transactions_for_block = []
        block_size = 0
        # Direct iteration instead of while with multiple condition checks
        for transaction in self.transaction_pool.transactions:
            if block_size + sys.getsizeof(transaction) > self.max_block_size:
                break
            transactions_for_block.append(transaction)
            block_size += sys.getsizeof(transaction)
        return transactions_for_block

    def get_balance(self, address):
        return self.balances.get(address, 0)

    def is_valid_chain(self, chain):
        return all(
            self.is_valid_proof(chain[i-1], chain[i].nonce) and
            chain[i].previous_hash == chain[i-1].hash
            for i in range(1, len(chain))
        )

    def check_double_spending(self, transaction):
        return any(
            tx.sender == transaction.sender and
            tx.recipient == transaction.recipient and
            tx.amount == transaction.amount
            for tx in self.current_transactions
        )

    def proof_of_work(self, last_block):
        """
        Perform proof-of-work by finding a nonce that, when combined with the previous block's hash,
        produces a hash with a certain number of leading zeros.
        """
        nonce = 0
        while True:
            guess = f'{last_block.hash}{nonce}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            if guess_hash[:self.DIFFICULTY] == '0' * self.DIFFICULTY:
                return nonce  # Found a valid nonce
            nonce += 1
    
    def is_valid_proof(self, last_block, nonce):
        guess = f'{last_block.hash}{nonce}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.DIFFICULTY] == '0' * self.DIFFICULTY

    def add_block(self, block):
        with self.chain_lock:
            if block.previous_hash != self.chain[-1].hash or not self.is_valid_proof(block, block.nonce):
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
                transaction = Transaction(self.miner_node.address, node.address, amount_per_node, "Initial Distribution", 1)
                self.transaction_pool.add_transaction(transaction)
                self.process_transaction(transaction)
        return True

    def create_genesis_block(self):
        # Creating initial transactions distributing funds to a central account
        initial_transactions = [Transaction("system", self.miner_node.address, 10000, "Genesis Block Reward", 1)]
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

        with self.transactions_lock:
            if not self.is_transaction_valid(transaction):
                logging.error(f"Invalid transaction: {transaction}")
                return None
            
            if not self.verify_transaction_signature(transaction):
                logging.error(f"Failed to verify transaction signature: {transaction}")
                return None

            self.transactions.append(transaction)
            self.current_transactions.append(transaction)
            self.transaction_pool.add_transaction(transaction)
            self.adjust_balances(transaction)
        
        logging.info(f"Transaction added to the pool: {transaction}")
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
            self.transaction_pool.add_transaction(transaction)
            return len(self.chain) + 1
        else:
            logging.error("Failed to add invalid transaction.")
            return None

    def mine(self):
        last_block = self.chain[-1]
        nonce = self.proof_of_work(last_block)
        transactions = self.get_next_transactions_for_block()
        new_block = Block(len(self.chain), time.time(), transactions, last_block.hash, nonce)
        if self.add_block(new_block):
            self.current_transactions = []  # Clear the list of transactions now that they are in a block
            return new_block
        return None

    def add_node(self):
        private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        public_key = private_key.public_key()

        node =  Node(self.generate_address(public_key))
        self.wallets[node.address] = Wallet(node)  # Create a wallet for the nod
        self.miner_node = node
        self.nodes.append(node)
        self.update_balances()  # Update balances after adding a new node
        return node.address

    def get_balances(self):
        balances = defaultdict(int)  # Use defaultdict for automatic handling of missing keys
        for block in self.chain:
            for transaction in block.transactions:
                balances[transaction.sender] -= transaction.amount
                balances[transaction.recipient] += transaction.amount

        # Update balances based on pending transactions
        for transaction in self.transactions:
            balances[transaction.sender] -= transaction.amount
            balances[transaction.recipient] += transaction.amount

        return dict(balances)  # Convert back to dict if necessary

    def update_balances(self):
        balances = self.get_balances()
        for node in self.nodes:
            node.balance = balances.get(node.address, 0)
    
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
        recipient = self.get_node_by_address(transaction.recipient) or self.get_contract_by_address(transaction.recipient)
        if isinstance(recipient, SmartContract):
            recipient.execute(transaction)
        else:
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
                self.transaction_pool.remove_transactions(self.transactions)  
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
            db = BlockchainDB()
            db.add_block(self.chain[-1])
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
                self.chain = [Block(
                    block_data["index"],
                    block_data["timestamp"],
                    [Transaction(**tx_data) for tx_data in block_data["transactions"]],
                    block_data["previous_hash"],
                    block_data["nonce"]
                ) for block_data in blockchain_data]
            logging.info("Blockchain loaded from disk successfully.")
        except FileNotFoundError:
            logging.warning("Blockchain file not found. Creating a new blockchain.")
            self.start_blockchain()  # Create a new blockchain if the file is not found
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
                response.raise_for_status()  # Checks if the response was successful
                data = response.json()
                length = data['length']
                chain = data['chain']
                if length > max_length and self.is_valid_chain(chain):
                    max_length = length
                    longest_chain = chain
            except HTTPError as e:
                logging.error(f"HTTP error when contacting node {node.address}: {str(e)}")
            except RequestException as e:
                logging.error(f"Network error when contacting node {node.address}: {str(e)}")
            except ValueError as e:
                logging.error(f"JSON decoding error: {str(e)}")

        if longest_chain:
            self.chain = longest_chain
            logging.info("Blockchain replaced by a longer chain")
            return True
        return False

    def get_transactions_by_address(self, address):
        transactions = []
        try:
            with open('blockchain.json', 'r') as file:
                blockchain_data = json.load(file)
                for block_data in blockchain_data:
                    for transaction_data in block_data.get('transactions', []):
                        if transaction_data.get('sender') == address or transaction_data.get('recipient') == address:
                            transactions.append(transaction_data)
            logging.info(f"Found {len(transactions)} transactions for address {address}")
        except FileNotFoundError:
            logging.error("Blockchain file not found.")
        except Exception as e:
            logging.error(f"An error occurred while loading blockchain from disk: {e}")
        return transactions

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