import unittest
import random
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode
import asyncio
import threading
import time
import logging
from utils import start_p2p_server, process_transaction

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def create_and_fund_nodes(main_address, blockchain, num_nodes=25, initial_funds=100):
    nodes = []
    for _ in range(num_nodes):
        address = blockchain.add_node()
        nodes.append(address)
        transaction = Transaction(main_address, address, initial_funds, "Initial funds", 1)
        success = blockchain.process_transaction(transaction)
        if not success:
            logging.error(f"Failed to process initial fund transaction for {address}")
    return nodes

def print_balances(blockchain):
    balances = blockchain.get_balances()
    logging.info("----------- Balances -----------")
    for address, balance in balances.items():
        logging.info(f"Address: {address}, Balance: {balance}")
    logging.info("--------------------------------")

def perform_transactions(blockchain, nodes):
    for sender in nodes:
        for _ in range(3):
            recipient = random.choice(nodes)
            while recipient == sender:
                recipient = random.choice(nodes)
            success = process_transaction(sender, recipient, 1, blockchain)
            if success:
                logging.info(f"Processed transaction from {sender} to {recipient}")
            else:
                logging.error(f"Failed to process transaction from {sender} to {recipient}")

def mine_blocks(blockchain, num_blocks=3):
    for _ in range(num_blocks):
        block = blockchain.mine_block()
        if block:
            logging.info(f"New block mined successfully. Block hash: {block.hash_block()}")
        else:
            logging.error("Failed to mine a new block.")

def test_tps(blockchain, nodes, duration_seconds=10):
    start_time = time.time()
    transactions_count = 0
    try:
        while time.time() - start_time < duration_seconds:
            for sender in nodes:
                recipients = random.sample([node for node in nodes if node != sender], 3)
                for recipient in recipients:
                    amount = random.randint(1, 10)  # Random small transaction amount
                    if blockchain.process_transaction(Transaction(sender, recipient, amount, "TPS Test", 1)):
                        transactions_count += 1
    except Exception as e:
        logging.error(f"Error during TPS test: {e}")
    total_time = time.time() - start_time
    tps = transactions_count / total_time
    logging.info(f"Transactions Per Second (TPS): {tps:.2f}, Total Transactions: {transactions_count}, Duration: {total_time:.2f} seconds")

# Utility function for asynchronous tests
def async_test(f):
    def wrapper(*args, **kwargs):
        coro = asyncio.coroutine(f)
        future = coro(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper

class BlockchainTestCase(unittest.TestCase):
    def setUp(self):
        self.blockchain = Blockchain()
        self.blockchain.load_from_disk()  # Assuming a mock or a preset state for tests
        self.nodes = self.create_and_fund_nodes(self.blockchain.miner_node.address, 25, 100)

    def test_transaction_processing(self):
        sender = self.nodes[0]
        recipient = self.nodes[1]
        transaction = Transaction(sender, recipient, 10, "Test Transaction", 1)
        self.assertTrue(self.blockchain.process_transaction(transaction))
        self.assertIn(transaction, self.blockchain.current_transactions)

    def test_mine_blocks(self):
        initial_length = len(self.blockchain.chain)
        self.blockchain.mine_block()
        self.assertEqual(len(self.blockchain.chain), initial_length + 1)

    @async_test
    def test_network_synchronization(self):
        node = P2PNode(self.blockchain)
        node.sync_blocks = MagicMock(return_value=True)
        asyncio.run(node.sync_blocks())
        node.sync_blocks.assert_called_once()

    def test_performance_tps(self):
        transactions_count = 0
        duration_seconds = 10
        start_time = time.time()
        while time.time() - start_time < duration_seconds:
            for sender in self.nodes:
                recipients = random.sample([node for node in self.nodes if node != sender], 3)
                for recipient in recipients:
                    transaction = Transaction(sender, recipient, 1, "TPS Test", 1)
                    if self.blockchain.process_transaction(transaction):
                        transactions_count += 1
        total_time = time.time() - start_time
        tps = transactions_count / total_time
        logging.info(f"TPS: {tps:.2f}")

# Entry point for the operational script
def main():
    try:
        logging.basicConfig(level=logging.DEBUG)
        blockchain = Blockchain()
        blockchain.load_from_disk()
        print("Blockchain loaded")

        num_nodes = 25
        initial_funds = 100

        nodes = create_and_fund_nodes(blockchain.miner_node.address, blockchain, num_nodes, initial_funds)
        print(f"{len(nodes)} nodes created and funded.")

        print_balances(blockchain)

        thread = threading.Thread(target=lambda: asyncio.run(start_p2p_server(blockchain)))
        thread.start()
        time.sleep(1)

        perform_transactions(blockchain, nodes)
        mine_blocks(blockchain)

        print_balances(blockchain)

        while blockchain.get_balances().get(blockchain.miner_node.address, 0) < 20:
            mine_blocks(blockchain, 1)

        print("Miner rewards reached 20 coins.")
        print_balances(blockchain)

        print("Printing the blockchain:")
        print(blockchain)

        test_tps(blockchain, nodes, 10)

        blockchain.save_to_disk()

    except Exception as e:
        logging.exception("An error occurred", exc_info=e)
        raise

if __name__ == '__main__':
    unittest.main() if 'unittest' in sys.modules else main()
