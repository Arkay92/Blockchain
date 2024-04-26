import random
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode
import asyncio
import threading
import time
import logging
from utils import start_p2p_server, process_transaction

def create_and_fund_nodes(blockchain, num_nodes=25, initial_funds=100):
    nodes = []
    miner_address = blockchain.add_node()
    total_funding = num_nodes * initial_funds
    blockchain.set_balance(miner_address, total_funding)

    for _ in range(num_nodes):
        address = blockchain.add_node()
        nodes.append(address)
        transaction = Transaction(miner_address, address, initial_funds, "Initial funds")
        blockchain.process_transaction(transaction)
    return nodes

def print_balances(blockchain):
    balances = blockchain.get_balances()
    print("----------- Balances -----------")
    for address, balance in balances.items():
        print(f"Address: {address}, Balance: {balance}")
    print("--------------------------------")

def perform_transactions(blockchain, nodes):
    for sender in nodes:
        for _ in range(3):
            recipient = random.choice(nodes)
            while recipient == sender:
                recipient = random.choice(nodes)
            if process_transaction(sender, recipient, 1, blockchain):
                print(f"Processed transaction from {sender} to {recipient}.")

def mine_blocks(blockchain, num_blocks=3):
    for _ in range(num_blocks):
        block = blockchain.mine_block()
        if block:
            print("New block mined successfully.")
            print(f"Block hash: {block.hash_block()}")
        else:
            print("Failed to mine a new block.")
            return

def test_tps(blockchain, nodes, duration_seconds=10):
    start_time = time.time()
    end_time = start_time + duration_seconds
    transactions_count = 0

    try:
        while time.time() < end_time:
            for sender in nodes:
                recipients = random.sample([node for node in nodes if node != sender], 3)
                for recipient in recipients:
                    amount = random.randint(1, 10)  # Random small transaction amount
                    transaction = Transaction(sender, recipient, amount, "TPS Test")
                    if blockchain.process_transaction(transaction):
                        transactions_count += 1
    except Exception as e:
        print(f"Error during TPS test: {e}")
    finally:
        total_time = time.time() - start_time
        tps = transactions_count / total_time
        print(f"Transactions Per Second (TPS): {tps:.2f}")
        print(f"Total Transactions: {transactions_count}")
        print(f"Duration: {total_time:.2f} seconds")

    return tps

def main():
    try:
        blockchain = Blockchain()
        blockchain.load_from_disk()
        print("Blockchain loaded")

        num_nodes = 25
        initial_funds = 100
        miner_initial_balance = num_nodes * initial_funds
        miner_address = blockchain.add_node()
        blockchain.set_balance(miner_address, miner_initial_balance)

        nodes = create_and_fund_nodes(blockchain, num_nodes, initial_funds)
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
    main()
