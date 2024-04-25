import threading
import asyncio
import time
import random
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode
import logging

def create_and_fund_nodes(blockchain, num_nodes=25, initial_funds=100):
    nodes = []
    miner_address = blockchain.add_node()  # Add the miner's address
    total_funding = num_nodes * initial_funds
    blockchain.set_balance(miner_address, total_funding)  # Ensure miner has enough funds

    for _ in range(num_nodes):
        address = blockchain.add_node()
        nodes.append(address)
        transaction = Transaction(miner_address, address, initial_funds, "Initial funds")
        blockchain.process_transaction(transaction)  # Process and record the transaction
    return nodes

def process_transaction(sender, recipient, amount, blockchain):
    if amount <= 0:
        print(f"Invalid transaction amount: {amount} must be positive.")
        return False
    if blockchain.get_balance(sender) < amount:
        print(f"Transaction failed: {sender} has insufficient funds.")
        return False
    transaction = Transaction(sender, recipient, amount, "Transfer")
    sender_node = blockchain.get_node_by_address(sender)
    if not sender_node:
        print(f"No node found for address {sender}.")
        return False
    sender_node.sign_transaction(transaction)
    blockchain.new_transaction(transaction)
    print(f"Transaction processed: {amount} from {sender} to {recipient}.")
    return True

def print_balances(blockchain):
    """Print balances in a more user-friendly manner."""
    balances = blockchain.get_balances()
    print("----------- Balances -----------")
    for address, balance in balances.items():
        print(f"Address: {address}, Balance: {balance}")
    print("--------------------------------")

async def start_p2p_server(blockchain):
    node = P2PNode(blockchain)
    await node.start()
    await node.sync_blocks()  # Sync blocks after starting the P2P server

def perform_transactions(blockchain, nodes):
    for sender in nodes:
        for _ in range(3):  # Each node sends a transaction to three different nodes
            recipient = random.choice(nodes)
            while recipient == sender:  # Ensure the recipient is not the sender
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

def main():
    try:
        blockchain = Blockchain()
        blockchain.load_from_disk()  # Load blockchain state from disk
        print("Blockchain loaded")

        # Ensure the miner has enough initial funds
        num_nodes = 25
        initial_funds = 100
        miner_initial_balance = num_nodes * initial_funds
        miner_address = blockchain.add_node()  # Make sure the miner node is created first
        blockchain.set_balance(miner_address, miner_initial_balance)  # Set the miner's initial balance

        nodes = create_and_fund_nodes(blockchain, num_nodes, initial_funds)
        print(f"{len(nodes)} nodes created and funded.")

        print_balances(blockchain)

        thread = threading.Thread(target=lambda: asyncio.run(start_p2p_server(blockchain)))
        thread.start()
        time.sleep(1)  # Wait for nodes to synchronize

        perform_transactions(blockchain, nodes)
        mine_blocks(blockchain)

        print_balances(blockchain)

        # Continue mining until a certain condition is met (example: miner rewards reach 20 coins)
        while blockchain.get_balances().get(blockchain.miner_node.address, 0) < 20:
            mine_blocks(blockchain, 1)

        print("Miner rewards reached 20 coins.")
        print_balances(blockchain)

        print("Printing the blockchain:")
        print(blockchain)

        blockchain.save_to_disk()  # Save blockchain state to disk

    except Exception as e:
        logging.exception("An error occurred", exc_info=e)
        raise

if __name__ == '__main__':
    main()