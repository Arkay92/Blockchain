import threading
import asyncio
import time
import random
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode

try:
    blockchain = Blockchain()
    print("Blockchain created")

    # Start 25 nodes and fund them with 100 coins each
    nodes = []
    miner_address = blockchain.add_node()  # Add the miner's address
    for _ in range(25):
        address = blockchain.add_node()
        nodes.append(address)
        transaction = Transaction(miner_address, address, 100, "Initial funds", miner_node=blockchain.miner_node)
        transaction.sign()
        blockchain.new_transaction(transaction)

    print("25 nodes created and funded.")

    # Print balances of all nodes
    balances = blockchain.get_balances()
    print("Balances after funding:")
    for address, balance in balances.items():
        print(f"{address}: {balance}")
    
    async def start_server():
        node = P2PNode(blockchain)
        await node.start()

    thread = threading.Thread(target=lambda: asyncio.run(start_server()))
    thread.start()

    time.sleep(1)  # Wait for nodes to synchronize

    # Each node sends a transaction to three random recipients
    for sender in nodes:
        recipient = random.choice(nodes)
        if recipient != sender:
            sender_address = sender
            recipient_address = recipient
            sender_balance = blockchain.get_balances().get(sender_address, 0)
            print("Sender balance:", sender_balance)
            if sender_balance >= 1:  # Check if sender has sufficient funds
                print("Sender:", sender_address)
                print("Recipient:", recipient_address)
                transaction = Transaction(sender_address, recipient_address, 1, "Transaction", miner_node=blockchain.miner_node)
                transaction.sign()
                try:
                    blockchain.new_transaction(transaction)
                except Exception as e:
                    print("An error occurred:", str(e))
                    traceback.print_exc()
            else:
                print("Sender does not have sufficient funds to send the transaction.")

    # Start mining until three blocks are mined
    for _ in range(3):
        block = blockchain.mine_block()
        if block:
            print("New block mined successfully.")
            print(f"Block hash: {block.hash_block()}")
        else:
            print("Failed to mine a new block.")
            break

    print("Three blocks mined successfully.")

    # Print balances of all nodes
    balances = blockchain.get_balances()
    print("Balances after all transactions:")
    for address, balance in balances.items():
        print(f"{address}: {balance}")

    print("Printing the blockchain:")
    print(blockchain)

    # Start mining until miner rewards reach 20 coins
    while blockchain.get_balances()[blockchain.miner_node.address] < 20:
        block = blockchain.mine_block()
        if block:
            print("New block mined successfully.")
            print(f"Block hash: {block.hash_block()}")
        else:
            print("Failed to mine a new block.")
            break

    print("Miner rewards reached 20 coins.")

    # Send 0.5 coins to every node from the miner
    for recipient in nodes:
        transaction = Transaction(blockchain.miner_node.address, str(recipient), 0.5, "Reward", miner_node=blockchain.miner_node)
        transaction.sign()
        blockchain.new_transaction(transaction)

    print("Reward transactions sent to nodes.")

    time.sleep(1)  # Wait for transactions to be processed

    # Print balances of all nodes
    balances = blockchain.get_balances()
    print("Balances after all transactions:")
    for address, balance in balances.items():
        print(f"{address}: {balance}")

    print("Printing the blockchain:")
    print(blockchain)

except Exception as e:
    print(f"An error occurred: {e}")
