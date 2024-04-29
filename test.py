import asyncio, hashlib, secrets, unittest, random, asyncio, threading, time, logging, json
from blockchain import Blockchain
from transaction import Transaction
from p2p import P2PNode
from utils import start_p2p_server, process_transaction
from unittest.mock import patch
from blockchain import Blockchain
from transaction import Transaction
from smart_contract import SmartContract

# Initialize logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_entropy_based_seed():
    """Generate seed based on Penrose tiling entropy."""
    choices = ''.join(secrets.choice(['A', 'B']) for _ in range(256))
    return hashlib.sha256(choices.encode()).digest()

def secure_random_number(min, max):
    """Generate a cryptographically secure random number using Penrose tiling based entropy."""
    seed = generate_entropy_based_seed()
    seed_int = int.from_bytes(seed, 'big')
    secure_random = secrets.SystemRandom(seed_int)
    return secure_random.randint(min, max)

def create_and_fund_nodes(main_address, blockchain, num_nodes=25, initial_funds=100):
    nodes = []
    for _ in range(num_nodes):
        address = blockchain.add_node()
        transaction = Transaction(main_address, address, initial_funds, "Initial funds", 1)
        success = blockchain.process_transaction(transaction)
        if not success:
            logging.error(f"Failed to process initial fund transaction for {address}")
            continue
        nodes.append(address)
    return nodes

def print_balances(blockchain):
    balances = blockchain.get_balances()
    logging.info("----------- Balances -----------")
    for address, balance in balances.items():
        logging.info(f"Address: {address}, Balance: {balance}")
    logging.info("--------------------------------")

def perform_transactions(blockchain, nodes):
    transactions = []
    for sender in nodes:
        recipients = random.sample([node for node in nodes if node != sender], 3)
        for recipient in recipients:
            amount = secure_random_number(1, 10)
            transaction = Transaction(sender, recipient, amount, "Test Transaction", 1)
            success = blockchain.process_transaction(transaction)
            transactions.append((transaction, success))
            if success:
                logging.info(f"Processed transaction from {sender} to {recipient}")
            else:
                logging.error(f"Failed to process transaction from {sender} to {recipient}")
    return transactions

async def mine_blocks(blockchain):
    async def mine():
        block = blockchain.mine_block()
        if block:
            logging.info(f"New block mined successfully. Block hash: {block.hash_block()}")
    await asyncio.gather(*(mine() for _ in range(5)))

def test_tps(blockchain, nodes, duration_seconds=10):
    start_time = time.time()
    transactions_count = 0
    try:
        while time.time() - start_time < duration_seconds:
            for sender in nodes:
                recipients = random.sample([node for node in nodes if node != sender], 3)
                for recipient in recipients:
                    amount = secure_random_number(1, 10)  # Random small transaction amount
                    if blockchain.process_transaction(Transaction(sender, recipient, amount, "TPS Test", 1)):
                        transactions_count += 1
    except Exception as e:
        logging.error(f"Error during TPS test: {e}")
    total_time = time.time() - start_time
    tps = transactions_count / total_time
    logging.info(f"Transactions Per Second (TPS): {tps:.2f}, Total Transactions: {transactions_count}, Duration: {total_time:.2f} seconds")

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
        self.nodes = [Node() for _ in range(5)]
        self.genesis_block = self.blockchain.chain[0]

    def test_transaction_processing(self):
        sender = self.nodes[0].address
        recipient = self.nodes[1].address
        transaction = Transaction(sender, recipient, 10, "Test Transaction")
        self.assertTrue(self.blockchain.process_transaction(transaction))
        self.assertIn(transaction, self.blockchain.current_transactions)

    @patch('blockchain.Blockchain.proof_of_stake')
    def test_network_partition(self, mock_stake):
        """Test how the system behaves under a network partition."""
        mock_stake.side_effect = lambda last_block, txs: 'node1'
        # simulate a network partition here and check for consistency

    def test_large_scale_transactions(self):
        """Simulate a large number of transactions to test performance and stability."""
        blockchain = Blockchain()
        for _ in range(1000):
            blockchain.new_transaction(Transaction(sender="a", recipient="b", amount=10))
        blockchain.mine_block()
        self.assertTrue(len(blockchain.chain) > 1)

    def test_transaction_failures(self):
        sender = self.nodes[0]
        recipient = random.choice([node for node in self.nodes if node != sender])
        transaction = Transaction(sender, recipient, 1000000, "Invalid Transaction", 1)  # Presumably invalid due to funds
        self.assertFalse(self.blockchain.process_transaction(transaction))
        self.assertNotIn(transaction, self.blockchain.current_transactions)

    @async_test
    async def test_mine_blocks(self):
        initial_length = len(self.blockchain.chain)
        await asyncio.run(mine_blocks(self.blockchain))
        self.assertEqual(len(self.blockchain.chain), initial_length + 1)

    @async_test
    async def test_network_synchronization(self):
        node = P2PNode(self.blockchain)
        success = await node.sync_blocks()
        self.assertTrue(success)

    def test_performance_tps(self):
        start_time = time.time()
        transactions = perform_transactions(self.blockchain, self.nodes)
        successful_transactions = [t for t, success in transactions if success]
        total_time = time.time() - start_time
        tps = len(successful_transactions) / total_time
        logging.info(f"Transactions Per Second (TPS): {tps:.2f}")
    
    def test_smart_contract_execution(self):
        contract_code =  """def transfer_tokens(context):
                                return context['amount'] * 2"""
        contract_data = {'amount': 5}
        sender = self.nodes[0]
        recipient = self.nodes[1]
        transaction = Transaction(sender.address, recipient.address, 5, "Test Transaction", 1,
                                data=json.dumps(contract_data), contract_code=contract_code)
        self.assertTrue(self.blockchain.process_transaction(transaction))
        self.assertEqual(transaction.amount, 10)  # Assert that amount was doubled by smart contract

    def test_consensus_mechanism(self):
        new_block = self.blockchain.mine()
        self.assertNotEqual(new_block.previous_hash, self.genesis_block.hash_block())  # Assert new block is added
        self.assertEqual(new_block.index, self.genesis_block.index + 1)  # Assert block index is incremented

def deploy_token_contract(blockchain, sender_address, recipient_address):
    # Ensure positive amount for deployment transaction
    amount = 100  # Initial transfer amount
    if amount <= 0:
        logging.error("Transaction amount must be positive")
        return

    # Token Contract Code
    token_contract_code = """
    def transfer_tokens(context):
        sender_balance = context['sender_balance']
        recipient_balance = context['recipient_balance']
        amount = context['amount']
        if sender_balance >= amount:
            sender_balance -= amount
            recipient_balance += amount
            context['sender_balance'] = sender_balance
            context['recipient_balance'] = recipient_balance
        return context
    """
    
    # Initial token balances
    initial_sender_balance = 1000
    initial_recipient_balance = 0

    # Data for the token contract
    token_contract_data = {
        "sender_balance": initial_sender_balance,
        "recipient_balance": initial_recipient_balance,
        "amount": amount  # Initial transfer amount
    }

    # Create a transaction to deploy the token contract
    transaction = Transaction(
        sender=sender_address,
        recipient=recipient_address,
        amount=amount,
        description="Token Contract Deployment",
        fee=1,
        data=json.dumps(token_contract_data),
        contract_code=token_contract_code
    )

    # Deploy contract
    contract_address = blockchain.deploy_contract(token_contract_code)
    sender = "17FSSWYQpvkjJf1M4YMSZZHj4K652oDwNy"
    transaction = Transaction(sender, contract_address, 5, "Contract Interaction", 10, data=json.dumps({'amount': 5}))

    # Process the transaction to deploy the token contract
    if blockchain.process_transaction(transaction):
        logging.info("Token contract deployed successfully")
    else:
        logging.error("Failed to deploy token contract")

def transfer_tokens(blockchain, sender_address, recipient_address, amount):
    # Ensure positive amount for token transfer
    if amount <= 0:
        logging.error("Transaction amount must be positive")
        return

    # Construct the transaction to invoke the token transfer logic
    transfer_data = {
        "sender": sender_address,
        "recipient": recipient_address,
        "amount": amount
    }

    # Create a transaction to transfer tokens
    transaction = Transaction(
        sender=sender_address,
        recipient=recipient_address,
        amount=amount,
        description="Token Transfer",
        fee=1,
        data=json.dumps(transfer_data),
        contract_code=""  # No contract code needed for token transfer
    )

    # Process the transaction to transfer tokens
    if blockchain.process_transaction(transaction):
        logging.info(f"Tokens transferred successfully from {sender_address} to {recipient_address}")
    else:
        logging.error("Failed to transfer tokens")

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
        asyncio.run(mine_blocks(blockchain))

        print_balances(blockchain)

        while blockchain.get_balances().get(blockchain.miner_node.address, 0) < 20:
            asyncio.run(mine_blocks(blockchain))

        print("Miner rewards reached 20 coins.")
        print_balances(blockchain)

        print("Printing the blockchain:")
        print(blockchain)

        test_tps(blockchain, nodes, 10)

        # Smart Contract Code
        contract_code = """
        def contract_logic(context):
            amount = context['amount']
            if amount == 5:
                context['amount'] *= 2  # Doubles the amount if it's exactly 5
            return context
        """

        # Data that might be used by the contract
        contract_data = json.dumps({
            "required_amount": 5,  # This could be any data needed for the contract logic
        })

        amount = secure_random_number(1, 10)  # Generates a random amount between 1 and 10
        transaction = Transaction(
            sender="1wajHnSvVe6JXdVx17AymCnzL6VDdx97F",
            recipient="13e5McNbKfVckxLR8APdWyPWAXctJzgbzE",
            amount=amount,
            description="Test Transaction",
            fee=1,
            data=contract_data,
            contract_code=contract_code
        )

        # Deploy contract
        contract_address = blockchain.deploy_contract(contract_code)
        sender = nodes[0]
        transaction = Transaction(sender, contract_address, 5, "Contract Deploy", 10, data=json.dumps({'amount': 5}))

        # Process the transaction after contract execution
        if blockchain.process_transaction(transaction):
            print("Transaction processed successfully with updated amount from smart contract.")
        else:
            print("Failed to process transaction after contract execution.")

        deploy_token_contract(blockchain, sender_address="1wajHnSvVe6JXdVx17AymCnzL6VDdx97F", 
                            recipient_address="13e5McNbKfVckxLR8APdWyPWAXctJzgbzE")
                            
        transfer_tokens(blockchain, sender_address="1wajHnSvVe6JXdVx17AymCnzL6VDdx97F", 
                        recipient_address="13e5McNbKfVckxLR8APdWyPWAXctJzgbzE", amount=50)

        blockchain.save_to_disk()

    except Exception as e:
        logging.exception("An error occurred", exc_info=e)
        raise

if __name__ == '__main__':
    unittest.main() if 'unittest' in sys.modules else main()
