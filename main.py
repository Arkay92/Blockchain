import logging
from test import main as test_main
from flask import Flask, jsonify
from blockchain import Blockchain  

app = Flask(__name__)
blockchain = Blockchain()

@app.route('/<address>/transactions', methods=['GET'])
def get_transactions(address):
    try:
        transactions = blockchain.get_transactions_by_address(address)
        if not transactions:
            logging.debug(f"No transactions found for address: {address}")
            return jsonify({'message': 'No transactions found for this address'}), 404
        
        # Convert dictionary data to the required format
        transactions_data = [{'sender': txn.get('sender'), 'recipient': txn.get('recipient'), 'amount': txn.get('amount')} for txn in transactions]
        
        return jsonify(transactions_data), 200
    except Exception as e:
        logging.error(f"Error retrieving transactions for {address}: {str(e)}")
        return jsonify({'error': str(e)}), 500

def main():
    try:
        test_main()
        app.run(debug=True, port=5001)

    except Exception as e:
        logging.exception("An error occurred", exc_info=e)
        raise

if __name__ == '__main__':
    main()