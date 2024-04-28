
import asyncio, time, threading, logging, ssl, requests, websockets
from socketserver import BaseRequestHandler, ThreadingTCPServer
from transaction import Transaction
from ssl import create_default_context, CERT_REQUIRED, Purpose

class P2PRequestHandler(BaseRequestHandler):
    MAX_REQUESTS_PER_MINUTE = 1000

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests = 0
        self.reset_time = time.time()

    def handle(self):
        try:
            self.requests += 1
            current_time = time.time()
            if current_time - self.reset_time > 60:
                self.requests = 0
                self.reset_time = current_time

            if self.requests > self.MAX_REQUESTS_PER_MINUTE:
                raise Exception("Too many requests")

            request = self.request.recv(1024).decode()
            response = asyncio.run(self.node.handle_request(request))
            return response.encode()

        except Exception as e:
            error_message = f"An error occurred: {str(e)}"
            traceback_str = traceback.format_exc()
            print(error_message)
            print(traceback_str)
            return f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_message}\n{traceback_str}".encode()

class P2PNode:
    def __init__(self, blockchain):
        self.peers = []
        self.server_address = ('', 5000)
        self.running = False
        self.blockchain = blockchain
        self.server = None

    async def sync_blocks(self):
        for peer_address in self.peers:
            try:
                response = await self.request_blocks(peer_address)
                if response and response.status_code == 200:
                    blocks = response.json().get('blocks', [])
                    for block_data in blocks:
                        block = Block(**block_data)
                        if self.blockchain.validate_block(block):
                            self.blockchain.add_block(block)
            except Exception as e:
                logging.error("Error syncing with peer %s: %s", peer_address, str(e))
    
    async def request_blocks(self, peer_address):
        try:
            response = await requests.get(f'http://{peer_address}/blocks')
            return response
        except Exception as e:
            logging.error("Failed to request blocks from peer %s: %s", peer_address, e)
            return None

    async def handle_request(self, request):
        try:
            request_str = request.decode()
            print("Received request:", request_str)
            response = await self.process_request(request_str)
            return response.encode()
        except Exception as e:
            print("Error handling request:", str(e))
            return "HTTP/1.1 500 Internal Server Error\r\n\r\n".encode()

    async def handler(self, websocket, path):
        self.peers.add(websocket)
        try:
            async for message in websocket:
                data = json.loads(message)
                await self.process_message(data, websocket)
        finally:
            self.peers.remove(websocket)

    async def process_message(self, data, websocket):
        if data['type'] == 'new_transaction':
            # Handle new transaction
            await self.handle_new_transaction(data, websocket)
        elif data['type'] == 'new_block':
            # Handle new block
            await self.handle_new_block(data, websocket)

    def broadcast_transaction(self, transaction):
        for peer in self.peers:
            try:
                # Send transaction to peer
                requests.post(f'http://{peer}/transactions/new', json=transaction.to_dict())
            except Exception as e:
                logging.error("Failed to send transaction to peer %s: %s", peer, str(e))

    async def sync_transaction_pool(self):
        for peer in self.peers:
            try:
                response = requests.get(f'http://{peer}/transactions/pool')
                if response.status_code == 200:
                    transactions = [Transaction.from_json(tx) for tx in response.json()['transactions']]
                    for tx in transactions:
                        if not any(tx.id == existing_tx.id for existing_tx in self.transaction_pool.transactions):
                            self.add_transaction_to_pool(tx)
            except Exception as e:
                logging.error("Failed to synchronize transaction pool from peer %s: %s", peer, str(e))

    async def handle_new_transaction(self, data, websocket):
        try:
            transaction_data = data['data']  # Assuming 'data' contains transaction information
            new_transaction = Transaction(**transaction_data)  # Creating a new transaction object
            if self.blockchain.is_valid_transaction(new_transaction):
                # If the transaction is valid, add it to the pending transactions pool
                self.blockchain.add_transaction(new_transaction)
                # Broadcast the transaction to all connected peers
                await self.broadcast(json.dumps({"type": "new_transaction", "data": transaction_data}))
                # Send a success response back to the sender
                await websocket.send(json.dumps({"status": "success", "message": "Transaction added to the pending pool"}))

                if self.node.add_transaction_to_pool(transaction):
                    return "HTTP/1.1 200 OK\\r\\n\\r\\nTransaction added."
                else:
                    return "HTTP/1.1 400 Bad Request\\r\\n\\r\\nTransaction validation failed."
            else:
                # If the transaction is invalid, reject it and send an error response back to the sender
                await websocket.send(json.dumps({"status": "error", "message": "Invalid transaction"}))
        except Exception as e:
            # If an error occurs during transaction handling, send an error response back to the sender
            await websocket.send(json.dumps({"status": "error", "message": str(e)}))

    async def handle_new_block(self, data, websocket):
        try:
            block_data = data['data']  # Assuming 'data' contains block information
            new_block = Block(**block_data)  # Creating a new block object
            if self.blockchain.is_valid_block(new_block):
                # If the block is valid, add it to the blockchain
                self.blockchain.add_block(new_block)
                # Broadcast the block to all connected peers
                await self.broadcast(json.dumps({"type": "new_block", "data": block_data}))
                # Send a success response back to the sender
                await websocket.send(json.dumps({"status": "success", "message": "Block added to the blockchain"}))
            else:
                # If the block is invalid, reject it and send an error response back to the sender
                await websocket.send(json.dumps({"status": "error", "message": "Invalid block"}))
        except Exception as e:
            # If an error occurs during block handling, send an error response back to the sender
            await websocket.send(json.dumps({"status": "error", "message": str(e)}))

    async def connect_to_peer(self, uri):
        async with websockets.connect(uri) as websocket:
            await self.message_listener(websocket)

    async def message_listener(self, websocket):
        async for message in websocket:
            print("Received message from peer:", message)

    def manage_peers(self):
        """Check the status of peers and prune disconnected or unresponsive peers."""
        active_peers = {peer for peer in self.peers if self.ping_peer(peer)}
        self.peers = active_peers

    async def broadcast(self, message):
        """Broadcast messages to all peers using an efficient compression protocol."""
        import zlib
        compressed_message = zlib.compress(message.encode())
        for peer in self.peers:
            await peer.send(compressed_message)

    def ping_peer(self, peer):
        """Ping a peer to check if it's still responsive."""
        try:
            response = requests.get(f'http://{peer}/ping')
            return response.status_code == 200
        except requests.RequestException:
            return False

    async def discover_peers(self):
        async with aiohttp.ClientSession() as session:
            for node_address in self.peers:
                try:
                    async with session.get(f'http://{node_address}/peers') as response:
                        if response.status == 200:
                            new_peers = await response.json()
                            for peer in new_peers.get('peers', []):
                                if peer not in self.peers:
                                    self.peers.add(peer)
                except Exception as e:
                    logging.error(f"Failed to discover peers from node {node_address}: {e}")

    def create_ssl_context(certfile, keyfile):
        """Create and return an SSL context for secure connections."""
        ssl_context = create_default_context(purpose=CERT_REQUIRED)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Enforcing higher version TLS
        return ssl_context

    async def start(self):
        try:
            ssl_context = self.create_ssl_context('MySelfSignedCert.crt', 'pk.pem')
            if ssl_context is not None:
                self.server = ThreadingTCPServer(self.server_address, P2PRequestHandler, bind_and_activate=False)
                self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
                self.server.server_bind()
                self.server.server_activate()
                self.running = True
                logging.info("Secure P2P server started with mutual TLS")
                server_thread = threading.Thread(target=self.server.serve_forever)
                server_thread.start()
                print("SSL context created successfully")
            else:
                print("Failed to create SSL context")
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")
        except Exception as e:
            print("An error occurred in starting the server:", str(e))

    async def process_request(self, request):
        method, *headers_and_body = request.split('\r\n\r\n')
        headers = headers_and_body[0]
        body = headers_and_body[1] if len(headers_and_body) > 1 else ''
        path = headers.split(' ')[1]

        if method == 'POST':
            if path == '/transactions/new':
                return await self.new_transaction(body)
            elif path == '/blocks':
                return await self.full_chain()
            elif path == '/peers/new':
                return await self.add_peer(body)
            elif path == '/mine':
                return await self.mine()
        elif method == 'GET' and path == '/blocks':
            return await self.full_chain()

        return "HTTP/1.1 404 Not Found\r\n\r\n"