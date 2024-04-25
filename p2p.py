
import asyncio
import time
import threading
from socketserver import BaseRequestHandler, ThreadingTCPServer
from transaction import Transaction
from ssl import create_default_context, Purpose

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

    async def handle_request(self, request):
        try:
            request_str = request.decode()
            print("Received request:", request_str)
            response = await self.process_request(request_str)
            return response.encode()
        except Exception as e:
            print("Error handling request:", str(e))
            return "HTTP/1.1 500 Internal Server Error\r\n\r\n".encode()

    async def start(self):
        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile='path/to/certfile', keyfile='path/to/keyfile')
            ssl_context.load_verify_locations('path/to/cacert.pem')
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            self.server = ThreadingTCPServer(self.server_address, P2PRequestHandler, bind_and_activate=False)
            self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
            self.server.server_bind()
            self.server.server_activate()
            self.running = True
            logging.info("Secure P2P server started with mutual TLS")
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.start()
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
            elif path == '/mine':
                return await self.mine()
            elif path == '/blocks':
                return await self.full_chain()
            elif path == '/peers/new':
                return await self.add_peer(body)
        elif method == 'GET' and path == '/blocks':
            return await self.full_chain()

        return "HTTP/1.1 404 Not Found\r\n\r\n"
