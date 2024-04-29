import hashlib, secrets, base58, ast
from wallet import Wallet
from node import Node

# in smart_contracts.py
class SmartContract:
    ALLOWED_NODES = {
        ast.Module, ast.FunctionDef, ast.Return, ast.If, ast.Compare, ast.BinOp, ast.Num, ast.Expr, ast.Load, ast.Store,
        ast.BoolOp, ast.UnaryOp, ast.Call, ast.Name, ast.arg, ast.arguments
    }
    
    def __init__(self, code, bchain):
        self.code = code
        self.blockchain = bchain
        self.address = self.generate_address()
        self.wallet = Wallet(Node(self.address))
        
    def generate_address(self):
        # Simple address generation based on contract hash (pseudo-random and unique)
        contract_id = hashlib.sha256(self.code.encode()).hexdigest()
        raw_address = hashlib.sha256(contract_id.encode()).digest()
        ripemd160 = hashlib.new('ripemd160', raw_address).digest()
        versioned_ripemd160 = b'\x00' + ripemd160  # \x00 is the version byte for Bitcoin mainnet addresses
        checksum = hashlib.sha256(hashlib.sha256(versioned_ripemd160).digest()).digest()[:4]
        full_address = base58.b58encode(versioned_ripemd160 + checksum).decode('utf-8')
        return full_address
    
    def execute(self, transaction):
        local_context = {}
        try:
            tree = ast.parse(self.code)
            for node in ast.walk(tree):
                if type(node) not in self.ALLOWED_NODES:
                    raise ValueError(f"Disallowed AST node: {type(node).__name__}")
            exec(compile(tree, filename="<ast>", mode="exec"), {}, local_context)
            contract_function = local_context['contract_logic']
            result = contract_function(transaction.context)
            transaction.amount = result['amount']
        except Exception as e:
            print(f"Execution error in smart contract: {e}")

    @staticmethod
    def validate_python_code(code):
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            print(f"Syntax error in contract code: {e}")
            return False