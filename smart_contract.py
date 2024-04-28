# in smart_contracts.py
class SmartContract:
    def __init__(self, code):
        self.code = code

    def execute(self, context):
        exec(self.code, context)