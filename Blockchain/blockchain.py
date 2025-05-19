import json
import hashlib
import time
import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from flask_cors import CORS
from uuid import uuid4
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.create_block(previous_hash='1', proof=100)  # Genesis block
        self.user_keys = {}
        self.balances = {}  # To track user balances

    def create_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.last_block),
        }

        self.current_transactions = []  # Clear pending transactions
        self.chain.append(block)  # Add the new block to the chain
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        # Ensure the transaction signature is valid
        if not self.verify_signature(sender, recipient, amount, signature):
            return 'Invalid transaction signature', 400

        # Check if sender has enough balance
        if sender != "0" and self.balances.get(sender, 0) < amount:
            return 'Insufficient balance', 400

        # Add the transaction to the list of pending transactions
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature
        })

        # Update balances
        if sender != "0":  # '0' is used as the system for mining rewards
            self.balances[sender] -= amount
        self.balances[recipient] = self.balances.get(recipient, 0) + amount

        return self.last_block['index'] + 1

    def register_user(self, username):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.user_keys[username] = (private_key, public_key)
        self.balances[username] = 0  # Initialize balance for new user
        return public_key

    def sign_transaction(self, username, amount):
        if username not in self.user_keys:
            raise KeyError(f"User '{username}' not found.")

        private_key = self.user_keys[username][0]
        message = f"{username}:{amount}".encode()

        try:
            signature = private_key.sign(
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            print(f"Error during signing: {str(e)}")
            raise e

    def verify_signature(self, sender, recipient, amount, signature):
        if sender not in self.user_keys:
            return False
        public_key = self.user_keys[sender][1]
        if isinstance(signature, str):
            signature = bytes.fromhex(signature)

        try:
            message = f"{sender}:{amount}".encode()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
        

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbors:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True
        return False

    def hash(self, block):
        block_copy = block.copy()
        for transaction in block_copy['transactions']:
            if isinstance(transaction['signature'], bytes):
                transaction['signature'] = transaction['signature'].hex()

        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self):
        last_proof = self.last_block['proof']
        proof = self.proof_of_work(last_proof)

        self.new_transaction(sender="0", recipient="Alice", amount=50, signature=b'')
        block = self.create_block(proof)
        return block

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


blockchain = Blockchain()

@app.route('/')
def index():
    return "Welcome to the Blockchain API!"

@app.route('/mine', methods=['GET'])
def mine():
    new_block = blockchain.mine_block()
    response = {
        'message': 'New Block Mined',
        'index': new_block['index'],
        'transactions': new_block['transactions'],
        'previous_hash': new_block['previous_hash'],
        'proof': new_block['proof'],
        'hash': blockchain.hash(new_block)
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required_fields = ['sender', 'recipient', 'amount']
    if not all(field in values for field in required_fields):
        return 'Missing values', 400
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['signature'])
    return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/user/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Username is required'}), 400
        public_key = blockchain.register_user(username)
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return jsonify({'message': f'User {username} registered successfully', 'public_key': public_key_pem}), 200
    except Exception as e:
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500
    return False

@app.route('/add_funds', methods=['POST'])
def add_funds():
    values = request.get_json()
    username = values.get('username')
    amount = values.get('amount')

    if username is None or amount is None:
        return "Error: Please supply a valid username and amount", 400

    # Add funds to user's balance
    blockchain.balances[username] = blockchain.balances.get(username, 0) + amount
    return jsonify({'message': f'Funds added. New balance for {username}: {blockchain.balances[username]}'}), 200

@app.route('/user/sign', methods=['POST'])
def sign_transaction_route():
    values = request.get_json()
    username = values.get('username')
    amount = values.get('amount')
    if username is None or amount is None:
        return "Error: Please supply a valid username and amount", 400
    signature = blockchain.sign_transaction(username, amount)
    # return jsonify({'signature': signature}), 200
    return jsonify({"message": "Transaction signed successfully!", "signature": signature})

@app.route('/balance/<username>', methods=['GET'])
def get_balance(username):
    balance = blockchain.balances.get(username, 0)
    return jsonify({'balance': balance}), 200

@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


if __name__ == '__main__':
    # app.run(debug=True) 
    import sys

# Check if a port argument is provided
port = 5000  # Default port

if len(sys.argv) > 1:
    for arg in sys.argv:
        if arg.startswith('--port='):
            port = int(arg.split('=')[1])

# Now use the 'port' variable
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=port)  # Replace with your run logic


