# import hashlib
# import time
# import json
# from flask import Flask, jsonify, request
# from werkzeug.security import generate_password_hash, check_password_hash

# class Block:
#     def __init__(self, index, previous_hash, transactions, proof, timestamp=None):
#         self.index = index
#         self.timestamp = timestamp or time.time()
#         self.transactions = transactions
#         self.previous_hash = previous_hash
#         self.proof = proof
#         self.hash = self.compute_hash()

#     def compute_hash(self):
#         # Combine block data into a single string
#         block_string = f"{self.index}{self.previous_hash}{self.transactions}{self.proof}{self.timestamp}"
#         # Return the SHA-256 hash of the block string
#         return hashlib.sha256(block_string.encode()).hexdigest()

# class Blockchain:
#     def __init__(self):
#         self.chain = []
#         self.current_transactions = []
#         self.balances = {}
#         self.create_genesis_block()

#     def create_genesis_block(self):
#         genesis_block = Block(0, "0", [], 100)
#         self.chain.append(genesis_block)
#         self.balances['Alice'] = 100  # Initial balance for Alice

#     def get_last_block(self):
#         return self.chain[-1]

#     def add_new_block(self, proof):
#         last_block = self.get_last_block()
#         new_block = Block(len(self.chain), last_block.hash, self.current_transactions, proof)
#         self.chain.append(new_block)
#         self.current_transactions = []  # Reset transactions after adding the block

#     def add_transaction(self, sender, recipient, amount):
#         if self.balances.get(sender, 0) < amount:
#             print(f"Transaction failed: {sender} does not have enough funds.")
#             return None

#         self.current_transactions.append({
#             'sender': sender,
#             'recipient': recipient,
#             'amount': amount
#         })

#         # Update balances
#         self.balances[sender] -= amount
#         self.balances[recipient] = self.balances.get(recipient, 0) + amount

#         return self.get_last_block().index + 1  # Return the index of the block that will store this transaction

#     def proof_of_work(self, last_proof):
#         proof = 0
#         while not self.is_valid_proof(last_proof, proof):
#             proof += 1
#         return proof

#     def is_valid_proof(self, last_proof, proof):
#         guess = f'{last_proof}{proof}'.encode()
#         guess_hash = hashlib.sha256(guess).hexdigest()
#         return guess_hash[:4] == "0000"  # Difficulty level

#     def mine_block(self):
#         last_block = self.get_last_block()
#         last_proof = last_block.proof
#         proof = self.proof_of_work(last_proof)

#         # Reward Alice for mining the block (50 units)
#         self.add_transaction(sender="0", recipient="Alice", amount=50)

#         # Add the new block with current transactions and proof
#         self.add_new_block(proof)
#         return self.get_last_block()

# # Flask web application
# app = Flask(__name__)

# blockchain = Blockchain()
# users = {}  # Store users in memory (use a database in production)

# @app.route('/', methods=['GET'])
# def home():
#     return "Welcome to the Blockchain API! Use /chain to view the blockchain, /mine to mine a block, /transactions/new to add a transaction, /register to create an account, and /login to authenticate."

# @app.route('/register', methods=['POST'])
# def register():
#     username = request.json.get('username')
#     password = request.json.get('password')

#     if username in users:
#         return jsonify({"msg": "User already exists!"}), 400

#     users[username] = generate_password_hash(password)
#     blockchain.balances[username] = 50  # Initialize user's balance to 0
#     return jsonify({"msg": "User registered successfully!", "balance": 50}), 201

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.json.get('username')
#     password = request.json.get('password')

#     user_password = users.get(username)

#     if user_password and check_password_hash(user_password, password):
#         return jsonify({"msg": "Login successful!"}), 200

#     return jsonify({"msg": "Bad username or password!"}), 401

# @app.route('/transactions/new', methods=['POST'])
# def new_transaction():
#     username = request.json.get('username')
#     password = request.json.get('password')
#     values = request.get_json()

#     # Authenticate user
#     user_password = users.get(username)
#     if not user_password or not check_password_hash(user_password, password):
#         return jsonify({"msg": "Bad username or password!"}), 401

#     required_fields = ['recipient', 'amount']
#     if not all(field in values for field in required_fields):
#         return 'Missing values', 400

#     index = blockchain.add_transaction(username, values['recipient'], values['amount'])
#     if index is None:
#         return jsonify({'message': 'Transaction failed: insufficient funds.'}), 400

#     response = {'message': f'Transaction will be added to Block {index}'}
#     return jsonify(response), 201

# @app.route('/mine', methods=['GET'])
# def mine():
#     new_block = blockchain.mine_block()
#     response = {
#         'message': 'New Block Mined',
#         'index': new_block.index,
#         'transactions': new_block.transactions,
#         'previous_hash': new_block.previous_hash,
#         'proof': new_block.proof,
#         'hash': new_block.hash
#     }
#     return jsonify(response), 200

# @app.route('/chain', methods=['GET'])
# def full_chain():
#     response = {
#         'chain': [block.__dict__ for block in blockchain.chain],
#         'length': len(blockchain.chain)
#     }
#     return jsonify(response), 200

# @app.route('/balance/<address>', methods=['GET'])
# def get_balance(address):
#     balance = blockchain.balances.get(address, 0)
#     response = {'address': address, 'balance': balance}
#     return jsonify(response), 200

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)


import hashlib
import time
import json
import asyncio
import websockets
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
import sys
import random

class Block:
    def __init__(self, index, previous_hash, transactions, proof, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.proof = proof
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.transactions}{self.proof}{self.timestamp}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.peers = set()
        self.stakes = {}  # Track stakes of each participant
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", [], 0)  # No proof required for genesis block
        self.chain.append(genesis_block)

    def get_last_block(self):
        return self.chain[-1]

    def add_new_block(self, proof):
        last_block = self.get_last_block()
        new_block = Block(len(self.chain), last_block.hash, self.current_transactions, proof)
        self.chain.append(new_block)
        self.current_transactions = []

    def add_transaction(self, sender, recipient, amount):
        # Sign the transaction using sender's private key (simplified for demonstration)
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': self.sign_transaction(sender, amount)  # Simplified signing
        }
        self.current_transactions.append(transaction)
        return self.get_last_block().index + 1

    def sign_transaction(self, sender, amount):
        # Simulate transaction signing (replace with actual signing logic)
        return f"{sender}:{amount}:{random.randint(1, 10000)}"  # Simplified signature

    def proof_of_stake(self, stakeholder):
        # Example logic for selecting a stakeholder to validate a block
        if stakeholder in self.stakes:
            total_stake = sum(self.stakes.values())
            selection = random.uniform(0, total_stake)
            current_sum = 0
            for peer, stake in self.stakes.items():
                current_sum += stake
                if current_sum >= selection:
                    return peer  # Selected stakeholder
        return None

    def validate_block(self, block):
        last_block = self.get_last_block()
        if block.previous_hash != last_block.hash:
            return False
        # Validate transactions within the block
        for tx in block.transactions:
            if not self.validate_transaction(tx):
                return False
        return True                  

    def validate_transaction(self, transaction):
        # Validate transaction signature (simplified for demonstration)
        return True  # Replace with actual signature validation logic

    def mine_block(self, miner_address):
        # Select a stakeholder to validate the block
        print(f"Trying to mine with address: {miner_address}")

        # Make sure the miner has stakes
        if miner_address not in self.stakes or self.stakes[miner_address] == 0:
            print(f"Miner {miner_address} has no stake.")
            return None  # Exit only if the miner has no stake

        selected_stakeholder = self.proof_of_stake(miner_address)
        if selected_stakeholder:
            # Add reward for the selected miner
            print(f"Stakeholder selected: {selected_stakeholder}")
            self.add_transaction(sender="0", recipient=miner_address, amount=1)  # Reward for mining
            self.add_new_block(selected_stakeholder)  # Use selected stakeholder as proof
            print(f"New block added by: {selected_stakeholder}")
            return self.get_last_block()
        else:
            print(f"No stakeholder selected.")
        
        return None

    def is_valid_chain(self, chain):
        for i in range(1, len(chain)):
            block = chain[i]
            previous_block = chain[i - 1]
            if block.previous_hash != previous_block.hash:
                return False
            if not self.validate_block(block):
                return False
        return True

# Flask API for basic blockchain operations
app = Flask(__name__)
blockchain = Blockchain()

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the Blockchain API!"

@app.route('/register_stake', methods=['POST'])
def register_stake():
    values = request.get_json()
    required = ['address', 'stake']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    
    address = values['address']
    stake = values['stake']
    
    # Register the stake
    blockchain.stakes[address] = stake
    
    return jsonify({'message': f'Stake of {stake} added for {address}'}), 201


@app.route('/mine/<string:miner_address>', methods=['GET'])
def mine(miner_address):
    new_block = blockchain.mine_block(miner_address)
    if new_block:
        response = {
            'message': 'New Block Mined',
            'index': new_block.index,
            'transactions': new_block.transactions,
            'previous_hash': new_block.previous_hash,
            'proof': new_block.proof,
            'hash': new_block.hash
        }
        # Broadcast the new block to all peers
        asyncio.run(broadcast_block(new_block))
        return jsonify(response), 200
    return jsonify({'message': 'Mining failed'}), 400

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400

    index = blockchain.add_transaction(values['sender'], values['recipient'], values['amount'])
    
    # Broadcast the new transaction to peers
    asyncio.run(broadcast_transaction(values))
    return jsonify({"message": f"Transaction will be added to Block {index}"}), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': [block.__dict__ for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/consensus', methods=['GET'])
def consensus():
    longest_chain = None
    current_length = len(blockchain.chain)

    # Fetch the chain from each peer
    for peer in blockchain.peers:
        try:
            response = requests.get(f'http://{peer}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > current_length and blockchain.is_valid_chain(chain):
                    current_length = length
                    longest_chain = chain
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to peer: {peer} - {e}")

    if longest_chain:
        blockchain.chain = [Block(**block) for block in longest_chain]
        response = {
            'message': 'Our chain was replaced',
            'new_chain': [block.__dict__ for block in blockchain.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': [block.__dict__ for block in blockchain.chain]
        }
    
    return jsonify(response), 200

# WebSocket Server and Client Code
PEERS = set()

async def handle_connection(websocket, path):
    async for message in websocket:
        data = json.loads(message)

        if data['type'] == 'new_block':
            new_block = data['block']
            # Validate and add the new block to the blockchain
            blockchain.add_new_block(new_block['proof'])
            print(f"Received new block: {new_block}")

        elif data['type'] == 'new_transaction':
            transaction = data['transaction']
            # Add the new transaction to the blockchain
            blockchain.add_transaction(transaction['sender'], transaction['recipient'], transaction['amount'])
            print(f"Received new transaction: {transaction}")

# Broadcast new blocks to peers
async def broadcast_block(block):
    if len(PEERS) > 0:
        block_data = {
            'type': 'new_block',
            'block': block.__dict__
        }
        message = json.dumps(block_data)
        await asyncio.gather(*[peer.send(message) for peer in PEERS])

# Broadcast new transactions to peers
async def broadcast_transaction(transaction):
    if len(PEERS) > 0:
        transaction_data = {
            'type': 'new_transaction',
            'transaction': transaction
        }
        message = json.dumps(transaction_data)
        await asyncio.gather(*[peer.send(message) for peer in PEERS])

async def connect_to_peer(uri):
    async with websockets.connect(uri) as websocket:
        PEERS.add(websocket)

# Run the WebSocket server
async def start_websocket_server():
    server = await websockets.serve(handle_connection, "localhost", 6789)
    await server.wait_closed()

if __name__ == '__main__':
    # Default port
    port = 5000

    # Parse command-line arguments
    for arg in sys.argv:
        if arg.startswith('--port='):
            port = int(arg.split('=')[1])

    # Run Flask app and WebSocket server
    Thread(target=lambda: app.run(port=port), daemon=True).start()
    asyncio.run(start_websocket_server())




#before implementing consensus mechanism
import json
import hashlib
import time
import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from uuid import uuid4
import threading
import websockets
import asyncio
import ssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sys
 
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.create_block(previous_hash='1', proof=100)
        self.user_keys = {}  # Store user public/private key pairs

    def create_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        # Verify signature before adding transaction
        if not self.verify_signature(sender, amount, signature):
            return 'Invalid transaction signature', 400

        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature
        })
        return self.last_block['index'] + 1

    def register_user(self, username):
        # Generate public/private key pair for new user
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.user_keys[username] = (private_key, public_key)
        return public_key

    def sign_transaction(self, username, amount):
        private_key = self.user_keys[username][0]
        # Sign transaction data
        signature = private_key.sign(
            f"{username}:{amount}".encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, sender, amount, signature):
        # Ensure the sender has a registered key before verifying
        if sender not in self.user_keys:
            return False
        public_key = self.user_keys[sender][1]
        try:
            public_key.verify(
                signature,
                f"{sender}:{amount}".encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @property
    def last_block(self):
        return self.chain[-1]

    def register_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            last_block = block
            current_index += 1
        return True

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
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self):
        last_proof = self.last_block['proof']
        proof = self.proof_of_work(last_proof)

        # Reward Alice for mining the block (50 units)
        self.new_transaction(sender="0", recipient="Alice", amount=50, signature=b'')  # Signature not needed for mining

        # Add the new block with current transactions and proof
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
        return guess_hash[:4] == "0000"  # Adjust difficulty as needed


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()

@app.route('/')
def index():
    return "Welcome to the Blockchain API!"  # Root route response

@app.route('/mine', methods=['GET'])
def mine():
    new_block = blockchain.mine_block()
    response = {
        'message': 'New Block Mined',
        'index': new_block['index'],
        'transactions': new_block['transactions'],
        'previous_hash': new_block['previous_hash'],
        'proof': new_block['proof'],
        'hash': blockchain.hash(new_block)  # Added to return the block hash
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['signature'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400
    for node in nodes:
        blockchain.register_node(node)
    response = {'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Our chain was replaced', 'new_chain': blockchain.chain}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': blockchain.chain}
    return jsonify(response), 200

@app.route('/sign_transaction', methods=['POST'])
def sign_transaction_route():
    values = request.get_json()
    required = ['username', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    signature = blockchain.sign_transaction(values['username'], values['amount'])
    return jsonify({'signature': signature.hex()}), 200

connected_clients = set()  # Store connected websocket clients

async def handle_client(websocket, path):
    # Register the client
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            # Broadcast the message to all connected clients
            for client in connected_clients:
                if client != websocket:  # Don't send the message back to the sender
                    await client.send(message)
    finally:
        # Unregister the client on disconnect
        connected_clients.remove(websocket)

def start_websocket_server():
    loop = asyncio.new_event_loop()  # Create a new event loop for this thread
    asyncio.set_event_loop(loop)  # Set the new event loop
    start_server = websockets.serve(handle_client, "localhost", 6789)
    loop.run_until_complete(start_server)
    loop.run_forever()

if __name__ == '__main__':
    blockchain.register_user("Alice")
    blockchain.register_user("Bob") 
    port = 5000  # Default port
    if len(sys.argv) > 1:
        port = int(sys.argv[1])  # Allow specifying the port as a command-line argument

    # Start the WebSocket server in a separate thread
    threading.Thread(target=start_websocket_server).start()
    app.run(host="0.0.0.0", port=port, debug=True)  
