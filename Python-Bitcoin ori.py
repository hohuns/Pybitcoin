
import datetime
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from hashlib import sha256
import binascii
import json
import requests
from flask import Flask, jsonify, request
from urllib.parse import urlparse
from pyprnt import prnt

app = Flask(__name__)
global difficulty

###Wallet###
class Wallet:
    balance = 0.0
    def __init__(self):
        '''
        constructor (create an object from the Wallet class)
        both keys are stored in terms of Crypto object
        '''
        random = Crypto.Random.new().read
        # private key is the proof that you own this wallet
        # => derive a public key from the private key
        self._private_key = RSA.generate(1024, random)
        # public key is your wallet address
        # => randomly generate a public key from the private key
        self._public_key = self._private_key.publickey()

    def sign_transaction(self, transaction):
        '''
        method to return the signature that is coming from the actual owner in a transaction
        implemented in the Wallet class instead of Transaction class to protect the private key from illegal access
        '''
        signer = PKCS1_v1_5.new(self._private_key)
        h = SHA.new(str(transaction.to_dict()).encode('utf-8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    @property  # getter function for public key (identity)
    def identity(self):
        '''method to export the public key in DER formation and decodes it as ascii'''
        pubkey = binascii.hexlify(self._public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')

    @property  # getter function for private key
    def secret(self):
        '''method to export the private key in DER formation and decodes it as ascii'''
        seckey = binascii.hexlify(self._private_key.exportKey(format='DER'))
        return seckey.decode('ascii')


###Transaction###

class Transaction:
    '''constructor to define the sender, recipient and value in a transactiom'''
    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.fee = self.transaction_fee(self.value)

    def to_dict(self):
        '''method to dump all contents (except signature) in the transaction as a dictionary'''
        # Signature is not included here
        return ({
            'sender': self.sender,
            'recipient': self.recipient,
            'value': self.value,
            'fee': self.fee
        })

    def add_signature(self, signature):
        '''method to add a signature to the transaction'''
        self.signature = signature

    def verify_transaction_signature(self):
        '''method to verify the signature in the transaction'''
        if hasattr(self, 'signature'):
            public_key = RSA.importKey(binascii.unhexlify(self.sender))
            verifier = PKCS1_v1_5.new(public_key)
            h = SHA.new(str(self.to_dict()).encode('utf-8'))
            return verifier.verify(h, binascii.unhexlify(self.signature))
        else:
            return False

    def to_json(self):
        '''method to generate JSON format from all contents of the transaction'''
        return json.dumps(self.__dict__, sort_keys=False)

#calculating the transaction hash


    def to_hash(self):
        return sha256(str(self.to_json()).encode()).hexdigest()

#Optional features for Transaction
#calculating the transaction fee
#-----------------------------------------------------------------------------------#
    def transaction_fee(self, amount):
        fee = float(amount) *0.01
        return float(fee)


###Block###
class Block:
    def __init__(self, index, transaction, timestamp, previous_hash):
        self.index = index
        self.transaction = transaction
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = '0'
        self.nonce = 0
        self.difficulty = 1
        self.merkle_root = None # add my mou

    def to_dict(self):
        return {
            'index': self.index,
            'transaction': self.transaction,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,  # add my mou
        }

    def to_json(self):

        return json.dumps(self.__dict__)

    def compute_hash(self):
        self.merkle_root = self.get_m_root()  # add my mou
        return sha256(str(self.to_dict()).encode()).hexdigest()

#Optional features of Block
#-----------------------------------------------------------------------------------#
    def get_m_root(self):
        '''This function calculate the merkle root of the block'''
        transaction_hash_list = []
        for tran in self.transaction:
            transaction_hash_list.append(sha256(tran.encode()).hexdigest())
        return self.m_Root(transaction_hash_list)

    def m_Root(self, transaction_hash_list):
        '''This is recursive function to calculate merkle root given the hash list of transactions'''
        if len(transaction_hash_list) <= 1:
            return transaction_hash_list[0]
        combine_hash_list = []
        i = 0
        while i < len(transaction_hash_list):
            trans_a = transaction_hash_list[i]
            if i + 1 < len(transaction_hash_list):
                trans_b = transaction_hash_list[i + 1]
            else:
                trans_b = transaction_hash_list[i]
            combine_hash = trans_hash_sum(trans_a, trans_b)
            combine_hash_list.append(combine_hash)
            i += 2
        return self.m_Root(combine_hash_list)

###Blockchain###
class Blockchain:
    global difficulty
    difficulty = 1
    INTEREST = 0.1
    nodes = set()

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        '''method to create and puts the genesis block into the blockchain'''
        block_reward = Transaction("Block_reward", myWallet.identity, "5.0").to_json()
        genesis_block = Block(0, block_reward, datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"), "0")
        # Hash of genesis block cannot be computed directly, proof of work is needed
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block.to_json())

    def register_node(self, node_url):
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def add_new_transaction(self, transaction: Transaction):
        if transaction.verify_transaction_signature():
            self.unconfirmed_transactions.append(transaction.to_json())
            return True
        else:
            return False

    def add_block(self, block, proof):
        previous_hash = self.last_block['hash']
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block.to_json())
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * difficulty) and block_hash == block.compute_hash())

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def consensus(self):
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get('http://' + node + '/fullchain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        # Replace our chain if longer chain is found
        if new_chain:
            self.chain = json.loads(new_chain)
            return True
        return False

    def valid_chain(self, chain):
        # check if a blockchain is valid
        current_index = 0
        chain = json.loads(chain)
        while current_index < len(chain):
            block = json.loads(chain[current_index])
            current_block = Block(
                block['index'],
                block['transaction'],
                block['timestamp'],
                block['previous_hash'])
            current_block.nonce = block['nonce']

            if current_index + 1 < len(chain):
                if current_block.compute_hash() != json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transaction, list):
                for transaction in current_block.transaction:
                    transaction = json.loads(transaction)
                    # skip Block reward because it does not have signature
                    if transaction['sender'] == 'Block_Reward':
                        continue
                    current_transaction = Transaction(
                        transaction['sender'],
                        transaction['recipient'],
                        transaction['value'])
                    current_transaction.signature = transaction['signature']
                    # validate digital signature of each transaction
                    if not current_transaction.verify_transaction_signature():
                        return False
                if not self.is_valid_proof(current_block, block['hash']):
                    return False
            current_index += 1
        return True

#Optional features of Blockchain: Able to give interest to coins holder
#-----------------------------------------------------------------------------------#
    def mine(self, myWallet):
        inte = myWallet.balance * self.INTEREST
        fee = [float(json.loads(transaction)['fee']) for transaction in self.unconfirmed_transactions]
        total_fee = sum(fee)

        neighbours = self.nodes
        for node in neighbours:
            response = requests.get('http://' + node + '/get_transactions')
            if response.status_code == 200:
                transactions = response.json()['transactions']

                for transaction in transactions:
                    self.unconfirmed_transactions.insert(0,transaction)
                    transaction = json.loads(transaction)
                    total_fee += float((transaction['fee']))
            requests.post('http://' + node + '/clear_unconfirmed_transaction')

        block_reward = Transaction("Block_Reward", myWallet.identity, str(5.0 + total_fee + inte)).to_json()
        self.unconfirmed_transactions.insert(0, block_reward)
        if not self.unconfirmed_transactions:
            return False

        new_block = Block(
            index=self.last_block['index'] + 1,
            transaction=self.unconfirmed_transactions,
            timestamp=datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
            previous_hash=self.last_block['hash'])

        new_block.difficulty = self.change_difficulty(self.last_block) #Call the change difficulty function each time when creating a new block


        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []
            blockchain.check_balance(myWallet.identity)
            return new_block
        else:
            return False

#Optional features of BlockChain : Able to change difficulty when the hash power of the network change.
#-----------------------------------------------------------------------------------#

# Hash power = rate of generating hash per seconds. (hash/s)
# Thus, we can assume that the shorter the time needed to generate a new block, the higher the hash power. And vice versa.

    def change_difficulty(self, previous_block):

        global difficulty

        # upper and lower limit of the difficulty
        lower_limit_diff = 1
        upper_limit_diff = 4

        # Comparing the last node timestamp and the 2nd last node timestamp to adjust the difficulty

        if len(self.chain) > 3:  # Make sure that there are more than 3 newly mined blocks in the chain

            last_two_blocks = [json.loads(block) for block in self.chain[-2:]]

            timestamps_last_2_blocks = list(
                map(lambda x: datetime.datetime.strptime(x["timestamp"], "%m/%d/%Y, %H:%M:%S"),
                    last_two_blocks))  # Merge the timestamps into a list

            time_difference = timestamps_last_2_blocks[1] - timestamps_last_2_blocks[0]

            print(" The time difference (s) between last and 2nd last block = ", time_difference.seconds, " seconds")

            # Adjust the difficulty so that it generated 1 block per 60 seconds averagely.
            # If the time difference lies between 30 to 60 seconds, no change on difficulity.

            if time_difference.total_seconds() > 60 and difficulty - 1 >= lower_limit_diff:
                difficulty -= 1
                print(" Blocks are generated too slow due to Hash power too low, thus difficulty is decreased to ",
                      difficulty)

            elif time_difference.total_seconds() < 30 and difficulty + 1 <= upper_limit_diff:
                difficulty += 1
                print(" Blocks are generated too fast due to Hash power too high, thus difficulty is increased to ",
                      difficulty)

            else:
                print(
                    " Difficulty level reach boundries\n OR The time difference between blocks is optimal,\n thus no change in difficulty, it remain in ",
                    difficulty)

        return difficulty

    @property
    def last_block(self):
        return json.loads(self.chain[-1])

#Optional features of Blockchain: partial validation using merkletree
#-----------------------------------------------------------------------------------#
    def validate_transaction(self, transaction_hash):
        """This function check whether the given transaction is
        in the blockchain given the hash of the transaction"""
        full_chain = []
        for block in self.chain:
            full_chain.append(json.loads(block))
        for block in full_chain[::-1]:  #iterate over the block chain, and find where the transaction is
            if self.partial_validation(block, transaction_hash):
                return "This transaction is in block " + str(block['index'])
        return "This transaction is not found"

    def hash_path(self, transaction_hash_list, hash_path, target_transaction):
        """This function return the hash path to get the merkle root"""
        if len(transaction_hash_list) <= 1:
            return hash_path
        parent = ""
        combine_hash_list = []
        i = 0
        while i < len(transaction_hash_list):
            trans_a = transaction_hash_list[i]
            if i + 1 < len(transaction_hash_list):
                trans_b = transaction_hash_list[i + 1]
            else:
                trans_b = transaction_hash_list[i]

            combine_hash = trans_hash_sum(trans_a, trans_b)
            combine_hash_list.append(combine_hash)
            if trans_a == target_transaction:
                parent = combine_hash
                hash_path.append(["right", trans_b])
            elif trans_b == target_transaction:
                parent = combine_hash
                hash_path.append(["left", trans_a])
            i += 2
        return self.hash_path(combine_hash_list, hash_path, parent)

    def partial_validation(self, block, transaction_hash):
        """This function can check whether the transaction is in the block given the block and
        the hash of transaction"""

        t_hash = transaction_hash
        root = transaction_hash
        transaction_hash_list = []
        for trans in block['transaction']:
            if trans == '{':
                break
            tran = json.loads(trans)
            new_tran = Transaction(tran['sender'], tran['recipient'], tran['value'])
            if 'signature' in tran.keys():
                new_tran.signature = tran['signature']
            new_transHash = new_tran.to_hash()
            transaction_hash_list.append(new_transHash)
        hash_path = self.hash_path(transaction_hash_list, [], t_hash)
        for k in hash_path:
            if k[0] == "left":
                root = trans_hash_sum(k[1], root)
            else:
                root = trans_hash_sum(root, k[1])
        if block['merkle_root'] == root:
            return True
        else:
            return False

#Optional features of BlockChain : It changes the balance of the wallet by calculating the transactions and fee
    def check_balance(self, address):

        if len(self.chain) <= 0:
            return None

        myWallet.balance = 0.0

        for i in range(1,len(self.chain)):
            block = json.loads(self.chain[i])
            transactions = block["transaction"]
            for transaction in transactions:
              transaction = json.loads(transaction)

              if transaction["recipient"] == address:
                 myWallet.balance += float(transaction["value"])
              elif transaction["sender"] == address:
                 myWallet.balance -= float(transaction["value"])
                 myWallet.balance -= float(transaction["fee"])


        for transaction in self.unconfirmed_transactions:
            transaction = json.loads(transaction)
            if transaction["recipient"] == address:
                myWallet.balance += float(transaction["value"])
            elif transaction["sender"] == address:
                myWallet.balance -= float(transaction["value"])
                myWallet.balance -= float(transaction["fee"])
        return None

def trans_hash_sum(a, b):
    '''simple method to get sum hash of two strings'''
    string_sum = str(a).encode() + str(b).encode()
    trans_hash_sum = sha256(string_sum).hexdigest()
    return trans_hash_sum

### Flask APIs###
@app.route('/verify', methods=['POST'])
def verify():
    ''' use following command in terminal, replace the <transaction_hash> with
    the hash of transaction that you want to verify:
    curl -d "hash=<transaction_hash>" -X POST http://127.0.0.1:5000/verify'''
    value = request.form
    return blockchain.validate_transaction(value.get('hash'))

#it check the balance before the transaction is created  
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['recipient_address', 'amount']
    # Check that the required fields are in the POST data
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_result = False
    transaction = Transaction(myWallet.identity, values['recipient_address'], values['amount'])
    fee = transaction.transaction_fee(float(values['amount']))
    if (myWallet.balance >= (float(values['amount']) + fee)):
        transaction.add_signature(myWallet.sign_transaction(transaction))
        transaction_result = blockchain.add_new_transaction(transaction)
        blockchain.check_balance(myWallet.identity)
    if transaction_result:

        response = {'message': 'Transaction will be added to Block'}
        return jsonify(response), 201
    else:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406


@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.unconfirmed_transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def part_chain():
    response = {
        'chain': blockchain.chain[-10:],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/fullchain', methods=['GET'])
def full_chain():
    response = {
        'chain': json.dumps(blockchain.chain),
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/get_nodes', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])
def register_node():
    values = request.form
    node = values.get('node')
    com_port = values.get('com_port')
    # handle type B request
    if com_port is not None:
        blockchain.register_node(request.remote_addr + ":" + com_port)
        return "ok", 200
    # handle type A request
    if node is None and com_port is None:
        return "Error: Please supply a valid nodes", 400
    # register node
    blockchain.register_node(node)
    # retrieve nodes list
    node_list = requests.get('http://' + node + '/get_nodes')
    if node_list.status_code == 200:
        node_list = node_list.json()['nodes']
        for node in node_list:
            blockchain.register_node(node)
    for new_nodes in blockchain.nodes:
        # sending type B request
        requests.post('http://' + new_nodes + '/register_node', data={'com_port': str(port)})
    # check if our chain is authoritative from other nodes
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Longer authoritative chain found from peers, replacing ours',
            'total_nodes': [node for node in blockchain.nodes]
        }
    else:
        response = {
            'message': 'New nodes have been added, but our chain is authoritative',
            'total_nodes': [node for node in blockchain.nodes]
        }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Our chain was replaced'
        }
    else:
        response = {
            'message': 'Our chain is authoritative'
        }
    return jsonify(response), 200



#It change the balance when mining
@app.route('/mine', methods=['GET'])
def mine():
    new_block = blockchain.mine(myWallet)
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    response = {
        'index': new_block.index,
        'transactions': new_block.transaction,
        'timestamp': new_block.timestamp,
        'previous_hash': new_block.previous_hash,
        'hash': new_block.hash,
        'nonce': new_block.nonce,
    }
    return jsonify(response), 200


#check the balance of the wallet
@app.route('/balance', methods=['GET'])
def balance():
    blockchain.check_balance(myWallet.identity)
    response = {
        'balance': myWallet.balance,
    }
    return jsonify(response), 200


#clear all unconfirmed transaction
@app.route('/clear_unconfirmed_transaction', methods=['POST'])
def clear_unconfirmed_transaction():
    blockchain.unconfirmed_transactions = []
    return jsonify(None), 201



if __name__ == "__main__":
    # Able to generate a new wallet
    myWallet = Wallet()
    blockchain = Blockchain()

    print('myWallet PubKey:', myWallet.identity)
    print('myWallet PrivateKey:', myWallet.secret)


    port = 5000
    app.run(host='127.0.0.1', port=port, debug=True)