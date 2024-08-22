import datetime
from hashlib import sha256
# import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import ecdsa

def apply_sha256(message):
    signature = sha256(message.encode('utf-8')).hexdigest()
    return signature

def get_merkle_root(transactions):
    merkle_root = ""
    count = len(transactions)
    previous_tree_layer = []
    for transaction in transactions:
        previous_tree_layer.append(transaction.transaction_id)
    
    tree_layer = previous_tree_layer

    while(count > 1):
        tree_layer = []
        for i in range(1,len(previous_tree_layer)):
            tree_layer.append(apply_sha256(previous_tree_layer[i-1] + previous_tree_layer[i]))
            count = len(tree_layer)
            previous_tree_layer = tree_layer

        if (len(tree_layer) == 1):
            merkle_root = tree_layer[0]
        else:
            merkle_root = " "
    return merkle_root

class Block():
    def __init__(self, prev_hash):
        self.prev_hash = prev_hash
        self.time_stamp = datetime.datetime.now().timestamp()

        self.merkle_root = ""
        self.transactions = []

        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        new_hash = apply_sha256(self.prev_hash + str(self.time_stamp) + str(self.nonce) + self.merkle_root)
        return new_hash
    
    def mine_block(self, difficulty):
        self.merkle_root = get_merkle_root(self.transactions)
        target = "0" * difficulty
        self.hash = self.calculate_hash()
        while (self.hash[0:difficulty] != target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        print("block mined! Hash: " + self.hash + "\n")

    def add_transaction(self, transaction):
        if (transaction == None):
            return False
        
        if ("0" != self.prev_hash):
            if (transaction.process_transaction() != True):
                print("Transaction failed to process. Discarded")
                return False
        
        self.transactions.append(transaction)
        print("Transaction successfully added to block")
        return True

    def convert_block_to_dict(self):
        attribute_dict = {}
        attribute_dict["hash"] = self.hash
        attribute_dict["previous_hash"] = self.prev_hash
        attribute_dict["data"] = self.data
        attribute_dict["time_stamp"] = self.time_stamp
        attribute_dict["none"] = self.nonce
        return(attribute_dict)

    
class NoobChain():

    blockchain = []
    UTXOs = []

    DIFFICULTY = 3

    minimum_transaction = 0.1
    
    walletA = None
    walletB = None

    genesis_transaction = None


    def __init__(self):

        walletA = Wallet()
        walletB = Wallet()

        coinbase = Wallet()

        #Create genesis transaction
        self.genesis_transaction = Transaction(coinbase.public_key, walletA.public_key, 100, None)
        self.genesis_transaction.generate_signature(coinbase.private_key)
        self.genesis_transaction.transaction_id = "0"
        self.genesis_transaction.output_UTXOs.append(Transaction_Output(self.genesis_transaction.recipient_address, self.genesis_transaction.value, self.genesis_transaction.transaction_id))
        for output in self.genesis_transaction.output_UTXOs:
            self.UTXOs.append(output)

        print("Creating and mining genesis block...")
        genesis = Block("0")
        genesis.add_transaction(self.genesis_transaction)
        self.add_block(genesis)

        #Testing:
        block1 = Block(genesis.hash)
        print("WalletA balance is: " + str(walletA.get_balance()) + "\n")
        print("WalletA is attempting to send 40 funds to WalletB")
        block1.add_transaction(walletA.send_funds(walletB.public_key, 40))
        self.add_block(block1)
        print("WalletA balance is now: " + str(walletA.get_balance()))
        print("WalletB balance is: " + str(walletB.get_balance()) + "\n")

        block2 = Block(block1.hash)
        print("WalletA is attempting to send more funds than it has (1000)")
        block2.add_transaction(walletA.send_funds(walletB.public_key, 1000))
        self.add_block(block2)
        print("WalletA's balance is: " + str(walletA.get_balance()))
        print("WalletB's balance is: " +str( walletB.get_balance()))

        block3 = Block(block2.hash)
        print("Wallet B is attempting to send funds (20) to walletA")
        block3.add_transaction(walletB.send_funds(walletA.public_key, 20))
        print("WalletA's balance is: " + str(walletA.get_balance()))
        print("WalletB's balance is: " + str(walletB.get_balance()))

        self.is_chain_valid()

        # print("private and public keys of wallet A:")
        # print(walletA.private_key.to_string().hex())
        # print(walletA.public_key.to_string().hex())

        # transaction = Transaction(walletA.public_key, walletB.public_key, 5, None)
        # transaction.generate_signature(walletA.private_key)

        # print("Is signature verified?")
        # print(transaction.verify_signature())
        

        # self.blockchain.append(Block("first block test", "0"))
        # print("Trying to Mine block 1...")
        # self.blockchain[len(self.blockchain)-1].mine_block(self.DIFFICULTY)

        # self.blockchain.append(Block("second block test", self.blockchain[len(self.blockchain)-1].hash))
        # print("Trying to Mne block 2...")
        # self.blockchain[len(self.blockchain)-1].mine_block(self.DIFFICULTY)

        # self.blockchain.append(Block("third block test", self.blockchain[len(self.blockchain)-1].hash))
        # print("Trying to Mne block 3...")
        # self.blockchain[len(self.blockchain)-1].mine_block(self.DIFFICULTY)

        # print(self.blockchain)
        # print("Checking if chain is valid...")
        # print(self.is_chain_valid())

        # print("The block chain:")
        # self.print_blockchain_data()

    # def print_blockchain_data(self):
    #     for i in range (0,len(self.blockchain)):
    #         block_data = self.blockchain[i].convert_block_to_dict()
    #         print(block_data)


    def is_chain_valid(self):
        hash_target = "0" * self.DIFFICULTY
        temp_UTXOs = []
        for output in self.genesis_transaction.output_UTXOs:
            temp_UTXOs.append(output)

        for i in range(1,len(self.blockchain)):
            current_block = self.blockchain[i]
            prev_block = self.blockchain[i-1]

            #verify blocks
            if (current_block.hash != current_block.calculate_hash()):
                print("Current Hashes not equal")
                return False
            if (prev_block.hash != current_block.prev_hash):
                print("Previous Hashes not equal")
                return False
            if (current_block.hash[0:self.DIFFICULTY] != hash_target):
                print("This block hasn't been mined")
                return False
            
            #verify transactions
            temp_output = None
            for t in range(0,len(current_block.transactions)):
                current_transaction = current_block.transactions[t]
                if (current_transaction.sequence == 0):
                    continue

                if (current_transaction.verify_signature() == False):
                    print("Signature on transaction ", t, " is Invalid")
                    return False
                
                if (current_transaction.get_inputs_value() != current_transaction.get_outputs_value()):
                    print("Inputs are not equal to outputs on transaction ", t)
                    return False
                
                for input in current_transaction.input_UTXOs:
                    for output in temp_UTXOs:
                        temp_output = output
                        break
                    
                    if (temp_output == None):
                        print("Reference input on transaction ", t)
                        return False
                    
                    if (input.output_UTXO.value != temp_output.value):
                        print("Referenced input transaction ", t, " value is invalid")
                        return False
                    
                    temp_UTXOs.remove(input.output_UTXO)

                for ouput in current_transaction.output_UTXOs:
                    temp_UTXOs.append(output)
                
                if (current_transaction.output_UTXOs[0].recipient_address != current_transaction.recipient_address):
                    print("Output recipient is not who it should be")
                    return False
                if (current_transaction.output_UTXOs[1].recipient_address != current_transaction.sender_address):
                    print("Transaction " , t, " ouput 'change' is not addressed to the sender")
                    return False
        print("Blockchain is valid")
        return True
    
    def add_block(self, new_block):
        new_block.mine_block(self.DIFFICULTY)
        self.blockchain.append(new_block)
    
class Wallet():
    private_key = ""
    public_key = ""

    UTXOs = []
    
    def __init__(self):
        self.generate_key_pair()

    def generate_key_pair(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256) 
        self.public_key = self.private_key.verifying_key
        signature = self.private_key.sign(b"message")
        assert self.public_key.verify(signature, b"message")

    # def sign_transaction(self, transaction):
    #     signing_key = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1, hashfunc=sha256)
    #     signed_transaction = signing_key.sign(transaction)
    #     return signed_transaction

    def get_balance(self):
        total = 0
        self.UTXOs = []
        for UTXO in NoobChain.UTXOs:
            if UTXO.check_ownership(self.public_key):
                self.UTXOs.append(UTXO)
                total += UTXO.value
        return total
    
    def send_funds(self, recipient_address, value):
        if (self.get_balance() < value):
            print("Not enough funds to send transaction")
            return None
        inputs = []
        total = 0
        for UTXO in self.UTXOs:
            total += UTXO.value
            inputs.append(Transaction_Input(UTXO))
            self.UTXOs.remove(UTXO)
            if (total > value):
                break
        
        new_transaction = Transaction(self.public_key, recipient_address, value, inputs)
        new_transaction.generate_signature(self.private_key)

        return new_transaction
    



class Transaction():
    
    sequence = 0  # A rough count of how many transactions have been generated

    def __init__(self, sender, recipient, value, inputs):
        self.transaction_id = ""
        self.sender_address = sender
        self.recipient_address = recipient
        self.value = value
        self.input_UTXOs = inputs
        self.output_UTXOs = []
        self.signature = None
        self.transaction_hexdata = self.sender_address.to_string().hex() + self.recipient_address.to_string().hex() + self.value.to_bytes().hex()
    
    def calculate_hash(self):
        self.sequence += 1  # Increase to avoid 2 identical transactions having the same hash
        new_hash = apply_sha256(self.transaction_hexdata + self.sequence.to_bytes().hex())
        return new_hash
    
    def generate_signature(self, private_key):
        self.signature = private_key.sign(bytes.fromhex(self.transaction_hexdata))
    
    def verify_signature(self):
        is_valid = self.sender_address.verify(self.signature, bytes.fromhex(self.transaction_hexdata))
        return is_valid
    
    def process_transaction(self):
        if (self.verify_signature() == False):
            print("Transaction signature failed to verify")
            return False
        
        #gather transaction inputs and check all inputs are unspent
        for input in self.input_UTXOs:
            input_valid = False
            input_id = input.output_UTXO_id.id
            for UTXO in NoobChain.UTXOs:
                if UTXO.id == input_id:
                    input_valid = True
                    input.output_UTXO = UTXO
            if input_valid == False:
                return False
            
        if (self.get_inputs_value() < NoobChain.minimum_transaction):
            print("Transaction too small: " + self.get_inputs_value())
            return False
        
        change = self.get_inputs_value() - self.value

        self.transaction_id = self.calculate_hash()

        self.output_UTXOs.append(Transaction_Output(self.recipient_address, self.value, self.transaction_id))
        self.output_UTXOs.append(Transaction_Output(self.sender_address, change, self.transaction_id))

        for output in self.output_UTXOs:
            NoobChain.UTXOs.append(output)

        for input in self.input_UTXOs:
            NoobChain.UTXOs.remove(input.output_UTXO)

        return True

    def get_inputs_value(self):
        total = 0
        for input in self.input_UTXOs:
            total += input.output_UTXO.value
        return total

    def get_outputs_value(self):
        total = 0
        for output in self.output_UTXOs:
            total += output.value
        return total            


class Transaction_Input():
    output_UTXO_id = ""
    output_UTXO = None

    def __init__(self, output_UTXO_id):
        self.output_UTXO_id = output_UTXO_id
    
    def print_data(self):
        print(self.output_UTXO)

class Transaction_Output():
    id = ""
    recipient_address = ""
    value = 0
    parent_transaction_id = 0

    def __init__(self, recipient, value, parent_transaction_id):
        self.recipient_address = recipient
        self.value = value
        self.parent_transaction_id = parent_transaction_id

        self.id = apply_sha256(recipient.to_string().hex() + value.to_bytes().hex() + parent_transaction_id)

    def check_ownership(self, public_key):
        return (public_key == self.recipient_address)




# my_wallet = Wallet()
# print("public key: " + str(my_wallet.public_key))
# print("private key: " + str(my_wallet.private_key))
bc = NoobChain()



    
#  sk_string = sk.to_string()
#  sk2 = ecdsa.SigningKey.from_string(sk_string, curve=ecdsa.SECP256k1, hashfunc=sha256)